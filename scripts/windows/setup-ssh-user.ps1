<#
.SYNOPSIS
Set up a local admin SSH account on a Windows PC.

.DESCRIPTION
Idempotently:
  1. Locate or register winget (only when it is needed).
  2. Install OpenSSH Server (Optional Feature by default, or Microsoft.OpenSSH.Preview
     with -UsePreview) and start sshd and ssh-agent.
  3. Create the local account with a random password nobody sees, and add it to Administrators.
  4. Add the public key to administrators_authorized_keys and lock down its ACL.
  5. Install PowerShell 7 and make it the default SSH shell.
  6. Set the global sshd_config directives and the Match Group administrators block.
Then it keeps the PC reachable on AC power: closing the lid does nothing, and the PC
never sleeps or turns its display off (battery behavior is unchanged).

Without -PublicKey, the key is read from the OpenPGP card's authentication slot through
gpg (Gpg4win). A missing card, or a card without an authentication key, fails before any
change.

Run from an elevated RDP or local Windows PowerShell session:
  powershell.exe -ExecutionPolicy Bypass -File .\setup-ssh-user.ps1 -UserName ssh-<name>

On managed machines where MachinePolicy is RemoteSigned (which overrides
-ExecutionPolicy Bypass), unblock a browser-downloaded copy first:
  Unblock-File .\setup-ssh-user.ps1

It is safe to re-run. Over SSH, a needed sshd restart requires -Force and may drop the
session. Logs and backups are written under:
  C:\ProgramData\SshUserSetup
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read by the functions below through script scope; the rule does not search function bodies.')]
[CmdletBinding()]
param(
    [string]$UserName,
    [string]$PublicKey,
    [switch]$UsePreview,
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$WorkDir = Join-Path $env:ProgramData 'SshUserSetup'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogPath = Join-Path $WorkDir "setup-$Timestamp.log"
$BackupDir = Join-Path $WorkDir "backup-$Timestamp"
$SshDir = Join-Path $env:ProgramData 'ssh'
$SshdConfigPath = Join-Path $SshDir 'sshd_config'
$AdminKeysPath = Join-Path $SshDir 'administrators_authorized_keys'
$OptionalFeatureName = 'OpenSSH.Server~~~~0.0.1.0'
$BuiltinSshdPath = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
$PwshPath = 'C:\Program Files\PowerShell\7\pwsh.exe'
$script:Changes = New-Object System.Collections.Generic.List[string]
$SshdDirectives = [ordered]@{
    PasswordAuthentication = 'no'
    PubkeyAuthentication   = 'yes'
    AuthenticationMethods  = 'publickey'
    UseDNS                 = 'no'
    TCPKeepAlive           = 'yes'
    ClientAliveInterval    = '60'
    ClientAliveCountMax    = '3'
}

# ---------------------------------------------------------------------------
# Pure functions (covered by Pester; must not touch the system)
# ---------------------------------------------------------------------------

function Get-SshdConfigUpdate {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Directives
    )

    $list = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) { $list.Add($line) }

    $matchIdx = $list.Count
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i] -match '^\s*Match\s') {
            $matchIdx = $i
            break
        }
    }

    foreach ($name in $Directives.Keys) {
        $n = [regex]::Escape($name)
        $wanted = "$name $($Directives[$name])"

        $found = -1
        for ($i = 0; $i -lt $matchIdx; $i++) {
            if ($list[$i] -match "^\s*$n(\s|$)") {
                $found = $i
                break
            }
        }
        if ($found -lt 0) {
            for ($i = 0; $i -lt $matchIdx; $i++) {
                if ($list[$i] -match "^\s*#\s*$n(\s|$)") {
                    $found = $i
                    break
                }
            }
        }

        if ($found -ge 0) {
            $list[$found] = $wanted
        } else {
            $list.Insert($matchIdx, $wanted)
            $matchIdx++
        }
    }

    $adminIdx = @()
    for ($i = $matchIdx; $i -lt $list.Count; $i++) {
        if ($list[$i] -match '^\s*Match\s+Group\s+administrators\s*$') {
            $adminIdx += $i
        }
    }

    if ($adminIdx.Count -gt 1) {
        throw "sshd_config has more than one 'Match Group administrators' block; fix it by hand."
    }

    if ($adminIdx.Count -eq 1) {
        $hasKeysFile = $false
        for ($i = $adminIdx[0] + 1; $i -lt $list.Count; $i++) {
            if ($list[$i] -match '^\s*Match\s') { break }
            if ($list[$i] -match '^\s*AuthorizedKeysFile\s+__PROGRAMDATA__/ssh/administrators_authorized_keys\s*$') {
                $hasKeysFile = $true
            }
        }
        if (-not $hasKeysFile) {
            throw "sshd_config 'Match Group administrators' block is missing 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'; fix it by hand."
        }
    } else {
        $list.Add('')
        $list.Add('Match Group administrators')
        $list.Add('       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys')
    }

    $result = $list.ToArray()
    return ,$result
}

function Test-AuthorizedKeyPresent {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory)][string]$PublicKey
    )

    $blob = ($PublicKey.Trim() -split '\s+')[1]
    foreach ($line in $Lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        foreach ($token in ($trimmed -split '\s+')) {
            if ($token -ceq $blob) { return $true }
        }
    }
    return $false
}

function Assert-PublicKeyFormat {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PublicKey)

    $tokens = @($PublicKey.Trim() -split '\s+')
    if ($tokens.Count -lt 2 -or $tokens[0] -notmatch '^(ssh-|ecdsa-|sk-)') {
        throw "PublicKey is not an OpenSSH public key line (expected '<type> <base64> [comment]' with type ssh-*, ecdsa-*, or sk-*)."
    }
}

function Get-ServiceExePath {
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PathName)

    if ($PathName -match '^\s?"([^"]+)"') {
        return $Matches[1]
    }
    if ($PathName -match '^\s*(.+?\.exe)(\s|$)') {
        return $Matches[1]
    }
    throw "Could not parse an executable path from service PathName '$PathName'."
}

function New-RandomPassword {
    # The SSH account logs in with a key only, so nobody needs to know this password.
    # It must still satisfy a local complexity policy if one is enforced.
    [OutputType([securestring])]
    param([ValidateRange(4, 127)][int]$Length = 32)

    $classes = @('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789', '!#$%&()*+,-./:;<=>?@[]^_{}~')
    $alphabet = -join $classes
    # Largest multiple of the alphabet size that fits in a byte; rejecting bytes at or
    # above it keeps every character equally likely.
    $limit = 256 - (256 % $alphabet.Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        do {
            $chars = [Collections.Generic.List[char]]::new()
            $byte = [byte[]]::new(1)
            while ($chars.Count -lt $Length) {
                $rng.GetBytes($byte)
                if ($byte[0] -lt $limit) { $chars.Add($alphabet[$byte[0] % $alphabet.Length]) }
            }
            $missing = @($classes | Where-Object { $class = $_; -not ($chars | Where-Object { $class.IndexOf($_) -ge 0 }) })
        } while ($missing.Count -gt 0)
    } finally {
        $rng.Dispose()
    }

    $password = [securestring]::new()
    foreach ($c in $chars) { $password.AppendChar($c) }
    $password.MakeReadOnly()
    return $password
}

function Get-PowerSettingAcIndex {
    # Reads the AC value from 'powercfg /qh' output. /qh also lists hidden settings; the lid
    # close action is hidden on some laptops and plain /query leaves it out. powercfg output is
    # localized, so a non-English system fails here instead of being misread.
    [OutputType([long])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $found = @($Lines | Where-Object { $_ -match '^\s*Current AC Power Setting Index:\s*0x[0-9a-fA-F]+\s*$' })
    if ($found.Count -ne 1) {
        throw "Expected one 'Current AC Power Setting Index' line in powercfg output, found $($found.Count). The script reads English powercfg output only."
    }
    $hex = ($found[0] -split ':')[-1].Trim()
    return [Convert]::ToInt64($hex, 16)
}

function Get-CardAuthKey {
    # Reads 'gpg --card-status --with-colons' output. Field 4 of the fpr and grp lines is the
    # authentication slot; fields 2 and 3 are the signing and encryption keys.
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $values = foreach ($prefix in 'fpr:', 'grp:') {
        $line = @($Lines | Where-Object { $_.StartsWith($prefix) } | Select-Object -First 1)
        $fields = @(if ($line.Count -gt 0) { $line[0] -split ':' })
        $value = if ($fields.Count -gt 3) { $fields[3] } else { '' }
        if ($value -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'The OpenPGP card has no authentication key (fpr/grp field 4 is empty). Plug in a YubiKey with an authentication subkey and re-run.'
        }
        $value
    }
    return [pscustomobject]@{ Fingerprint = $values[0]; Keygrip = $values[1] }
}

function ConvertFrom-ReadKeyOutput {
    # Turns 'gpg-connect-agent "READKEY --format=ssh <keygrip>" /bye' output into an OpenSSH
    # public key line, with the same openpgp:0x<last 8 of fingerprint> comment gpg --export-ssh-key uses.
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory)][string]$Fingerprint
    )

    foreach ($line in $Lines) {
        if ($line -match '^D ((?:ssh|ecdsa|sk)-\S+) (\S+)') {
            return "$($Matches[1]) $($Matches[2]) openpgp:0x$($Fingerprint.Substring(32).ToUpperInvariant())"
        }
        if ($line -match '^ERR') {
            throw "gpg-agent READKEY failed: $line"
        }
    }
    throw 'gpg-agent READKEY returned no SSH key.'
}

function Get-FirewallRuleUpdate {
    # Returns the Set-NetFirewallRule arguments that bring a rule to enabled, all profiles, and
    # local subnet only. Only differing keys are included, so a correct rule returns empty.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'The -Profile parameter mirrors Set-NetFirewallRule -Profile; it shadows $PROFILE only inside this function.')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][string]$Enabled,
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$RemoteAddress
    )

    $update = [ordered]@{}
    if ($Enabled -ne 'True') { $update.Enabled = 'True' }
    if ($Profile -ne 'Any') { $update.Profile = 'Any' }
    if ($RemoteAddress.Count -ne 1 -or $RemoteAddress[0] -ne 'LocalSubnet') { $update.RemoteAddress = 'LocalSubnet' }
    return $update
}

# ---------------------------------------------------------------------------
# System functions
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDesktopEdition {
    return $PSVersionTable.PSEdition -eq 'Desktop'
}

function Write-Step {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Write-Host is the only output Start-Transcript records on Windows PowerShell 5.1; the transcript is the setup log.')]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Get-GpgToolPath {
    [OutputType([string])]
    param([Parameter(Mandatory)][ValidateSet('gpg', 'gpg-connect-agent')][string]$Name)

    $cmd = Get-Command "$Name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    $fallback = "C:\Program Files\GnuPG\bin\$Name.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }

    throw "$Name.exe not found; install Gpg4win: winget install --id GnuPG.Gpg4win"
}

function Get-CardSshPublicKey {
    # stderr is not redirected: under Windows PowerShell 5.1 with ErrorActionPreference Stop,
    # redirected native stderr becomes a terminating error. The exit code is checked instead.
    [OutputType([string])]
    param()

    $status = @(& (Get-GpgToolPath gpg) --card-status --with-colons)
    if ($LASTEXITCODE -ne 0) {
        throw 'No OpenPGP card found. Plug in your YubiKey and re-run; chezmoi apply re-runs this script until it succeeds.'
    }
    $key = Get-CardAuthKey -Lines $status

    $out = @(& (Get-GpgToolPath gpg-connect-agent) "READKEY --format=ssh $($key.Keygrip)" /bye)
    if ($LASTEXITCODE -ne 0) {
        throw "gpg-connect-agent READKEY failed with exit code $LASTEXITCODE"
    }
    return ConvertFrom-ReadKeyOutput -Lines $out -Fingerprint $key.Fingerprint
}

function Get-WingetPath {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    Write-Step 'winget not found; registering App Installer...'
    Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe

    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    $fallback = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }

    throw 'winget.exe not found, even after registering App Installer.'
}

function Initialize-WingetSource {
    # On freshly enrolled machines the winget index package can be missing for this user,
    # and every winget search then fails with 0x8a15000f.
    if (Get-AppxPackage -Name 'Microsoft.Winget.Source') { return }

    Write-Step 'winget source package missing; installing source.msix...'
    $msix = Join-Path $WorkDir 'winget-source.msix'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri 'https://cdn.winget.microsoft.com/cache/source.msix' -OutFile $msix -UseBasicParsing
    Add-AppxPackage -Path $msix
    $script:Changes.Add('installed winget source package')
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$InstallerType
    )

    $wingetArgs = @('install', '--id', $Id, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($InstallerType) {
        $wingetArgs += @('--installer-type', $InstallerType)
    }

    $winget = Get-WingetPath
    Initialize-WingetSource

    Write-Step "Installing $Id with winget..."
    & $winget @wingetArgs
    if ($LASTEXITCODE -ne 0) {
        throw "winget install $Id failed with exit code $LASTEXITCODE"
    }
}

function Install-OpenSSHServer {
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($svc) {
        $exe = Get-ServiceExePath -PathName $svc.PathName
        $isBuiltin = $exe -eq $BuiltinSshdPath
        if ($UsePreview -and $isBuiltin) {
            throw "-UsePreview was given, but the existing sshd service is the built-in Optional Feature ($exe). Re-run without -UsePreview. This script never switches flavors."
        }
        if (-not $UsePreview -and -not $isBuiltin) {
            throw "The existing sshd service is not the built-in Optional Feature ($exe). Re-run with -UsePreview, or remove Microsoft.OpenSSH.Preview first."
        }
    }

    if ($UsePreview) {
        if (-not $svc) {
            Invoke-WingetInstall -Id 'Microsoft.OpenSSH.Preview'
            $script:Changes.Add('installed Microsoft.OpenSSH.Preview')
        } else {
            Write-Step 'Microsoft.OpenSSH.Preview sshd service already present.'
        }
    } else {
        Write-Step "Checking Windows capability $OptionalFeatureName..."
        $capability = Get-WindowsCapability -Online -Name $OptionalFeatureName
        if ($capability.State -ne 'Installed') {
            Write-Step "Installing Windows capability $OptionalFeatureName (this can take 5-15 minutes with no output; do not interrupt)..."
            $result = Add-WindowsCapability -Online -Name $OptionalFeatureName
            $script:Changes.Add('installed OpenSSH Optional Feature')
            if ($result.RestartNeeded) {
                Write-Step 'WARNING: Add-WindowsCapability reports that a restart is needed.'
            }
        } else {
            Write-Step "$OptionalFeatureName is already installed."
        }
    }

    if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
        throw 'sshd service not found after installing OpenSSH Server.'
    }
}

function Start-OpenSSHService {
    foreach ($name in @('sshd', 'ssh-agent')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $service) { continue }

        if ($service.StartType -ne 'Automatic') {
            Write-Step "Setting $name startup type to Automatic..."
            Set-Service -Name $name -StartupType Automatic
            $script:Changes.Add("set $name startup type to Automatic")
        }
        if ($service.Status -ne 'Running') {
            Write-Step "Starting $name..."
            Start-Service -Name $name
            $script:Changes.Add("started $name")
        }
    }
}

function Get-SshdExePath {
    $path = Get-ServiceExePath -PathName (Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName
    if (-not (Test-Path -LiteralPath $path)) {
        throw "sshd.exe from the sshd service PathName does not exist: $path"
    }
    return $path
}

function Set-SshUserAccount {
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Step "Creating local user $UserName..."
        New-LocalUser -Name $UserName -Password (New-RandomPassword) -PasswordNeverExpires | Out-Null
        $script:Changes.Add("created local user $UserName")
    } else {
        Write-Step "Local user $UserName already exists."
    }

    try {
        Add-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction Stop
        $script:Changes.Add("added $UserName to Administrators")
    } catch {
        if ($_.FullyQualifiedErrorId -like 'MemberExists*') {
            Write-Step "$UserName is already a member of Administrators."
        } else {
            throw
        }
    }
}

function Set-AdminAuthorizedKey {
    if (-not (Test-Path -LiteralPath $SshDir)) {
        New-Item -ItemType Directory -Path $SshDir -Force | Out-Null
    }

    $existingLines = @()
    $existingText = ''
    if (Test-Path -LiteralPath $AdminKeysPath) {
        $existingLines = [IO.File]::ReadAllLines($AdminKeysPath)
        $existingText = [IO.File]::ReadAllText($AdminKeysPath)
    }

    if (-not (Test-AuthorizedKeyPresent -Lines $existingLines -PublicKey $PublicKey)) {
        if (Test-Path -LiteralPath $AdminKeysPath) {
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
            Copy-Item -LiteralPath $AdminKeysPath -Destination $BackupDir -Force
        }
        $text = "$($PublicKey.Trim())`r`n"
        if ($existingText.Length -gt 0 -and -not $existingText.EndsWith("`n")) {
            $text = "`r`n" + $text
        }
        Write-Step "Adding public key to $AdminKeysPath..."
        [IO.File]::AppendAllText($AdminKeysPath, $text, (New-Object System.Text.UTF8Encoding $false))
        $script:Changes.Add("added public key to $AdminKeysPath")
    } else {
        Write-Step "Public key already present in $AdminKeysPath."
    }

    Write-Step 'Applying administrators_authorized_keys ACL...'
    & icacls.exe $AdminKeysPath /inheritance:r /grant 'SYSTEM:(F)' /grant 'BUILTIN\Administrators:(F)'
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed for $AdminKeysPath with exit code $LASTEXITCODE"
    }

    Assert-AdminAuthorizedKeyAcl
}

function Assert-AdminAuthorizedKeyAcl {
    $acl = Get-Acl -LiteralPath $AdminKeysPath
    $rules = @($acl.Access)
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)

    $ok = $acl.AreAccessRulesProtected -and (($sids -join ',') -eq 'S-1-5-18,S-1-5-32-544')
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') {
            $ok = $false
        }
    }

    if (-not $ok) {
        $found = ($rules | ForEach-Object { "$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" }) -join '; '
        throw "ACL on $AdminKeysPath must be exactly SYSTEM and BUILTIN\Administrators with FullControl and inheritance removed (protected=$($acl.AreAccessRulesProtected)). Found: $found"
    }
    Write-Step 'Verified administrators_authorized_keys ACL.'
}

function Set-DefaultShell {
    if (-not (Test-Path -LiteralPath $PwshPath)) {
        # The MSI (wix) installs to the fixed $PwshPath for all users; winget's default MSIX does not.
        Invoke-WingetInstall -Id 'Microsoft.PowerShell' -InstallerType 'wix'
        $script:Changes.Add('installed PowerShell 7')
        if (-not (Test-Path -LiteralPath $PwshPath)) {
            throw "PowerShell 7 not found at $PwshPath after winget install."
        }
    } else {
        Write-Step "PowerShell 7 present at $PwshPath."
    }

    $key = 'HKLM:\SOFTWARE\OpenSSH'
    if (-not (Test-Path -LiteralPath $key)) {
        New-Item -Path $key -Force | Out-Null
    }

    $wanted = [ordered]@{
        DefaultShell              = $PwshPath
        DefaultShellCommandOption = '-Command'
    }
    foreach ($name in $wanted.Keys) {
        $props = Get-ItemProperty -LiteralPath $key
        $current = $null
        if ($props) {
            $prop = $props.PSObject.Properties[$name]
            if ($prop) { $current = $prop.Value }
        }
        if ($current -ne $wanted[$name]) {
            Write-Step "Setting $key $name to '$($wanted[$name])'..."
            New-ItemProperty -Path $key -Name $name -Value $wanted[$name] -PropertyType String -Force | Out-Null
            $script:Changes.Add("set $name to '$($wanted[$name])'")
        } else {
            Write-Step "$name already set to '$current'."
        }
    }
}

function Invoke-Powercfg {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = @(& powercfg.exe @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "powercfg $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
    return ,$output
}

function Set-PowerForRemoteAccess {
    # A closed laptop sleeps by default, and SSH and RDP stop answering. On Modern Standby laptops
    # the display timeout also starts standby, which later drops the network. These are AC-only,
    # so a laptop on battery still sleeps.
    $settings = @(
        @{ Subgroup = 'SUB_BUTTONS'; Setting = 'LIDACTION'; Value = 0; Label = 'lid close action on AC power to Do nothing' }
        @{ Subgroup = 'SUB_SLEEP'; Setting = 'STANDBYIDLE'; Value = 0; Label = 'sleep on AC power to Never' }
        @{ Subgroup = 'SUB_VIDEO'; Setting = 'VIDEOIDLE'; Value = 0; Label = 'display turn-off on AC power to Never' }
    )

    $changed = @()
    foreach ($s in $settings) {
        $current = Get-PowerSettingAcIndex -Lines (Invoke-Powercfg -Arguments '/qh', 'SCHEME_CURRENT', $s.Subgroup, $s.Setting)
        if ($current -eq $s.Value) {
            Write-Step "Power: $($s.Label) already set."
        } else {
            Write-Step "Power: setting $($s.Label)..."
            Invoke-Powercfg -Arguments '/setacvalueindex', 'SCHEME_CURRENT', $s.Subgroup, $s.Setting, "$($s.Value)" | Out-Null
            $changed += $s
        }
    }
    if ($changed.Count -eq 0) { return }

    Invoke-Powercfg -Arguments '/setactive', 'SCHEME_CURRENT' | Out-Null
    foreach ($s in $changed) {
        $now = Get-PowerSettingAcIndex -Lines (Invoke-Powercfg -Arguments '/qh', 'SCHEME_CURRENT', $s.Subgroup, $s.Setting)
        if ($now -ne $s.Value) {
            throw "Power: $($s.Setting) on AC power is $now after setting it to $($s.Value)."
        }
        $script:Changes.Add("set $($s.Label)")
    }
}

function Set-SshdConfig {
    if (-not (Test-Path -LiteralPath $SshdConfigPath)) {
        throw "$SshdConfigPath not found; sshd never generated it. Check that sshd started, then re-run."
    }

    $old = [IO.File]::ReadAllLines($SshdConfigPath)
    $new = Get-SshdConfigUpdate -Lines $old -Directives $SshdDirectives
    $sshd = Get-SshdExePath

    if (($old -join "`n") -ceq ($new -join "`n")) {
        & $sshd -t -f $SshdConfigPath
        if ($LASTEXITCODE -ne 0) {
            throw "sshd_config validation failed with exit code $LASTEXITCODE"
        }
        Write-Step 'sshd_config already correct.'
        return
    }

    if ($env:SSH_CONNECTION -and -not $Force) {
        throw 'sshd_config needs changes and sshd must restart; re-run with -Force or from RDP/local.'
    }

    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $backup = Join-Path $BackupDir 'sshd_config'
    Copy-Item -LiteralPath $SshdConfigPath -Destination $backup -Force

    Write-Step "Writing $SshdConfigPath..."
    [IO.File]::WriteAllLines($SshdConfigPath, $new, (New-Object System.Text.UTF8Encoding $false))

    & $sshd -t -f $SshdConfigPath
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Copy-Item -LiteralPath $backup -Destination $SshdConfigPath -Force
        throw "sshd_config validation failed with exit code $code; restored $backup"
    }

    Write-Step 'Restarting sshd...'
    Restart-Service -Name sshd
    $script:Changes.Add('updated sshd_config and restarted sshd')
}

function Get-SshMdmFirewallRule {
    return @(
        Get-NetFirewallRule -PolicyStore ActiveStore -PolicyStoreSourceType MDM -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
            Where-Object { @(($_ | Get-NetFirewallPortFilter).LocalPort) -contains '22' }
    )
}

function Get-SshLocalFirewallRuleState {
    $r = Get-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue
    if (-not $r) { return $null }
    return [pscustomobject]@{
        Enabled       = "$($r.Enabled)"
        Profile       = "$($r.Profile)"
        RemoteAddress = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
    }
}

function Set-SshFirewallRule {
    # An MDM rule means MDM owns SSH reachability, so the local rule is left alone. Otherwise the
    # local rule is opened on every network profile, but only to the local subnet.
    $rules = @(Get-SshMdmFirewallRule)
    if ($rules.Count -gt 0) {
        Write-Step "Found MDM firewall rule for TCP 22: $(($rules | ForEach-Object { $_.DisplayName }) -join ', ')"
        return
    }

    $state = Get-SshLocalFirewallRuleState
    if (-not $state) {
        Write-Step 'Creating firewall rule OpenSSH-Server-In-TCP...'
        New-NetFirewallRule -Name OpenSSH-Server-In-TCP -DisplayName 'OpenSSH SSH Server (sshd)' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -RemoteAddress LocalSubnet -Enabled True | Out-Null
        $script:Changes.Add('created firewall rule OpenSSH-Server-In-TCP (TCP 22, local subnet, all profiles)')
        return
    }

    $u = Get-FirewallRuleUpdate -Enabled $state.Enabled -Profile $state.Profile -RemoteAddress $state.RemoteAddress
    if ($u.Count -gt 0) {
        Write-Step "Updating firewall rule OpenSSH-Server-In-TCP: $($u.Keys -join ', ')..."
        Set-NetFirewallRule -Name OpenSSH-Server-In-TCP @u
        $script:Changes.Add("updated firewall rule OpenSSH-Server-In-TCP: $($u.Keys -join ', ')")
    } else {
        Write-Step 'Firewall rule OpenSSH-Server-In-TCP already allows TCP 22 from the local subnet.'
    }
}

function Test-SshListener {
    $listener = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue
    if (-not $listener) {
        throw 'TCP/22 listener was not found; sshd is not accepting connections.'
    }
    Write-Step 'Verified TCP/22 listener is present.'
}

function Write-Summary {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Write-Host is the only output Start-Transcript records on Windows PowerShell 5.1; the transcript is the setup log.')]
    param()

    if ($script:Changes.Count -eq 0) {
        Write-Step 'Done. No changes were needed.'
    } else {
        Write-Step 'Done. Changed:'
        foreach ($change in $script:Changes) {
            Write-Host "  - $change"
        }
    }

    $addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            ForEach-Object { $_.IPAddress }
    )
    foreach ($address in $addresses) {
        Write-Host "ssh $UserName@$address"
    }
}

function Invoke-Main {
    if (-not (Test-IsDesktopEdition)) {
        throw 'Run this with Windows PowerShell: powershell.exe -ExecutionPolicy Bypass -File .\setup-ssh-user.ps1'
    }
    if (-not (Test-IsAdmin)) {
        throw 'This script must run elevated as an administrator.'
    }
    if (-not $UserName) {
        throw 'Pass -UserName ssh-<name>.'
    }
    # The card is read before the transcript and before any change, so a missing YubiKey changes nothing.
    if (-not $PublicKey) {
        $script:PublicKey = Get-CardSshPublicKey
    }
    Assert-PublicKeyFormat -PublicKey $PublicKey

    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    Start-Transcript -Path $LogPath -Force | Out-Null

    try {
        Write-Step "Starting SSH user setup for $UserName."
        Write-Step "Log path: $LogPath"

        Install-OpenSSHServer
        Start-OpenSSHService
        Set-SshUserAccount
        Set-AdminAuthorizedKey
        Set-DefaultShell
        Set-SshdConfig
        Set-PowerForRemoteAccess
        Test-SshListener
        Set-SshFirewallRule
        Write-Summary
    } catch {
        Write-Step "ERROR: $($_.Exception.Message)"
        Write-Step "Log: $LogPath"
        throw
    } finally {
        Stop-Transcript | Out-Null
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
