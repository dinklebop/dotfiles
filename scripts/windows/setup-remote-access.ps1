<#
.SYNOPSIS
Pick an account on this PC, then set up SSH and RDP for it.

.DESCRIPTION
Lists the user profiles on this PC that can get remote access: Entra accounts (by their
cached UPN), local accounts, and Microsoft accounts. Built-in, disabled, and ssh-* accounts
are left out. You pick one, and the script:
  1. runs setup-ssh-user.ps1 -UserName ssh-<name>, which reads the SSH key from the YubiKey
     (or uses -PublicKey), then
  2. runs enable-rdp.ps1 for the picked account.
Both scripts must sit in the same folder as this one. Any failure stops the run and exits
non-zero. A Home edition fails only the RDP half, after SSH is set up.

The SSH account name is ssh- plus the lowercased UPN prefix (Entra), email prefix (Microsoft
account), or account name (local). If that is not a valid name (20 characters at most), you
are asked for one. For a Microsoft account without a cached email, you are asked for it.

The choice is saved to C:\ProgramData\SshUserSetup\selection.json. A re-run, such as the
one chezmoi apply starts when a script changes, uses the saved choice without prompting
while its profile still exists. -Reselect asks again. If the saved profile is gone, it warns
and asks again. A new choice with a different SSH account name leaves the old ssh-<name>
account in place and prints how to remove it.

-PublicKey '<ssh key>' is passed to setup-ssh-user.ps1 and skips the YubiKey.

Run from an elevated Windows PowerShell session:
  powershell.exe -ExecutionPolicy Bypass -File .\setup-remote-access.ps1 [-Reselect] [-PublicKey '<ssh key>']
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read by the functions below through script scope; the rule does not search function bodies.')]
[CmdletBinding()]
param(
    [switch]$Reselect,
    [string]$PublicKey
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$SelectionPath = Join-Path $env:ProgramData 'SshUserSetup\selection.json'
# Administrator, Guest, DefaultAccount, WDAGUtilityAccount.
$ExcludedRids = 500, 501, 503, 504
$SelectionProperties = 'Sid', 'AccountType', 'DisplayName', 'Principal', 'RdpUserName', 'SshUserName'

# ---------------------------------------------------------------------------
# Pure functions (covered by Pester; must not touch the system)
# ---------------------------------------------------------------------------

function ConvertTo-SshUserName {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    return 'ssh-' + ($Name -split '@')[0].ToLowerInvariant()
}

function Test-SshUserName {
    # Windows caps local account names at 20 characters.
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    return $Name -cmatch '^ssh-[a-z0-9][a-z0-9._-]*$' -and $Name.Length -le 20
}

function Get-RemoteAccessCandidate {
    # Entra profiles need a cached UPN: Translate() gives AD\name, which RDP cannot use.
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profiles,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$LocalUsers,
        [Parameter(Mandatory)][hashtable]$IdentityNames,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $candidates = foreach ($p in $Profiles) {
        if ($p.Special) { continue }
        $sid = [string]$p.Sid

        if ($sid -like 'S-1-12-1-*') {
            $upn = $IdentityNames[$sid]
            if (-not $upn -or -not ([string]$upn).Contains('@')) {
                Write-Warning "Skipping Entra profile $($p.LocalPath): no cached UPN."
                continue
            }
            [pscustomobject]@{
                Sid         = $sid
                AccountType = 'Entra'
                DisplayName = "$upn (Entra)"
                Principal   = "AzureAD\$upn"
                RdpUserName = $null
                SshUserName = ConvertTo-SshUserName -Name $upn
                NeedsEmail  = $false
            }
        } elseif ($sid -like 'S-1-5-21-*') {
            $user = @($LocalUsers | Where-Object { $_.Sid -eq $sid }) | Select-Object -First 1
            if (-not $user) { continue }
            if ($ExcludedRids -contains [int64](($sid -split '-')[-1])) { continue }
            if (-not $user.Enabled -or $user.Name -like 'ssh-*') { continue }

            $principal = "$ComputerName\$($user.Name)"
            if ($user.PrincipalSource -eq 'MicrosoftAccount') {
                $email = $IdentityNames[$sid]
                if (-not $email -or -not ([string]$email).Contains('@')) { $email = $null }
                $name = $user.Name
                $rdpUser = $null
                if ($email) {
                    $name = $email
                    $rdpUser = "MicrosoftAccount\$email"
                }
                [pscustomobject]@{
                    Sid         = $sid
                    AccountType = 'MicrosoftAccount'
                    DisplayName = "$name (Microsoft account: RDP needs the account password, not a PIN or Windows Hello)"
                    Principal   = $principal
                    RdpUserName = $rdpUser
                    SshUserName = ConvertTo-SshUserName -Name $name
                    NeedsEmail  = -not $email
                }
            } else {
                [pscustomobject]@{
                    Sid         = $sid
                    AccountType = 'Local'
                    DisplayName = "$($user.Name) (local)"
                    Principal   = $principal
                    RdpUserName = $principal
                    SshUserName = ConvertTo-SshUserName -Name $user.Name
                    NeedsEmail  = $false
                }
            }
        }
    }
    return @($candidates | Sort-Object -Property DisplayName)
}

function Test-SavedSelection {
    [OutputType([bool])]
    param(
        [AllowNull()][object]$Selection,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates
    )
    if ($null -eq $Selection) { return $false }
    $names = @($Selection.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($property in $SelectionProperties) {
        if ($names -notcontains $property) { return $false }
    }
    return @($Candidates | ForEach-Object { $_.Sid }) -contains $Selection.Sid
}

# ---------------------------------------------------------------------------
# System and prompt functions
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Status output for an interactive admin script.')]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Get-ProfileRecord {
    return @(
        Get-CimInstance Win32_UserProfile | ForEach-Object {
            [pscustomobject]@{ Sid = $_.SID; LocalPath = $_.LocalPath; Special = $_.Special }
        }
    )
}

function Get-LocalUserRecord {
    return @(
        Get-LocalUser | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Sid = $_.SID.Value; Enabled = $_.Enabled; PrincipalSource = "$($_.PrincipalSource)" }
        }
    )
}

function Get-IdentityName {
    # The UPN (Entra) or email (Microsoft account) Windows cached at sign-in; $null when absent.
    param([Parameter(Mandatory)][string]$Sid)
    $key = Get-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$Sid\IdentityCache\$Sid" -ErrorAction SilentlyContinue
    if (-not $key) { return $null }
    return $key.GetValue('UserName')
}

function Read-Selection {
    if (-not (Test-Path -LiteralPath $SelectionPath)) { return $null }
    return [IO.File]::ReadAllText($SelectionPath, (New-Object System.Text.UTF8Encoding $false)) | ConvertFrom-Json
}

function Write-Selection {
    param([Parameter(Mandatory)][object]$Selection)
    New-Item -ItemType Directory -Path (Split-Path -Parent $SelectionPath) -Force | Out-Null
    [IO.File]::WriteAllText($SelectionPath, ($Selection | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false))
}

function Read-CandidateChoice {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Status output for an interactive admin script.')]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates)

    if ($Candidates.Count -eq 0) {
        throw 'No eligible user profile found. Sign in once as the user you want, then re-run.'
    }
    for ($i = 0; $i -lt $Candidates.Count; $i++) {
        Write-Host "$($i + 1)) $($Candidates[$i].DisplayName)"
    }
    while ($true) {
        $raw = Read-Host 'Set up SSH and RDP for which account? [number]'
        if ($null -eq $raw) { throw 'No input available; run setup-remote-access.ps1 from an interactive elevated console.' }
        $answer = ([string]$raw).Trim()
        $number = 0
        if ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $Candidates.Count) {
            return $Candidates[$number - 1]
        }
    }
}

function Read-Email {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    while ($true) {
        $raw = Read-Host "Microsoft account email for $Name"
        if ($null -eq $raw) { throw 'No input available; run setup-remote-access.ps1 from an interactive elevated console.' }
        $answer = ([string]$raw).Trim()
        if ($answer.Contains('@')) { return $answer }
    }
}

function Read-SshUserName {
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Suggested)
    $prompt = 'SSH account name (ssh-<name>, 20 characters at most)'
    $suggestedOk = Test-SshUserName -Name $Suggested
    if ($suggestedOk) { $prompt += " [$Suggested]" }
    while ($true) {
        $raw = Read-Host $prompt
        if ($null -eq $raw) { throw 'No input available; run setup-remote-access.ps1 from an interactive elevated console.' }
        $answer = ([string]$raw).Trim()
        if (-not $answer -and $suggestedOk) { return $Suggested }
        if (Test-SshUserName -Name $answer) { return $answer }
    }
}

function Invoke-RemoteAccessScript {
    # In-process, so an exception from the script propagates and this run exits non-zero.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Arguments
    )
    & (Join-Path $PSScriptRoot $Name) @Arguments
}

function Resolve-RemoteAccessSelection {
    $profiles = @(Get-ProfileRecord)
    $users = @(Get-LocalUserRecord)
    $names = @{}
    foreach ($p in $profiles) {
        if ($p.Special) { continue }
        $name = Get-IdentityName -Sid $p.Sid
        if ($null -ne $name) { $names[$p.Sid] = $name }
    }
    $candidates = @(Get-RemoteAccessCandidate -Profiles $profiles -LocalUsers $users -IdentityNames $names -ComputerName $env:COMPUTERNAME)

    # An unreadable selection.json counts as one that no longer matches, so the new choice overwrites it.
    $unreadable = $false
    try {
        $saved = Read-Selection
    } catch {
        $saved = $null
        $unreadable = $true
    }
    $valid = Test-SavedSelection -Selection $saved -Candidates $candidates
    if ($valid -and -not $Reselect) {
        Write-Step "Using saved selection $($saved.DisplayName) -> $($saved.SshUserName) (re-run with -Reselect to change)."
        return $saved
    }
    if ($unreadable -or ($null -ne $saved -and -not $valid)) {
        Write-Warning 'Saved selection no longer matches a profile on this PC; choose again.'
    }

    $choice = Read-CandidateChoice -Candidates $candidates
    $rdpUserName = $choice.RdpUserName
    $sshUserName = $choice.SshUserName
    if ($choice.NeedsEmail) {
        $email = Read-Email -Name $choice.Principal
        $rdpUserName = "MicrosoftAccount\$email"
        $sshUserName = ConvertTo-SshUserName -Name $email
    }
    if (-not (Test-SshUserName -Name $sshUserName)) {
        $sshUserName = Read-SshUserName -Suggested $sshUserName
    }

    $selection = [pscustomobject]@{
        Sid         = $choice.Sid
        AccountType = $choice.AccountType
        DisplayName = $choice.DisplayName
        Principal   = $choice.Principal
        RdpUserName = $rdpUserName
        SshUserName = $sshUserName
    }
    Write-Selection -Selection $selection

    $old = $null
    if ($null -ne $saved -and $saved.PSObject.Properties['SshUserName']) { $old = $saved.SshUserName }
    if ($old -and $old -ne $selection.SshUserName) {
        Write-Step "The previous SSH account $old was left in place. Remove it with: Remove-LocalUser -Name $old"
    }
    return $selection
}

function Invoke-Main {
    if (-not (Test-IsDesktopEdition)) {
        throw 'Run this with Windows PowerShell: powershell.exe -ExecutionPolicy Bypass -File .\setup-remote-access.ps1'
    }
    if (-not (Test-IsAdmin)) {
        throw 'This script must run elevated as an administrator.'
    }

    $sel = Resolve-RemoteAccessSelection

    $sshArgs = @{ UserName = $sel.SshUserName }
    if ($PublicKey) { $sshArgs.PublicKey = $PublicKey }
    Invoke-RemoteAccessScript -Name 'setup-ssh-user.ps1' -Arguments $sshArgs

    $rdpArgs = @{ Principal = $sel.Principal; AccountType = $sel.AccountType }
    if ($null -ne $sel.RdpUserName) { $rdpArgs.RdpUserName = $sel.RdpUserName }
    Invoke-RemoteAccessScript -Name 'enable-rdp.ps1' -Arguments $rdpArgs
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
