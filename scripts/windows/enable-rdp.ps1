<#
.SYNOPSIS
Give a user RDP and local admin rights on a Windows PC.

.DESCRIPTION
First it makes the RDP host ready, unless policy or MDM already does: Home editions fail,
Remote Desktop and NLA are turned on, and the built-in Remote Desktop firewall rules are
opened to the local subnet on every network profile.

Then it adds -Principal to the local Administrators and Remote Desktop Users groups with
net localgroup, and verifies each membership by SID. Entra users connect from a Mac with
Entra web-account sign-in in Windows App; see README.md in this folder. Local and Microsoft
accounts sign in with the account password; a Microsoft account that has only ever used a
PIN or Windows Hello needs one password sign-in first. -RdpUserName is the user name in the
connection file: required for MicrosoftAccount, and -Principal by default for Local.

Then it asks which Windows App connection file you want (Entra: hostname, IP by device name,
or IP by device ID; local and Microsoft accounts: IP or hostname) and prints a QR code.
Scanning it with the iPhone camera opens Messages with a shell command; pasted into Terminal
on the Mac, it writes ~/Desktop/<host>-<variant>.rdp. The command is also printed as text.
Over SSH there is no prompt and no QR code; the commands for every file are printed instead.

rdp-qr.ps1 must sit in the same folder; this script dot-sources it. If it cannot be loaded,
the memberships are still set and only the QR code step fails, with a warning.

Run from an elevated Windows PowerShell session:
  powershell.exe -ExecutionPolicy Bypass -File .\enable-rdp.ps1 -Principal 'AzureAD\user@example.com' -AccountType Entra
  powershell.exe -ExecutionPolicy Bypass -File .\enable-rdp.ps1 -Principal "$env:COMPUTERNAME\alice" -AccountType Local

It is safe to re-run. It exits non-zero if the RDP host cannot be made ready or either
membership is not in place.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read by the functions below through script scope; the rule does not search function bodies.')]
[CmdletBinding()]
param(
    [string]$Principal,
    [ValidateSet('Entra', 'Local', 'MicrosoftAccount')][string]$AccountType,
    [string]$RdpUserName
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:RdpChanges = New-Object System.Collections.Generic.List[string]
$GroupSids = @(
    'S-1-5-32-544'  # Administrators
    'S-1-5-32-555'  # Remote Desktop Users
)

$script:QrLoadError = $null
try { . (Join-Path $PSScriptRoot 'rdp-qr.ps1') } catch { $script:QrLoadError = $_.Exception.Message }

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Status output for an interactive admin script.')]
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Get-UserSid {
    param([Parameter(Mandatory)][string]$Principal)
    try {
        return ([Security.Principal.NTAccount]$Principal).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Could not resolve $Principal to a SID: $($_.Exception.Message)"
    }
}

function Get-GroupName {
    param([Parameter(Mandatory)][string]$GroupSid)
    return (Get-LocalGroup -SID $GroupSid).Name
}

function Get-GroupMemberSid {
    param([Parameter(Mandatory)][string]$GroupSid)
    return @(Get-LocalGroupMember -SID $GroupSid | ForEach-Object { $_.SID.Value })
}

function Invoke-NetLocalGroupAdd {
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$Principal
    )
    & net.exe localgroup $GroupName $Principal /add
    if ($LASTEXITCODE -ne 0) {
        throw "net localgroup `"$GroupName`" $Principal /add failed with exit code $LASTEXITCODE"
    }
}

function Add-UserToGroup {
    param(
        [Parameter(Mandatory)][string]$GroupSid,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][string]$UserSid
    )
    $groupName = Get-GroupName -GroupSid $GroupSid
    if ((Get-GroupMemberSid -GroupSid $GroupSid) -contains $UserSid) {
        Write-Step "$Principal is already a member of $groupName."
        return
    }
    Write-Step "Adding $Principal to $groupName."
    Invoke-NetLocalGroupAdd -GroupName $groupName -Principal $Principal
    if ((Get-GroupMemberSid -GroupSid $GroupSid) -notcontains $UserSid) {
        throw "$Principal ($UserSid) is still not a member of $groupName after net localgroup /add."
    }
    Write-Step "Added $Principal to $groupName."
}

function Resolve-RdpTarget {
    # Entra needs AzureAD\<upn>: the bare UPN and Translate()'s AD\name do not resolve for RDP.
    [OutputType([pscustomobject])]
    param(
        [string]$Principal,
        [string]$AccountType,
        [string]$RdpUserName
    )
    $usage = 'Usage: -Principal <AzureAD\upn | COMPUTER\name> -AccountType Entra|Local|MicrosoftAccount [-RdpUserName <name>]'
    if (-not $Principal -or -not $AccountType) { throw $usage }
    if ($AccountType -eq 'Entra') {
        if ($Principal -notlike 'AzureAD\*@*' -or $RdpUserName) { throw $usage }
        $rdpUser = $null
    } elseif ($AccountType -eq 'MicrosoftAccount') {
        if (-not $RdpUserName) { throw $usage }
        $rdpUser = $RdpUserName
    } elseif ($AccountType -eq 'Local') {
        $rdpUser = $RdpUserName
        if (-not $rdpUser) { $rdpUser = $Principal }
    } else {
        throw $usage
    }
    return [pscustomobject]@{ Principal = $Principal; AccountType = $AccountType; RdpUserName = $rdpUser }
}

function Test-RdpHostEdition {
    # Home editions (EditionID Core, CoreN, CoreSingleLanguage, ...) have no RDP host.
    [OutputType([bool])]
    param([string]$EditionId)
    return $EditionId -notlike 'Core*'
}

function Get-RdpPolicyDecision {
    # A policy value wins over the local one, so a conflicting policy fails instead of being
    # silently overridden; a local write would have no effect.
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$PolicyValue,
        [Parameter(Mandatory)][int]$Wanted
    )
    if ($null -eq $PolicyValue) { return 'set-local' }
    if ($PolicyValue -eq $Wanted) { return 'policy-ok' }
    if ($Name -eq 'fDenyTSConnections') {
        throw "Policy sets fDenyTSConnections=$PolicyValue, so RDP is off by policy; change the policy, then re-run."
    }
    if ($Name -eq 'UserAuthentication') {
        throw "Policy sets UserAuthentication=$PolicyValue, so NLA is off by policy; refusing to open RDP without NLA."
    }
    throw "Policy sets $Name=$PolicyValue, but $Wanted is needed."
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

function Get-RegistryValue {
    # $null when the key or the value does not exist.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $key) { return $null }
    return $key.GetValue($Name)
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Get-RdpMdmFirewallRule {
    return @(
        Get-NetFirewallRule -PolicyStore ActiveStore -PolicyStoreSourceType MDM -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
            Where-Object { @(($_ | Get-NetFirewallPortFilter).LocalPort) -contains '3389' }
    )
}

function Get-RdpLocalFirewallRuleState {
    param([Parameter(Mandatory)][string]$Name)
    $r = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if (-not $r) { return $null }
    return [pscustomobject]@{
        Enabled       = "$($r.Enabled)"
        Profile       = "$($r.Profile)"
        RemoteAddress = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
    }
}

function Set-FirewallRuleScope {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][Collections.IDictionary]$Update
    )
    Set-NetFirewallRule -Name $Name @Update
}

function Enable-RdpHost {
    # Policy and MDM win: a policy value or an MDM firewall rule is reported and never changed.
    # Everything is decided before anything changes, so a refusal leaves the PC as it was.
    $editionId = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID'
    if (-not (Test-RdpHostEdition -EditionId $editionId)) {
        throw "Windows edition $editionId cannot host Remote Desktop. SSH is already set up; RDP needs Windows Pro or higher."
    }

    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $settings = @(
        @{ Name = 'fDenyTSConnections'; Wanted = 0; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Change = 'turned Remote Desktop on'; PolicyOk = 'Remote Desktop is turned on by policy.' }
        @{ Name = 'UserAuthentication'; Wanted = 1; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Change = 'turned on NLA for RDP-Tcp'; PolicyOk = 'NLA is turned on by policy.' }
    )
    foreach ($setting in $settings) {
        $setting.Decision = Get-RdpPolicyDecision -Name $setting.Name -PolicyValue (Get-RegistryValue -Path $pol -Name $setting.Name) -Wanted $setting.Wanted
        $setting.NeedsWrite = $setting.Decision -ne 'policy-ok' -and (Get-RegistryValue -Path $setting.Path -Name $setting.Name) -ne $setting.Wanted
    }
    $rules = @(Get-RdpMdmFirewallRule)
    $updates = [ordered]@{}
    if ($rules.Count -eq 0) {
        foreach ($name in 'RemoteDesktop-UserMode-In-TCP', 'RemoteDesktop-UserMode-In-UDP') {
            $state = Get-RdpLocalFirewallRuleState -Name $name
            if (-not $state) {
                throw "Built-in firewall rule $name not found."
            }
            $updates[$name] = Get-FirewallRuleUpdate -Enabled $state.Enabled -Profile $state.Profile -RemoteAddress $state.RemoteAddress
        }
    }

    foreach ($setting in $settings) {
        if ($setting.Decision -eq 'policy-ok') {
            Write-Step $setting.PolicyOk
        } elseif ($setting.NeedsWrite) {
            Set-RegistryDword -Path $setting.Path -Name $setting.Name -Value $setting.Wanted
            Write-Step "Set $($setting.Name) to $($setting.Wanted)."
            $script:RdpChanges.Add($setting.Change)
        }
    }
    if ($rules.Count -gt 0) {
        Write-Step "Found MDM firewall rule for port 3389: $(($rules | ForEach-Object { $_.DisplayName }) -join ', ')"
        return
    }
    foreach ($name in $updates.Keys) {
        $u = $updates[$name]
        if ($u.Count -gt 0) {
            Write-Step "Updating firewall rule ${name}: $($u.Keys -join ', ')..."
            Set-FirewallRuleScope -Name $name -Update $u
            $script:RdpChanges.Add("updated firewall rule ${name}: $($u.Keys -join ', ')")
        } else {
            Write-Step "Firewall rule $name already allows RDP from the local subnet."
        }
    }
}

function Get-RdpFileLine {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('hostname', 'ip-name', 'ip-deviceid', 'ip')][string]$Variant,
        [Parameter(Mandatory)][string]$HostName,
        [string]$IpAddress,
        [string]$DeviceId,
        [string]$UserName
    )
    if ($UserName) {
        # Password sign-in: NLA needs the user name, and enablerdsaadauth would force Entra sign-in.
        if ($Variant -ne 'hostname' -and $Variant -ne 'ip') {
            throw "The $Variant file is for Entra accounts only."
        }
        $address = $HostName
        if ($Variant -eq 'ip') {
            if (-not $IpAddress) {
                throw 'The ip connection file needs -IpAddress.'
            }
            $address = $IpAddress
        }
        return @("full address:s:$address", "username:s:$UserName", 'screen mode id:i:1')
    }
    if ($Variant -eq 'ip') {
        throw 'The ip file needs -UserName.'
    }
    if ($Variant -eq 'hostname') {
        return @("full address:s:$HostName", 'enablerdsaadauth:i:1', 'screen mode id:i:1')
    }
    if (-not $IpAddress) {
        throw "The $Variant connection file needs -IpAddress."
    }
    if ($Variant -eq 'ip-name') {
        $identity = $HostName
        $identityType = 'Entra ID Device Name'
    } else {
        if (-not $DeviceId) {
            throw "The $Variant connection file needs -DeviceId."
        }
        $identity = $DeviceId
        $identityType = 'Entra ID Device ID'
    }
    return @("full address:s:$IpAddress", 'enablerdsaadauth:i:1', "server identity:s:$identity", "server identity type:s:$identityType", 'screen mode id:i:1')
}

function Get-MacRdpCommand {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$Variant,
        [Parameter(Mandatory)][string[]]$Line
    )
    # Inside a single-quoted printf format: \ and % are printf escapes, and ' ends the quote.
    $escaped = foreach ($item in $Line) { $item.Replace('\', '\\').Replace('%', '%%').Replace("'", "'\''") }
    $format = (@($escaped) -join '\n') + '\n'
    # >| because zsh with noclobber refuses to overwrite with >.
    return "printf '$format' >| ~/Desktop/${HostName}-${Variant}.rdp"
}

function Get-MacRdpMessage {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$Variant,
        [Parameter(Mandatory)][string]$Command
    )
    return "RDP file for $HostName ($Variant). Paste in Terminal on your Mac:`n$Command"
}

function Get-SmsUri {
    # Encoded by hand because [Uri]::EscapeDataString differs across .NET versions.
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Body)
    $uri = [Text.StringBuilder]::new('sms://open?addresses=&body=')
    foreach ($byte in [Text.Encoding]::UTF8.GetBytes($Body)) {
        $unreserved = ($byte -ge 0x41 -and $byte -le 0x5A) -or ($byte -ge 0x61 -and $byte -le 0x7A) -or
            ($byte -ge 0x30 -and $byte -le 0x39) -or $byte -eq 0x2D -or $byte -eq 0x2E -or $byte -eq 0x5F -or $byte -eq 0x7E
        if ($unreserved) {
            [void]$uri.Append([char]$byte)
        } else {
            [void]$uri.Append(('%{0:X2}' -f $byte))
        }
    }
    return $uri.ToString()
}

function Get-DeviceIdFromDsregcmd {
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)
    foreach ($item in $Line) {
        if ($item -match '^\s*DeviceId\s*:\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*$') {
            return $Matches[1]
        }
    }
    throw 'No DeviceId line found in dsregcmd /status output; is this PC Entra joined?'
}

function Get-LanIPv4 {
    [OutputType([string])]
    param()
    $candidates = @(
        foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            $interface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4
            foreach ($address in @(Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                if ($address.IPAddress -notlike '169.254.*') {
                    [pscustomobject]@{ IPAddress = $address.IPAddress; Metric = $route.RouteMetric + $interface.InterfaceMetric }
                }
            }
        }
    )
    if ($candidates.Count -eq 0) {
        throw 'No IPv4 address found on an interface with a default route (0.0.0.0/0).'
    }
    return ($candidates | Sort-Object Metric | Select-Object -First 1).IPAddress
}

function Get-EntraDeviceId {
    [OutputType([string])]
    param()
    $output = @(& dsregcmd.exe /status)
    if ($LASTEXITCODE -ne 0) {
        throw "dsregcmd /status failed with exit code $LASTEXITCODE"
    }
    return Get-DeviceIdFromDsregcmd -Line $output
}

function Read-RdpVariant {
    [OutputType([string])]
    param([string]$AccountType = 'Entra')
    $variants = @{ '' = 'hostname'; '1' = 'hostname'; '2' = 'ip-name'; '3' = 'ip-deviceid' }
    $prompt = 'Connection file for your Mac: 1 = hostname, 2 = IP by device name, 3 = IP by device ID [1]'
    if ($AccountType -ne 'Entra') {
        $variants = @{ '' = 'ip'; '1' = 'ip'; '2' = 'hostname' }
        $prompt = 'Connection file for your Mac: 1 = IP, 2 = hostname [1]'
    }
    while ($true) {
        $answer = ([string](Read-Host $prompt)).Trim()
        if ($variants.ContainsKey($answer)) {
            return $variants[$answer]
        }
    }
}

function Write-MacCommand {
    # No timestamp prefix, so the whole line can be copied into Terminal.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Status output for an interactive admin script.')]
    param([Parameter(Mandatory)][string]$Command)
    Write-Host $Command
}

function Get-PcHostName {
    # The DNS host name; $env:COMPUTERNAME is the NetBIOS name, cut to 15 characters.
    [OutputType([string])]
    param()
    return [Net.Dns]::GetHostName()
}

function Get-ConsoleWindowSize {
    # $null when the host has no console window; some hosts throw on RawUI.WindowSize.
    param()
    try {
        return $Host.UI.RawUI.WindowSize
    } catch {
        return $null
    }
}

function Show-MacRdpSetup {
    # -UserName is empty for Entra accounts; otherwise it is the username:s: value.
    param([string]$UserName)
    $hostName = Get-PcHostName
    if ($env:SSH_CONNECTION) {
        $ipAddress = $null
        $deviceId = $null
        $ipError = $null
        $deviceIdError = $null
        try { $ipAddress = Get-LanIPv4 } catch { $ipError = $_.Exception.Message }
        $variants = 'ip', 'hostname'
        if (-not $UserName) {
            try { $deviceId = Get-EntraDeviceId } catch { $deviceIdError = $_.Exception.Message }
            $variants = 'hostname', 'ip-name', 'ip-deviceid'
        }
        Write-Step 'Over SSH, so no QR code. To write a Windows App connection file to ~/Desktop, paste one of these into Terminal on your Mac:'
        foreach ($variant in $variants) {
            $reasons = @()
            if ($variant -ne 'hostname' -and $ipError) { $reasons += $ipError }
            if ($variant -eq 'ip-deviceid' -and $deviceIdError) { $reasons += $deviceIdError }
            if ($reasons) {
                Write-Warning "Skipped ${variant}: $($reasons -join ' ')"
                continue
            }
            $line = Get-RdpFileLine -Variant $variant -HostName $hostName -IpAddress $ipAddress -DeviceId $deviceId -UserName $UserName
            Write-MacCommand -Command (Get-MacRdpCommand -HostName $hostName -Variant $variant -Line $line)
        }
        return
    }

    if ($script:QrLoadError) {
        throw "rdp-qr.ps1 could not be loaded: $script:QrLoadError"
    }
    $accountType = 'Entra'
    if ($UserName) { $accountType = 'Local' }
    $variant = Read-RdpVariant -AccountType $accountType
    $ipAddress = $null
    $deviceId = $null
    if ($variant -ne 'hostname') { $ipAddress = Get-LanIPv4 }
    if ($variant -eq 'ip-deviceid') { $deviceId = Get-EntraDeviceId }
    $line = Get-RdpFileLine -Variant $variant -HostName $hostName -IpAddress $ipAddress -DeviceId $deviceId -UserName $UserName
    $command = Get-MacRdpCommand -HostName $hostName -Variant $variant -Line $line
    $message = Get-MacRdpMessage -HostName $hostName -Variant $variant -Command $command
    $uri = Get-SmsUri -Body $message
    Write-Step 'Or paste this command into Terminal on your Mac:'
    Write-MacCommand -Command $command
    $rows = (New-QrMatrix -Text $uri).Rows
    Write-Step 'Scan the QR code below with the iPhone camera and send the message to yourself.'
    $needed = Get-QrConsoleSize -Rows $rows
    $window = Get-ConsoleWindowSize
    # One more row for the prompt line after the QR code.
    if ($window -and ($window.Width -lt $needed.Width -or $window.Height -lt $needed.Height + 1)) {
        Write-Warning "Make this window at least $($needed.Width) columns by $($needed.Height + 1) rows (maximize it), or the QR code will not fit on screen."
    }
    Write-QrCode -Rows $rows
}

function Invoke-Main {
    if (-not (Test-IsAdmin)) {
        throw 'This script must run elevated as an administrator.'
    }
    $t = Resolve-RdpTarget -Principal $Principal -AccountType $AccountType -RdpUserName $RdpUserName
    Write-Step "Configuring RDP access for $($t.Principal)."
    Enable-RdpHost
    $userSid = Get-UserSid -Principal $t.Principal
    Write-Step "User SID: $userSid"
    foreach ($groupSid in $GroupSids) {
        Add-UserToGroup -GroupSid $groupSid -Principal $t.Principal -UserSid $userSid
    }
    Write-Step "Done. $($t.Principal) is a member of Administrators and Remote Desktop Users."
    if ($script:RdpChanges.Count -gt 0) {
        Write-Step "RDP host changes: $($script:RdpChanges -join '; ')."
    }
    if ($t.AccountType -eq 'Entra') {
        Write-Step 'Connect from Windows App with Entra web-account sign-in; see README.md.'
    } else {
        Write-Step "Connect from Windows App as $($t.RdpUserName) with the account password (not a PIN or Windows Hello)."
    }
    try {
        Show-MacRdpSetup -UserName $t.RdpUserName
    } catch {
        # The memberships are in place; a missing connection file must not fail the run.
        Write-Warning "Could not prepare the Mac connection file: $($_.Exception.Message) See README.md to write the connection file by hand."
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
