Describe 'enable-rdp.ps1' {
    BeforeAll {
        $ScriptPath = Join-Path $PSScriptRoot '..' 'enable-rdp.ps1'
        . $ScriptPath

        # Dot-sourcing puts the parameters in this scope. Remove them so the tests set them in
        # script scope, where they live on a real run.
        Remove-Variable -Name Principal, AccountType, RdpUserName

        # Spelled out here (not read from the script) so a changed value fails the tests.
        $UserSid = 'S-1-12-1-1000000001-1000000002-1000000003-1000000004'
        $OtherSid = 'S-1-12-1-2000000001-2000000002-2000000003-2000000004'
    }

    It 'contains only ASCII bytes, because Windows PowerShell 5.1 reads BOM-less files as Windows-1252 and silently drops the code around non-ASCII characters' {
        $nonAscii = @([IO.File]::ReadAllBytes($ScriptPath) | Where-Object { $_ -gt 0x7F })
        $nonAscii.Count | Should -Be 0
    }

    It 'targets Administrators and Remote Desktop Users by well-known SID, because RDP needs the logon right and D3 keeps local admin' {
        $GroupSids | Should -Be @('S-1-5-32-544', 'S-1-5-32-555')
    }

    Context 'Add-UserToGroup' {
        BeforeEach {
            Mock Get-GroupName { 'Remote Desktop Users' }
            Mock Write-Step { }
            Mock Invoke-NetLocalGroupAdd { $script:Added = $true }
            $script:Added = $false
        }

        It 'does not add when the user SID is already a member, so re-runs change nothing' {
            Mock Get-GroupMemberSid { @($UserSid) }

            Add-UserToGroup -GroupSid 'S-1-5-32-555' -Principal 'AzureAD\user@example.com' -UserSid $UserSid

            Should -Invoke Invoke-NetLocalGroupAdd -Times 0 -Exactly
        }

        It 'adds when only a different Entra SID is present, because name matching mistook prv-user@example.com for user@example.com' {
            Mock Get-GroupMemberSid { if ($script:Added) { @($OtherSid, $UserSid) } else { @($OtherSid) } }

            Add-UserToGroup -GroupSid 'S-1-5-32-555' -Principal 'AzureAD\user@example.com' -UserSid $UserSid

            Should -Invoke Invoke-NetLocalGroupAdd -Times 1 -Exactly -ParameterFilter { $GroupName -eq 'Remote Desktop Users' -and $Principal -eq 'AzureAD\user@example.com' }
        }

        It 'throws when the user SID is still absent after the add, because the old script printed Done without checking' {
            Mock Get-GroupMemberSid { @($OtherSid) }

            { Add-UserToGroup -GroupSid 'S-1-5-32-555' -Principal 'AzureAD\user@example.com' -UserSid $UserSid } | Should -Throw '*still not a member of Remote Desktop Users*'
        }
    }

    Context 'Invoke-Main' {
        BeforeEach {
            Mock Enable-RdpHost { }
            Mock Add-UserToGroup { }
            Mock Get-UserSid { $UserSid }
            Mock Write-Step { }
        }

        It 'refuses to run unelevated and changes nothing, because group changes need admin and must not half-apply' {
            Mock Test-IsAdmin { $false }
            $script:Principal = 'AzureAD\user@example.com'
            $script:AccountType = 'Entra'
            $script:RdpUserName = ''

            { Invoke-Main } | Should -Throw '*must run elevated*'
            Should -Invoke Enable-RdpHost -Times 0 -Exactly
            Should -Invoke Add-UserToGroup -Times 0 -Exactly
        }

        It 'throws the usage error before Enable-RdpHost when -Principal and -AccountType are missing, because there is no default user to fall back to and the RDP host must not change for nobody' {
            Mock Test-IsAdmin { $true }
            $script:Principal = ''
            $script:AccountType = ''
            $script:RdpUserName = ''

            { Invoke-Main } | Should -Throw 'Usage: -Principal*'
            Should -Invoke Enable-RdpHost -Times 0 -Exactly
            Should -Invoke Get-UserSid -Times 0 -Exactly
            Should -Invoke Add-UserToGroup -Times 0 -Exactly
        }
    }

    Context 'Resolve-RdpTarget' {
        It 'rejects the Entra principal <Name> without AzureAD\, because the bare UPN or AD\name does not resolve for RDP' -ForEach @(
            @{ Name = 'user@example.com' }
            @{ Name = 'AD\user' }
        ) {
            { Resolve-RdpTarget -Principal $Name -AccountType 'Entra' } | Should -Throw 'Usage: -Principal*'
        }

        It 'accepts AzureAD\ plus the UPN with no RdpUserName and rejects one, because the Entra files sign in through Entra and carry no user name' {
            $t = Resolve-RdpTarget -Principal 'AzureAD\user@example.com' -AccountType 'Entra'

            $t.Principal | Should -BeExactly 'AzureAD\user@example.com'
            $t.AccountType | Should -BeExactly 'Entra'
            $t.RdpUserName | Should -BeNullOrEmpty
            { Resolve-RdpTarget -Principal 'AzureAD\user@example.com' -AccountType 'Entra' -RdpUserName 'x' } | Should -Throw 'Usage: -Principal*'
        }

        It 'requires -RdpUserName for MicrosoftAccount, because the local SAM name is not the Microsoft account sign-in name' {
            { Resolve-RdpTarget -Principal 'EXAMPLPC\alice' -AccountType 'MicrosoftAccount' } | Should -Throw 'Usage: -Principal*'

            (Resolve-RdpTarget -Principal 'EXAMPLPC\alice' -AccountType 'MicrosoftAccount' -RdpUserName 'MicrosoftAccount\user@example.com').RdpUserName |
                Should -BeExactly 'MicrosoftAccount\user@example.com'
        }

        It 'defaults RdpUserName to Principal for Local, because a local account signs in to RDP with COMPUTER\name' {
            (Resolve-RdpTarget -Principal 'EXAMPLPC\alice' -AccountType 'Local').RdpUserName | Should -BeExactly 'EXAMPLPC\alice'
        }
    }

    Context 'Test-RdpHostEdition' {
        It 'returns <Expected> for <EditionId>, because Home (Core*) has no RDP host and must fail loudly instead of leaving a PC that never accepts RDP' -ForEach @(
            @{ EditionId = 'Core'; Expected = $false }
            @{ EditionId = 'CoreN'; Expected = $false }
            @{ EditionId = 'CoreSingleLanguage'; Expected = $false }
            @{ EditionId = 'Professional'; Expected = $true }
            @{ EditionId = 'Enterprise'; Expected = $true }
        ) {
            Test-RdpHostEdition -EditionId $EditionId | Should -Be $Expected
        }
    }

    Context 'Get-RdpPolicyDecision' {
        It 'returns policy-ok when the policy already has the wanted value, so Intune PCs are not touched' {
            Get-RdpPolicyDecision -Name 'fDenyTSConnections' -PolicyValue 0 -Wanted 0 | Should -BeExactly 'policy-ok'
        }

        It 'returns set-local when there is no policy value, because then only the local value decides' {
            Get-RdpPolicyDecision -Name 'UserAuthentication' -PolicyValue $null -Wanted 1 | Should -BeExactly 'set-local'
        }

        It 'throws the exact message for a conflicting <Name> policy, because a local write is a silent no-op under policy and the operator must learn which policy value to change' -ForEach @(
            @{ Name = 'fDenyTSConnections'; Value = 1; Wanted = 0; Message = 'Policy sets fDenyTSConnections=1, so RDP is off by policy; change the policy, then re-run.' }
            @{ Name = 'UserAuthentication'; Value = 0; Wanted = 1; Message = 'Policy sets UserAuthentication=0, so NLA is off by policy; refusing to open RDP without NLA.' }
        ) {
            # The messages contain no wildcard characters, so -ExpectedMessage matches them exactly.
            { Get-RdpPolicyDecision -Name $Name -PolicyValue $Value -Wanted $Wanted } | Should -Throw -ExpectedMessage $Message
        }
    }

    Context 'Enable-RdpHost' {
        BeforeEach {
            $script:RdpChanges = New-Object System.Collections.Generic.List[string]
            $LocalTs = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $LocalRdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            $PolicyTs = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            $CurrentVersion = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            Mock Write-Step { }
            # A read of any other path throws, so a wrong path fails the test instead of reading as $null.
            Mock Get-RegistryValue { throw "Unexpected Get-RegistryValue -Path $Path -Name $Name" }
            Mock Get-RegistryValue { $null } -ParameterFilter { $Path -eq $PolicyTs }
            Mock Get-RegistryValue { 'Professional' } -ParameterFilter { $Path -eq $CurrentVersion -and $Name -eq 'EditionID' }
            Mock Set-RegistryDword { }
            Mock Set-FirewallRuleScope { }
            Mock Get-RdpMdmFirewallRule { }
            Mock Get-RdpLocalFirewallRuleState { [pscustomobject]@{ Enabled = 'True'; Profile = 'Private'; RemoteAddress = @('Any') } }
        }

        It 'changes neither the registry nor the firewall when policy and an MDM 3389 rule are in place, because Intune owns those settings' {
            Mock Get-RegistryValue { 0 } -ParameterFilter { $Path -eq $PolicyTs -and $Name -eq 'fDenyTSConnections' }
            Mock Get-RegistryValue { 1 } -ParameterFilter { $Path -eq $PolicyTs -and $Name -eq 'UserAuthentication' }
            Mock Get-RdpMdmFirewallRule { [pscustomobject]@{ DisplayName = 'Intune RDP' } }

            Enable-RdpHost

            Should -Invoke Set-RegistryDword -Times 0 -Exactly
            Should -Invoke Set-FirewallRuleScope -Times 0 -Exactly
            $script:RdpChanges.Count | Should -Be 0
        }

        It 'turns RDP and NLA on and opens both UserMode rules to the local subnet on every profile when there is no policy, and reports each change, because a personal PC has RDP off, may have NLA off, and has Private-only rules' {
            Mock Get-RegistryValue { 1 } -ParameterFilter { $Path -eq $LocalTs -and $Name -eq 'fDenyTSConnections' }
            Mock Get-RegistryValue { 0 } -ParameterFilter { $Path -eq $LocalRdpTcp -and $Name -eq 'UserAuthentication' }

            Enable-RdpHost

            Should -Invoke Set-RegistryDword -Times 2 -Exactly
            Should -Invoke Set-RegistryDword -Times 1 -Exactly -ParameterFilter { $Path -eq $LocalTs -and $Name -eq 'fDenyTSConnections' -and $Value -eq 0 }
            Should -Invoke Set-RegistryDword -Times 1 -Exactly -ParameterFilter { $Path -eq $LocalRdpTcp -and $Name -eq 'UserAuthentication' -and $Value -eq 1 }
            foreach ($rule in 'RemoteDesktop-UserMode-In-TCP', 'RemoteDesktop-UserMode-In-UDP') {
                Should -Invoke Set-FirewallRuleScope -Times 1 -Exactly -ParameterFilter { $Name -eq $rule -and $Update.Profile -eq 'Any' -and $Update.RemoteAddress -eq 'LocalSubnet' }
            }
            Should -Invoke Set-FirewallRuleScope -Times 2 -Exactly
            @($script:RdpChanges) | Should -BeExactly @(
                'turned Remote Desktop on'
                'turned on NLA for RDP-Tcp'
                'updated firewall rule RemoteDesktop-UserMode-In-TCP: Profile, RemoteAddress'
                'updated firewall rule RemoteDesktop-UserMode-In-UDP: Profile, RemoteAddress'
            )
        }

        It 'throws the NLA policy message and changes neither the registry nor the firewall when only NLA is refused by policy, because a refused run must leave the PC unchanged' {
            Mock Get-RegistryValue { 0 } -ParameterFilter { $Path -eq $PolicyTs -and $Name -eq 'UserAuthentication' }
            Mock Get-RegistryValue { 1 } -ParameterFilter { $Path -eq $LocalTs -and $Name -eq 'fDenyTSConnections' }

            { Enable-RdpHost } | Should -Throw -ExpectedMessage 'Policy sets UserAuthentication=0, so NLA is off by policy; refusing to open RDP without NLA.'
            Should -Invoke Set-RegistryDword -Times 0 -Exactly
            Should -Invoke Set-FirewallRuleScope -Times 0 -Exactly
        }

        It 'throws when the built-in UDP rule is missing and changes no registry value, because a refused run must leave the PC unchanged' {
            Mock Get-RegistryValue { 1 } -ParameterFilter { $Path -eq $LocalTs -and $Name -eq 'fDenyTSConnections' }
            Mock Get-RegistryValue { 0 } -ParameterFilter { $Path -eq $LocalRdpTcp -and $Name -eq 'UserAuthentication' }
            Mock Get-RdpLocalFirewallRuleState { $null } -ParameterFilter { $Name -eq 'RemoteDesktop-UserMode-In-UDP' }

            { Enable-RdpHost } | Should -Throw -ExpectedMessage 'Built-in firewall rule RemoteDesktop-UserMode-In-UDP not found.'
            Should -Invoke Set-RegistryDword -Times 0 -Exactly
        }

        It 'throws on a Home edition before any change, because Home has no RDP host and the operator must learn that SSH is still usable' {
            Mock Get-RegistryValue { 'Core' } -ParameterFilter { $Path -eq $CurrentVersion -and $Name -eq 'EditionID' }

            { Enable-RdpHost } | Should -Throw '*edition Core cannot host Remote Desktop*SSH is already set up*'
            Should -Invoke Set-RegistryDword -Times 0 -Exactly
            Should -Invoke Set-FirewallRuleScope -Times 0 -Exactly
        }
    }

    Context 'Mac connection file' {
        BeforeAll {
            # Placeholder values; the sms-* fixtures encode these. The encoder was verified on the
            # phone with a real PC's values of the same lengths.
            $HostName = 'EXAMPLPC'
            $IpAddress = '10.200.30.144'
            $DeviceId = '00000000-1111-2222-3333-444444444444'
        }

        It 'writes the hostname file lines, because Windows App needs enablerdsaadauth for Entra sign-in and screen mode 1 opens a window' {
            Get-RdpFileLine -Variant 'hostname' -HostName $HostName | Should -Be @(
                'full address:s:EXAMPLPC'
                'enablerdsaadauth:i:1'
                'screen mode id:i:1'
            )
        }

        It 'writes the ip-name file lines, because Entra sign-in to an IP needs server identity and its type' {
            Get-RdpFileLine -Variant 'ip-name' -HostName $HostName -IpAddress $IpAddress | Should -Be @(
                'full address:s:10.200.30.144'
                'enablerdsaadauth:i:1'
                'server identity:s:EXAMPLPC'
                'server identity type:s:Entra ID Device Name'
                'screen mode id:i:1'
            )
        }

        It 'writes the ip-deviceid file lines, because the device ID identifies the PC even if its name changes' {
            Get-RdpFileLine -Variant 'ip-deviceid' -HostName $HostName -IpAddress $IpAddress -DeviceId $DeviceId | Should -Be @(
                'full address:s:10.200.30.144'
                'enablerdsaadauth:i:1'
                'server identity:s:00000000-1111-2222-3333-444444444444'
                'server identity type:s:Entra ID Device ID'
                'screen mode id:i:1'
            )
        }

        It 'throws when an IP variant lacks its IP or device ID, because a file with an empty address or identity fails only later in Windows App' {
            { Get-RdpFileLine -Variant 'ip-name' -HostName $HostName } | Should -Throw '*-IpAddress*'
            { Get-RdpFileLine -Variant 'ip-deviceid' -HostName $HostName -DeviceId $DeviceId } | Should -Throw '*-IpAddress*'
            { Get-RdpFileLine -Variant 'ip-deviceid' -HostName $HostName -IpAddress $IpAddress } | Should -Throw '*-DeviceId*'
        }

        It 'builds a printf command that overwrites the Desktop file, because the Mac shell is zsh with noclobber' {
            $line = Get-RdpFileLine -Variant 'hostname' -HostName $HostName

            Get-MacRdpCommand -HostName $HostName -Variant 'hostname' -Line $line |
                Should -BeExactly "printf 'full address:s:EXAMPLPC\nenablerdsaadauth:i:1\nscreen mode id:i:1\n' >| ~/Desktop/EXAMPLPC-hostname.rdp"
        }

        It 'escapes backslash, percent, and single quote, because they would otherwise change the printf output or end the shell quote' {
            Get-MacRdpCommand -HostName 'h' -Variant 'v' -Line @('a\b', '50%', "it's") |
                Should -BeExactly "printf 'a\\b\n50%%\nit'\''s\n' >| ~/Desktop/h-v.rdp"
        }

        It 'builds the sms URI for <Variant> exactly as the fixture, because the fixture is the segno-generated reference for the encoder, which was verified on the iPhone and Mac with a real PC''s values of the same lengths' -ForEach @(
            @{ Variant = 'hostname' }
            @{ Variant = 'ip-name' }
            @{ Variant = 'ip-deviceid' }
        ) {
            $expected = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures' 'qr' "sms-$Variant.input"), [Text.UTF8Encoding]::new($false))
            $line = Get-RdpFileLine -Variant $Variant -HostName $HostName -IpAddress $IpAddress -DeviceId $DeviceId
            $command = Get-MacRdpCommand -HostName $HostName -Variant $Variant -Line $line
            $message = Get-MacRdpMessage -HostName $HostName -Variant $Variant -Command $command

            Get-SmsUri -Body $message | Should -BeExactly $expected
        }

        It 'writes the local ip file lines with the user name and no enablerdsaadauth, because NLA with a password needs the local principal and enablerdsaadauth forces Entra sign-in' {
            Get-RdpFileLine -Variant 'ip' -HostName $HostName -IpAddress $IpAddress -UserName 'EXAMPLPC\alice' | Should -Be @(
                'full address:s:10.200.30.144'
                'username:s:EXAMPLPC\alice'
                'screen mode id:i:1'
            )
        }

        It 'throws for an Entra-only variant with -UserName and for ip without it, because a server identity or a missing user name breaks password sign-in only later in Windows App' {
            { Get-RdpFileLine -Variant 'ip-deviceid' -HostName $HostName -IpAddress $IpAddress -DeviceId $DeviceId -UserName 'EXAMPLPC\alice' } | Should -Throw '*for Entra accounts only*'
            { Get-RdpFileLine -Variant 'ip' -HostName $HostName -IpAddress $IpAddress } | Should -Throw '*needs -UserName*'
        }

        It 'escapes the backslash in the local user name, because printf must write a single backslash into the .rdp file' {
            $line = Get-RdpFileLine -Variant 'ip' -HostName $HostName -IpAddress $IpAddress -UserName 'EXAMPLPC\alice'

            Get-MacRdpCommand -HostName $HostName -Variant 'ip' -Line $line |
                Should -BeExactly "printf 'full address:s:10.200.30.144\nusername:s:EXAMPLPC\\alice\nscreen mode id:i:1\n' >| ~/Desktop/EXAMPLPC-ip.rdp"
        }

        It 'reads the device ID from dsregcmd /status, because the ip-deviceid file needs it' {
            $output = @(
                '+----------------------------------------------------------------------+'
                '| Device State                                                         |'
                ''
                '             AzureAdJoined : YES'
                '                  DeviceId : 00000000-1111-2222-3333-444444444444'
                '                Thumbprint : 0123456789ABCDEF0123456789ABCDEF01234567'
            )

            Get-DeviceIdFromDsregcmd -Line $output | Should -Be '00000000-1111-2222-3333-444444444444'
        }

        It 'throws when dsregcmd shows no DeviceId, because an empty server identity would fail only later in Windows App' {
            { Get-DeviceIdFromDsregcmd -Line @('             AzureAdJoined : NO', '') } | Should -Throw '*DeviceId*'
        }
    }

    Context 'Read-RdpVariant' {
        It 'trims the answer and asks again after an invalid one, because a stray space or typo must not pick the wrong file' {
            $script:Answers = [Collections.Generic.Queue[string]]::new([string[]]@('x', ' 2 '))
            Mock Read-Host { $script:Answers.Dequeue() }

            Read-RdpVariant | Should -Be 'ip-name'
            Should -Invoke Read-Host -Times 2 -Exactly
        }

        It 'returns hostname for an empty answer, because the prompt offers 1 as the default for Enter' {
            Mock Read-Host { '' }

            Read-RdpVariant | Should -Be 'hostname'
        }

        It 'returns ip-deviceid for 3, because that is the number the prompt shows for IP by device ID' {
            Mock Read-Host { '3' }

            Read-RdpVariant | Should -Be 'ip-deviceid'
        }

        It 'returns ip for an empty answer with -AccountType Local, because the prompt offers IP as the default for password accounts' {
            Mock Read-Host { '' }

            Read-RdpVariant -AccountType 'Local' | Should -Be 'ip'
        }
    }

    Context 'Get-LanIPv4' {
        BeforeAll {
            # The NetTCPIP cmdlets exist only on Windows; Mock needs a command to replace.
            if (-not (Get-Command Get-NetRoute -ErrorAction SilentlyContinue)) {
                function Get-NetRoute { [CmdletBinding()] param($AddressFamily, $DestinationPrefix) }
            }
            if (-not (Get-Command Get-NetIPInterface -ErrorAction SilentlyContinue)) {
                function Get-NetIPInterface { [CmdletBinding()] param($InterfaceIndex, $AddressFamily) }
            }
            if (-not (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue)) {
                function Get-NetIPAddress { [CmdletBinding()] param($InterfaceIndex, $AddressFamily) }
            }
        }

        BeforeEach {
            # Interface 1 has the lower route metric, interface 2 the lower sum of route and interface metric.
            Mock Get-NetRoute { @([pscustomobject]@{ InterfaceIndex = 1; RouteMetric = 0 }, [pscustomobject]@{ InterfaceIndex = 2; RouteMetric = 10 }) }
            Mock Get-NetIPInterface { [pscustomobject]@{ InterfaceMetric = 50 } } -ParameterFilter { $InterfaceIndex -eq 1 }
            Mock Get-NetIPInterface { [pscustomobject]@{ InterfaceMetric = 5 } } -ParameterFilter { $InterfaceIndex -eq 2 }
            Mock Get-NetIPAddress { [pscustomobject]@{ IPAddress = '10.0.0.5' } } -ParameterFilter { $InterfaceIndex -eq 1 }
        }

        It 'picks the address on the default route with the lowest route plus interface metric, because Windows sends traffic that way' {
            Mock Get-NetIPAddress { [pscustomobject]@{ IPAddress = '192.168.1.50' } } -ParameterFilter { $InterfaceIndex -eq 2 }

            Get-LanIPv4 | Should -Be '192.168.1.50'
        }

        It 'ignores a 169.254.* address on the winning interface, because a link-local address is not reachable from the Mac' {
            Mock Get-NetIPAddress { [pscustomobject]@{ IPAddress = '169.254.10.20' } } -ParameterFilter { $InterfaceIndex -eq 2 }

            Get-LanIPv4 | Should -Be '10.0.0.5'
        }

        It 'throws when there is no default route, because an ip-* file needs an address the Mac can reach' {
            Mock Get-NetRoute { }

            { Get-LanIPv4 } | Should -Throw '*default route*'
        }
    }

    Context 'Show-MacRdpSetup at the console' {
        BeforeEach {
            $script:SavedSshConnection = $env:SSH_CONNECTION
            $script:SavedQrLoadError = $script:QrLoadError
            $env:SSH_CONNECTION = $null
            $script:Calls = [Collections.Generic.List[string]]::new()
            $script:QrRows = $null
            $script:MacCommand = $null
            Mock Read-RdpVariant { 'hostname' }
            Mock Get-PcHostName { 'EXAMPLPC' }
            Mock Get-ConsoleWindowSize { [pscustomobject]@{ Width = 500; Height = 500 } }
            Mock Get-LanIPv4 { throw 'Get-LanIPv4 must not run for the hostname file' }
            Mock Get-EntraDeviceId { throw 'Get-EntraDeviceId must not run for the hostname file' }
            Mock Write-Step { }
            Mock Write-Warning { }
            Mock Write-MacCommand { $script:Calls.Add('Write-MacCommand'); $script:MacCommand = $Command }
            Mock Write-QrCode { $script:Calls.Add('Write-QrCode'); $script:QrRows = $Rows }
        }

        AfterEach {
            $env:SSH_CONNECTION = $script:SavedSshConnection
            $script:QrLoadError = $script:SavedQrLoadError
        }

        It 'draws the hostname QR code from the segno-generated reference fixture last, after the command, without looking up the IP or device ID, because the hostname file needs neither and the code must stay on screen' {
            $uri = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures' 'qr' 'sms-hostname.input'), [Text.UTF8Encoding]::new($false))
            $expectedRows = (New-QrMatrix -Text $uri).Rows
            $line = Get-RdpFileLine -Variant 'hostname' -HostName 'EXAMPLPC'

            Show-MacRdpSetup

            Should -Invoke Get-LanIPv4 -Times 0 -Exactly
            Should -Invoke Get-EntraDeviceId -Times 0 -Exactly
            ($script:QrRows -join "`n") | Should -BeExactly ($expectedRows -join "`n")
            $script:MacCommand | Should -BeExactly (Get-MacRdpCommand -HostName 'EXAMPLPC' -Variant 'hostname' -Line $line)
            @($script:Calls) | Should -Be @('Write-MacCommand', 'Write-QrCode')
        }

        It 'warns to maximize a 120x30 window, because the hostname QR code needs 69 columns by 36 rows and a cut-off code does not scan' {
            Mock Get-ConsoleWindowSize { [pscustomobject]@{ Width = 120; Height = 30 } }

            Show-MacRdpSetup

            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*maximize*' }
        }

        It 'does not warn in a large window, because a needless warning teaches people to ignore it' {
            Show-MacRdpSetup

            Should -Invoke Write-Warning -Times 0 -Exactly -ParameterFilter { $Message -like '*maximize*' }
        }

        It 'throws before prompting when rdp-qr.ps1 failed to load, because Invoke-Main turns that into a warning and the user must not answer a prompt for nothing' {
            $script:QrLoadError = 'The term rdp-qr.ps1 is not recognized'

            { Show-MacRdpSetup } | Should -Throw '*rdp-qr.ps1 could not be loaded*'
            Should -Invoke Read-RdpVariant -Times 0 -Exactly
        }
    }

    Context 'Show-MacRdpSetup over SSH' {
        BeforeAll {
            function Get-ExpectedCommand {
                param([Parameter(Mandatory)][string]$Variant)
                $line = Get-RdpFileLine -Variant $Variant -HostName 'EXAMPLPC' -IpAddress '10.200.30.144' -DeviceId '00000000-1111-2222-3333-444444444444'
                return Get-MacRdpCommand -HostName 'EXAMPLPC' -Variant $Variant -Line $line
            }
        }

        BeforeEach {
            $script:SavedSshConnection = $env:SSH_CONNECTION
            $env:SSH_CONNECTION = '10.0.0.1 50000 10.0.0.2 22'
            $script:Steps = [Collections.Generic.List[string]]::new()
            Mock Get-PcHostName { 'EXAMPLPC' }
            Mock Write-Step { $script:Steps.Add($Message) }
            Mock Write-MacCommand { $script:Steps.Add($Command) }
            Mock Write-Warning { }
            Mock Get-LanIPv4 { '10.200.30.144' }
            Mock Get-EntraDeviceId { '00000000-1111-2222-3333-444444444444' }
            Mock Read-RdpVariant { throw 'Read-RdpVariant must not run over SSH' }
            Mock Write-QrCode { }
        }

        AfterEach {
            $env:SSH_CONNECTION = $script:SavedSshConnection
        }

        It 'still prints the hostname and ip-name commands when the device ID lookup fails, because those files do not need the device ID' {
            Mock Get-EntraDeviceId { throw 'No DeviceId line found' }

            Show-MacRdpSetup

            @($script:Steps | Where-Object { $_ -like 'printf *' }) | Should -Be @((Get-ExpectedCommand -Variant 'hostname'), (Get-ExpectedCommand -Variant 'ip-name'))
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*Skipped ip-deviceid*No DeviceId line found*' }
        }

        It 'still prints the hostname command when the IP lookup fails, because only the ip-* files need the IP' {
            Mock Get-LanIPv4 { throw 'No IPv4 address found' }

            Show-MacRdpSetup

            @($script:Steps | Where-Object { $_ -like 'printf *' }) | Should -Be @((Get-ExpectedCommand -Variant 'hostname'))
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*Skipped ip-name*No IPv4 address found*' }
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*Skipped ip-deviceid*No IPv4 address found*' }
        }

        It 'prints all three commands without prompting or drawing a QR code, because a non-interactive SSH run has no one to answer or scan' {
            Show-MacRdpSetup

            Should -Invoke Read-RdpVariant -Times 0 -Exactly
            Should -Invoke Write-QrCode -Times 0 -Exactly
            $expected = foreach ($variant in 'hostname', 'ip-name', 'ip-deviceid') {
                $line = Get-RdpFileLine -Variant $variant -HostName 'EXAMPLPC' -IpAddress '10.200.30.144' -DeviceId '00000000-1111-2222-3333-444444444444'
                Get-MacRdpCommand -HostName 'EXAMPLPC' -Variant $variant -Line $line
            }
            @($script:Steps | Where-Object { $_ -like 'printf *' }) | Should -Be @($expected)
            Should -Invoke Write-Step -Times 0 -Exactly -ParameterFilter { $Message -like '*printf *' }
        }

        It 'prints the ip and hostname commands with -UserName and never looks up the Entra device ID, because a local or Microsoft account PC may not be Entra joined' {
            Mock Get-EntraDeviceId { throw 'Get-EntraDeviceId must not run for a password account' }

            Show-MacRdpSetup -UserName 'EXAMPLPC\alice'

            Should -Invoke Get-EntraDeviceId -Times 0 -Exactly
            $expected = foreach ($variant in 'ip', 'hostname') {
                $line = Get-RdpFileLine -Variant $variant -HostName 'EXAMPLPC' -IpAddress '10.200.30.144' -UserName 'EXAMPLPC\alice'
                Get-MacRdpCommand -HostName 'EXAMPLPC' -Variant $variant -Line $line
            }
            @($script:Steps | Where-Object { $_ -like 'printf *' }) | Should -Be @($expected)
        }
    }

    Context 'Invoke-Main when the Mac connection file cannot be prepared' {
        It 'warns and does not fail, because the group memberships are already in place and the connection file is only a convenience' {
            Mock Test-IsAdmin { $true }
            $script:Principal = 'AzureAD\user@example.com'
            $script:AccountType = 'Entra'
            $script:RdpUserName = ''
            Mock Enable-RdpHost { }
            Mock Get-UserSid { 'S-1-12-1-1000000001-1000000002-1000000003-1000000004' }
            Mock Add-UserToGroup { }
            Mock Write-Step { }
            Mock Show-MacRdpSetup { throw 'No DeviceId line found' }
            Mock Write-Warning { }

            { Invoke-Main } | Should -Not -Throw
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*No DeviceId line found*' }
        }
    }
}
