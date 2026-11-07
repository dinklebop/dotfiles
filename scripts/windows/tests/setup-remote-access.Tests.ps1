Describe 'setup-remote-access.ps1' {
    BeforeAll {
        # The script builds its constants from Windows env vars at load time. They are
        # absent in the Linux test container, so give them placeholder values.
        if (-not $env:ProgramData) { $env:ProgramData = '/ProgramData' }
        $SavedComputerName = $env:COMPUTERNAME
        $env:COMPUTERNAME = 'EXAMPLPC'

        . (Join-Path $PSScriptRoot '..' 'setup-remote-access.ps1')

        # Dot-sourcing puts the parameters in this scope. Remove them so the tests set them in
        # script scope, where they live on a real run.
        Remove-Variable -Name Reselect, PublicKey

        # Spelled out here (not read from the script) so a changed value fails the tests.
        $Base = 'S-1-5-21-1000000000-2000000000-3000000000'
        $EntraSid = 'S-1-12-1-1000000001-1000000002-1000000003-1000000004'
        $EntraNoUpnSid = 'S-1-12-1-2000000001-2000000002-2000000003-2000000004'
        $EntraBadUpnSid = 'S-1-12-1-3000000001-3000000002-3000000003-3000000004'
        $AliceSid = "$Base-1001"
        $MsaSid = "$Base-1002"
        $MsaNoEmailSid = "$Base-1003"
        $DefaultUserSid = "$Base-1004"
        $SshSid = "$Base-1005"
        $AdminSid = "$Base-500"
        $SpecialSid = "$Base-1006"
        $OrphanSid = "$Base-1007"
        $MsaWarning = '(Microsoft account: RDP needs the account password, not a PIN or Windows Hello)'

        function New-TestProfile {
            param([string]$Sid, [string]$Name, [bool]$Special = $false)
            [pscustomobject]@{ Sid = $Sid; LocalPath = "C:\Users\$Name"; Special = $Special }
        }
        function New-TestUser {
            param([string]$Sid, [string]$Name, [bool]$Enabled = $true, [string]$Source = 'Local')
            [pscustomobject]@{ Name = $Name; Sid = $Sid; Enabled = $Enabled; PrincipalSource = $Source }
        }

        $TestProfiles = @(
            New-TestProfile 'S-1-5-18' 'systemprofile' $true
            New-TestProfile $EntraSid 'JaneDoe'
            New-TestProfile $EntraNoUpnSid 'nocache'
            New-TestProfile $EntraBadUpnSid 'badcache'
            New-TestProfile $AliceSid 'alice'
            New-TestProfile $MsaSid 'dsmith'
            New-TestProfile $MsaNoEmailSid 'erin'
            New-TestProfile $DefaultUserSid 'defaultuser0'
            New-TestProfile $SshSid 'ssh-x'
            New-TestProfile $AdminSid 'Administrator'
            # bob is an enabled local user, so only the Special flag can exclude this profile.
            New-TestProfile $SpecialSid 'bob' $true
            # A domain or deleted account: a profile with no local user.
            New-TestProfile $OrphanSid 'gone'
        )
        $TestUsers = @(
            New-TestUser $AdminSid 'Administrator'
            New-TestUser $AliceSid 'alice'
            New-TestUser $MsaSid 'dsmith' -Source 'MicrosoftAccount'
            New-TestUser $MsaNoEmailSid 'erin' -Source 'MicrosoftAccount'
            New-TestUser $DefaultUserSid 'defaultuser0' -Enabled $false
            New-TestUser $SshSid 'ssh-x'
            New-TestUser $SpecialSid 'bob'
        )
        $TestIdentityNames = @{
            $EntraSid       = 'Jane.Doe@example.com'
            $EntraBadUpnSid = 'janedoe'
            $MsaSid         = 'Dave.Smith@example.com'
        }

        function Get-TestCandidate {
            Get-RemoteAccessCandidate -Profiles $TestProfiles -LocalUsers $TestUsers -IdentityNames $TestIdentityNames -ComputerName 'EXAMPLPC'
        }

        function New-TestSelection {
            param([string]$Sid, [string]$SshUserName)
            [pscustomobject]@{ Sid = $Sid; AccountType = 'Local'; DisplayName = 'alice (local)'; Principal = 'EXAMPLPC\alice'; RdpUserName = 'EXAMPLPC\alice'; SshUserName = $SshUserName }
        }
    }

    AfterAll {
        $env:COMPUTERNAME = $SavedComputerName
    }

    Context 'Get-RemoteAccessCandidate' {
        BeforeEach {
            Mock Write-Warning { }
        }

        It 'uses the IdentityStore UPN after AzureAD\ and ssh- plus the UPN prefix for an Entra profile, because Translate() gives AD\name, which RDP cannot use' {
            $c = @(Get-TestCandidate | Where-Object { $_.Sid -eq $EntraSid })

            $c.Count | Should -Be 1
            $c[0].AccountType | Should -BeExactly 'Entra'
            $c[0].Principal | Should -BeExactly 'AzureAD\Jane.Doe@example.com'
            $c[0].DisplayName | Should -BeExactly 'Jane.Doe@example.com (Entra)'
            $c[0].RdpUserName | Should -BeNullOrEmpty
            $c[0].SshUserName | Should -BeExactly 'ssh-jane.doe'
            $c[0].NeedsEmail | Should -BeFalse
        }

        It 'skips an Entra profile with no cached UPN, or one without @, with a warning, because guessing a UPN would grant RDP to the wrong identity' {
            $sids = @(Get-TestCandidate | ForEach-Object { $_.Sid })

            $sids | Should -Not -Contain $EntraNoUpnSid
            $sids | Should -Not -Contain $EntraBadUpnSid
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'Skipping Entra profile C:\Users\nocache: no cached UPN.' }
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'Skipping Entra profile C:\Users\badcache: no cached UPN.' }
        }

        It 'excludes defaultuser0 (disabled), ssh-x, RID 500, special profiles, and SIDs with no local user, because only a real person''s account may get SSH and admin RDP, and an ssh-* account must not get its own ssh-ssh-* account (D13)' {
            $sids = @(Get-TestCandidate | ForEach-Object { $_.Sid } | Sort-Object)

            $sids | Should -Be @(@($EntraSid, $AliceSid, $MsaSid, $MsaNoEmailSid) | Sort-Object)
        }

        It 'uses COMPUTER\name as the principal and RDP user name of a local account, because a local account signs in to RDP with COMPUTER\name' {
            $c = @(Get-TestCandidate | Where-Object { $_.Sid -eq $AliceSid })

            $c[0].AccountType | Should -BeExactly 'Local'
            $c[0].Principal | Should -BeExactly 'EXAMPLPC\alice'
            $c[0].RdpUserName | Should -BeExactly 'EXAMPLPC\alice'
            $c[0].DisplayName | Should -BeExactly 'alice (local)'
            $c[0].SshUserName | Should -BeExactly 'ssh-alice'
        }

        It 'gives a Microsoft account MicrosoftAccount\ plus the email as RdpUserName, an SSH name from the email prefix, and the password warning, because the local name is not the sign-in name and RDP rejects a PIN (D20, D25)' {
            $c = @(Get-TestCandidate | Where-Object { $_.Sid -eq $MsaSid })

            $c[0].AccountType | Should -BeExactly 'MicrosoftAccount'
            $c[0].Principal | Should -BeExactly 'EXAMPLPC\dsmith'
            $c[0].RdpUserName | Should -BeExactly 'MicrosoftAccount\Dave.Smith@example.com'
            $c[0].SshUserName | Should -BeExactly 'ssh-dave.smith'
            $c[0].DisplayName | Should -BeExactly "Dave.Smith@example.com $MsaWarning"
            $c[0].NeedsEmail | Should -BeFalse
        }

        It 'marks a Microsoft account with no cached email as NeedsEmail with no RDP user name, because a guessed sign-in name would fail only later in Windows App' {
            $c = @(Get-TestCandidate | Where-Object { $_.Sid -eq $MsaNoEmailSid })

            $c[0].NeedsEmail | Should -BeTrue
            $c[0].RdpUserName | Should -BeNullOrEmpty
            $c[0].DisplayName | Should -BeExactly "erin $MsaWarning"
        }

        It 'excludes a non-special profile whose SID is neither Entra nor local, because only Entra and local or Microsoft accounts can get SSH and RDP' {
            $serviceSid = 'S-1-5-80-1000000000-2000000000-3000000000-4000000000'
            # A matching local user, so only the SID class can exclude the profile.
            $c = @(Get-RemoteAccessCandidate -Profiles @(New-TestProfile $serviceSid 'svc') -LocalUsers @(New-TestUser $serviceSid 'svc') -IdentityNames @{} -ComputerName 'EXAMPLPC')

            $c.Count | Should -Be 0
        }
    }

    Context 'Test-SshUserName' {
        It 'returns <Expected> for <Name>, because Windows caps account names at 20 characters and SSH user names cannot contain spaces' -ForEach @(
            @{ Name = 'ssh-user'; Expected = $true }
            @{ Name = 'ssh-aaaaaaaaaaaaaaaa'; Expected = $true }
            @{ Name = 'ssh-aaaaaaaaaaaaaaaaa'; Expected = $false }
            @{ Name = 'ssh-jane doe'; Expected = $false }
            @{ Name = 'ssh-jane@example.com'; Expected = $false }
            @{ Name = 'jane'; Expected = $false }
        ) {
            Test-SshUserName -Name $Name | Should -Be $Expected
        }
    }

    Context 'Resolve-RemoteAccessSelection' {
        BeforeAll {
            function Get-ChoiceNumber {
                param([string]$Sid)
                $sids = @(Get-TestCandidate 3>$null | ForEach-Object { $_.Sid })
                return [string]([array]::IndexOf($sids, $Sid) + 1)
            }
        }

        BeforeEach {
            $script:Reselect = $false
            $script:Written = $null
            $script:Steps = [Collections.Generic.List[string]]::new()
            Mock Get-ProfileRecord { $TestProfiles }
            Mock Get-LocalUserRecord { $TestUsers }
            Mock Get-IdentityName { $TestIdentityNames[$Sid] }
            Mock Read-Selection { $null }
            Mock Write-Selection { $script:Written = $Selection }
            Mock Write-Step { $script:Steps.Add($Message) }
            Mock Write-Warning { }
            Mock Write-Host { }
            # Answers are dequeued in order; an extra prompt throws, so a logic error fails the
            # test instead of looping forever on a prompt that never gets a valid answer.
            $script:Answers = [Collections.Generic.Queue[string]]::new()
            Mock Read-Host { if ($script:Answers.Count -eq 0) { throw "Unexpected prompt: $Prompt" }; $script:Answers.Dequeue() }
        }

        It 'does not prompt and keeps the saved selection when it is valid and -Reselect is not given, because re-runs from chezmoi apply must not prompt (D14)' {
            Mock Read-Selection { New-TestSelection -Sid $AliceSid -SshUserName 'ssh-alice' }
            Mock Read-Host { throw 'Read-Host must not run with a valid saved selection' }

            $sel = Resolve-RemoteAccessSelection

            Should -Invoke Read-Host -Times 0 -Exactly
            Should -Invoke Write-Selection -Times 0 -Exactly
            $sel.Sid | Should -BeExactly $AliceSid
            $sel.SshUserName | Should -BeExactly 'ssh-alice'
            $script:Steps | Should -Contain 'Using saved selection alice (local) -> ssh-alice (re-run with -Reselect to change).'
        }

        It 'prompts with -Reselect, writes the new selection, and prints the old ssh- account with Remove-LocalUser, because the old account is left in place (D14)' {
            $script:Reselect = $true
            Mock Read-Selection { New-TestSelection -Sid $AliceSid -SshUserName 'ssh-alice' }
            $script:Answers.Enqueue((Get-ChoiceNumber -Sid $MsaSid))

            $sel = Resolve-RemoteAccessSelection

            Should -Invoke Read-Host -Times 1 -Exactly
            Should -Invoke Write-Selection -Times 1 -Exactly
            @($script:Written.PSObject.Properties | ForEach-Object { $_.Name }) | Should -Be @('Sid', 'AccountType', 'DisplayName', 'Principal', 'RdpUserName', 'SshUserName')
            $script:Written.Sid | Should -BeExactly $MsaSid
            $script:Written.AccountType | Should -BeExactly 'MicrosoftAccount'
            $script:Written.RdpUserName | Should -BeExactly 'MicrosoftAccount\Dave.Smith@example.com'
            $script:Written.SshUserName | Should -BeExactly 'ssh-dave.smith'
            $sel.Sid | Should -BeExactly $MsaSid
            $script:Steps | Should -Contain 'The previous SSH account ssh-alice was left in place. Remove it with: Remove-LocalUser -Name ssh-alice'
            Should -Invoke Write-Warning -Times 0 -Exactly -ParameterFilter { $Message -like 'Saved selection*' }
        }

        It 'warns and prompts when the saved SID is no longer a candidate, because the saved profile was deleted and its access must not be re-applied' {
            Mock Read-Selection { New-TestSelection -Sid "$Base-9999" -SshUserName 'ssh-alice' }
            $script:Answers.Enqueue((Get-ChoiceNumber -Sid $AliceSid))

            Resolve-RemoteAccessSelection | Out-Null

            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'Saved selection no longer matches a profile on this PC; choose again.' }
            Should -Invoke Read-Host -Times 1 -Exactly
            $script:Written.Sid | Should -BeExactly $AliceSid
            $script:Steps | Should -Not -Contain 'The previous SSH account ssh-alice was left in place. Remove it with: Remove-LocalUser -Name ssh-alice'
        }

        It 'prompts once for the email of a Microsoft account without one and derives the RDP and SSH names from it, because the local name is not the sign-in name' {
            $script:Answers.Enqueue((Get-ChoiceNumber -Sid $MsaNoEmailSid))
            $script:Answers.Enqueue('Erin.M@example.com')

            Resolve-RemoteAccessSelection | Out-Null

            Should -Invoke Read-Host -Times 1 -Exactly -ParameterFilter { $Prompt -like '*email*' }
            Should -Invoke Read-Host -Times 2 -Exactly
            $script:Written.RdpUserName | Should -BeExactly 'MicrosoftAccount\Erin.M@example.com'
            $script:Written.SshUserName | Should -BeExactly 'ssh-erin.m'
        }

        It 'asks for the SSH name when the suggested one is too long, and asks again after an invalid answer, because Windows caps account names at 20 characters and an invalid name must not be used' {
            Mock Get-ProfileRecord { @(New-TestProfile "$Base-1010" 'averyveryverylongname') }
            Mock Get-LocalUserRecord { @(New-TestUser "$Base-1010" 'averyveryverylongname') }
            $script:Answers.Enqueue('1')
            $script:Answers.Enqueue('ssh-has space')
            $script:Answers.Enqueue('ssh-short')

            Resolve-RemoteAccessSelection | Out-Null

            Should -Invoke Read-Host -Times 2 -Exactly -ParameterFilter { $Prompt -like 'SSH account name*' }
            $script:Written.SshUserName | Should -BeExactly 'ssh-short'
        }

        It 'warns, prompts, and overwrites selection.json when it cannot be read, because a damaged file must be recoverable without deleting it by hand' {
            Mock Read-Selection { throw 'Invalid JSON primitive.' }
            $script:Answers.Enqueue((Get-ChoiceNumber -Sid $AliceSid))

            Resolve-RemoteAccessSelection | Out-Null

            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'Saved selection no longer matches a profile on this PC; choose again.' }
            Should -Invoke Read-Host -Times 1 -Exactly
            Should -Invoke Write-Selection -Times 1 -Exactly
            $script:Written.Sid | Should -BeExactly $AliceSid
            @($script:Steps | Where-Object { $_ -like 'The previous SSH account*' }).Count | Should -Be 0
        }
    }

    Context 'Read-CandidateChoice' {
        BeforeAll {
            $TwoCandidates = @(
                [pscustomobject]@{ Sid = $AliceSid; DisplayName = 'alice (local)' }
                [pscustomobject]@{ Sid = $EntraSid; DisplayName = 'Jane.Doe@example.com (Entra)' }
            )
        }

        BeforeEach {
            Mock Write-Host { }
            $script:Answers = [Collections.Generic.Queue[string]]::new()
            Mock Read-Host { if ($script:Answers.Count -eq 0) { throw "Unexpected prompt: $Prompt" }; $script:Answers.Dequeue() }
        }

        It 'throws without prompting when there are no candidates, because there is nothing to pick and the user must sign in first' {
            { Read-CandidateChoice -Candidates @() } | Should -Throw 'No eligible user profile found. Sign in once as the user you want, then re-run.'
            Should -Invoke Read-Host -Times 0 -Exactly
        }

        It 'asks again after an out-of-range answer and a non-number, because a bad answer must not pick an account' {
            $script:Answers.Enqueue('3')
            $script:Answers.Enqueue('x')
            $script:Answers.Enqueue('2')

            $c = Read-CandidateChoice -Candidates $TwoCandidates

            Should -Invoke Read-Host -Times 3 -Exactly
            $c.Sid | Should -BeExactly $EntraSid
        }

        It 'throws when input is closed, because a chezmoi apply without a console must fail instead of hanging' {
            Mock Read-Host { $null }

            { Read-CandidateChoice -Candidates $TwoCandidates } | Should -Throw 'No input available; run setup-remote-access.ps1 from an interactive elevated console.'
            Should -Invoke Read-Host -Times 1 -Exactly
        }
    }

    Context 'selection.json' {
        It 'writes UTF-8 without a BOM into a new folder and reads the same values back, because the spec requires no BOM and the Entra RdpUserName must stay null' {
            $SelectionPath = Join-Path $TestDrive 'SshUserSetup' 'selection.json'
            $sel = [pscustomobject]@{ Sid = $EntraSid; AccountType = 'Entra'; DisplayName = 'Jane.Doe@example.com (Entra)'; Principal = 'AzureAD\Jane.Doe@example.com'; RdpUserName = $null; SshUserName = 'ssh-jane.doe' }

            Write-Selection -Selection $sel
            $back = Read-Selection

            $bytes = [IO.File]::ReadAllBytes($SelectionPath)
            $bytes[0] | Should -Be ([byte][char]'{')
            $back.Principal | Should -BeExactly 'AzureAD\Jane.Doe@example.com'
            $null -eq $back.RdpUserName | Should -BeTrue
            Test-SavedSelection -Selection $back -Candidates @([pscustomobject]@{ Sid = $EntraSid }) | Should -BeTrue
        }
    }

    Context 'Invoke-Main' {
        BeforeEach {
            $script:PublicKey = ''
            $script:Calls = [Collections.Generic.List[object]]::new()
            Mock Test-IsDesktopEdition { $true }
            Mock Test-IsAdmin { $true }
            Mock Resolve-RemoteAccessSelection {
                [pscustomobject]@{ Sid = $MsaSid; AccountType = 'MicrosoftAccount'; DisplayName = 'x'; Principal = 'EXAMPLPC\dsmith'; RdpUserName = 'MicrosoftAccount\Dave.Smith@example.com'; SshUserName = 'ssh-dave.smith' }
            }
            Mock Invoke-RemoteAccessScript { $script:Calls.Add([pscustomobject]@{ Name = $Name; Arguments = $Arguments }) }
        }

        It 'runs setup-ssh-user.ps1 before enable-rdp.ps1 with the selection, because a Home edition fails only the RDP half and SSH must already be set up by then' {
            Invoke-Main

            @($script:Calls | ForEach-Object { $_.Name }) | Should -Be @('setup-ssh-user.ps1', 'enable-rdp.ps1')
            $script:Calls[0].Arguments.UserName | Should -BeExactly 'ssh-dave.smith'
            $script:Calls[1].Arguments.Principal | Should -BeExactly 'EXAMPLPC\dsmith'
            $script:Calls[1].Arguments.AccountType | Should -BeExactly 'MicrosoftAccount'
            $script:Calls[1].Arguments.RdpUserName | Should -BeExactly 'MicrosoftAccount\Dave.Smith@example.com'
        }

        It 'passes PublicKey to setup-ssh-user.ps1 only when it is given, because setup-ssh-user.ps1 reads the YubiKey only when PublicKey is absent' {
            Invoke-Main
            @($script:Calls[0].Arguments.Keys) | Should -Be @('UserName')

            $script:Calls.Clear()
            $script:PublicKey = 'ssh-rsa AAAAtest test-only'
            Invoke-Main
            $script:Calls[0].Arguments.PublicKey | Should -BeExactly 'ssh-rsa AAAAtest test-only'
            $script:Calls[1].Arguments.ContainsKey('PublicKey') | Should -BeFalse
        }

        It 'lets an exception from enable-rdp.ps1 propagate, so chezmoi apply fails and retries on the next run (D15)' {
            Mock Invoke-RemoteAccessScript { if ($Name -eq 'enable-rdp.ps1') { throw 'Windows edition Core cannot host Remote Desktop.' } }

            { Invoke-Main } | Should -Throw '*cannot host Remote Desktop*'
            Should -Invoke Invoke-RemoteAccessScript -Times 1 -Exactly -ParameterFilter { $Name -eq 'setup-ssh-user.ps1' }
        }
    }
}
