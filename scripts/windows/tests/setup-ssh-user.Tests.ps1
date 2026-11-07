Describe 'setup-ssh-user.ps1 pure functions' {
    BeforeAll {
        # The script builds its constants from Windows env vars at load time. They are
        # absent in the Linux test container, so give them placeholder values.
        if (-not $env:ProgramData) { $env:ProgramData = '/ProgramData' }
        if (-not $env:WINDIR) { $env:WINDIR = '/Windows' }

        . (Join-Path $PSScriptRoot '..' 'setup-ssh-user.ps1')

        $Fixture = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'sshd_config_default')

        # Spelled out here (not read from the script) so a changed value fails the tests.
        $Expected = @(
            'PasswordAuthentication no',
            'PubkeyAuthentication yes',
            'AuthenticationMethods publickey',
            'UseDNS no',
            'TCPKeepAlive yes',
            'ClientAliveInterval 60',
            'ClientAliveCountMax 3'
        )
        $AdminBlock = @(
            'Match Group administrators',
            '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'
        )

        function Get-GlobalSection {
            param([string[]]$Lines)
            foreach ($line in $Lines) {
                if ($line -match '^\s*Match\s') { break }
                $line
            }
        }

        # A throwaway key made for these tests; its private half was deleted.
        $PublicKey = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'test_key.pub') -Raw).Trim()
        $KeyType = ($PublicKey -split '\s+')[0]
        $KeyBlob = ($PublicKey -split '\s+')[1]
    }

    Context 'Get-SshdConfigUpdate' {
        It 'puts each required directive in the global section exactly once, because directives after a Match block silently do not apply' {
            $new = Get-SshdConfigUpdate -Lines $Fixture -Directives $SshdDirectives
            $global = @(Get-GlobalSection $new)

            foreach ($line in $Expected) {
                @($global | Where-Object { $_ -ceq $line }).Count | Should -Be 1 -Because "'$line' must be set globally"
                $name = ($line -split ' ')[0]
                @($global | Where-Object { $_ -match "^\s*$name(\s|$)" }).Count | Should -Be 1 -Because "$name must not be duplicated"
            }
        }

        It 'changes only the six commented directives and adds one AuthenticationMethods line on the default config, so unrelated settings are not disturbed' {
            $new = Get-SshdConfigUpdate -Lines $Fixture -Directives $SshdDirectives

            # The default config has no AuthenticationMethods line, so it is inserted, not uncommented.
            @($new | Where-Object { $_ -ceq 'AuthenticationMethods publickey' }).Count | Should -Be 1
            $rest = @($new | Where-Object { $_ -cne 'AuthenticationMethods publickey' })
            $rest.Count | Should -Be $Fixture.Count
            $changed = @(for ($i = 0; $i -lt $Fixture.Count; $i++) { if ($Fixture[$i] -cne $rest[$i]) { $Fixture[$i] } })
            $changed.Count | Should -Be 6
            foreach ($old in $changed) {
                $old | Should -Match '^#(PasswordAuthentication|PubkeyAuthentication|UseDNS|TCPKeepAlive|ClientAliveInterval|ClientAliveCountMax) '
            }
        }

        It 'leaves the Match Group administrators block byte-identical, because admin key lookup depends on it' {
            $new = Get-SshdConfigUpdate -Lines $Fixture -Directives $SshdDirectives

            $oldIdx = [array]::IndexOf([string[]]$Fixture, 'Match Group administrators')
            $newIdx = [array]::IndexOf($new, 'Match Group administrators')
            $oldIdx | Should -BeGreaterThan 0
            ($new[$newIdx..($new.Count - 1)] -join "`n") | Should -BeExactly ($Fixture[$oldIdx..($Fixture.Count - 1)] -join "`n")
        }

        It 'returns identical lines when applied to its own output, so a re-run neither rewrites sshd_config nor restarts sshd' {
            $once = Get-SshdConfigUpdate -Lines $Fixture -Directives $SshdDirectives
            $twice = Get-SshdConfigUpdate -Lines $once -Directives $SshdDirectives

            ($twice -join "`n") | Should -BeExactly ($once -join "`n")
        }

        It 'turns an uncommented PasswordAuthentication yes into no without adding a second line, because password auth must not stay on' {
            $lines = @('Port 22', 'PasswordAuthentication yes', 'Subsystem sftp sftp-server.exe', '') + $AdminBlock
            $global = @(Get-GlobalSection (Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives))

            $pw = @($global | Where-Object { $_ -match '^\s*PasswordAuthentication(\s|$)' })
            $pw.Count | Should -Be 1
            $pw[0] | Should -BeExactly 'PasswordAuthentication no'
        }

        It 'replaces an existing AuthenticationMethods line with publickey only, because PasswordAuthentication no does not turn off keyboard-interactive login' {
            $lines = @('Port 22', 'AuthenticationMethods any', '') + $AdminBlock
            $global = @(Get-GlobalSection (Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives))

            $methods = @($global | Where-Object { $_ -match '^\s*AuthenticationMethods(\s|$)' })
            $methods.Count | Should -Be 1
            $methods[0] | Should -BeExactly 'AuthenticationMethods publickey'
        }

        It 'replaces a lowercase passwordauthentication line instead of duplicating it, because sshd keywords are case-insensitive and the first one wins' {
            $lines = @('Port 22', 'passwordauthentication yes', '') + $AdminBlock
            $new = Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives
            $global = @(Get-GlobalSection $new)

            $new[1] | Should -BeExactly 'PasswordAuthentication no'
            @($global | Where-Object { $_ -match '^\s*passwordauthentication(\s|$)' }).Count | Should -Be 1
        }

        It 'inserts a global line when a directive exists only inside a Match block, because in-block settings do not apply globally' {
            $lines = @('Port 22', '', 'Match User bob', '    UseDNS yes', '') + $AdminBlock
            $new = Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives
            $global = @(Get-GlobalSection $new)

            $global | Should -Contain 'UseDNS no'
            $new | Should -Contain '    UseDNS yes'
            $matchAt = [array]::IndexOf($new, 'Match User bob')
            $new[$matchAt + 1] | Should -BeExactly '    UseDNS yes'
        }

        It 'does not touch the prose comment that mentions passwords, because only real directive lines may be edited' {
            $prose = '# To disable tunneled clear text passwords, change to no here!'
            $new = Get-SshdConfigUpdate -Lines $Fixture -Directives $SshdDirectives

            $idx = [array]::IndexOf([string[]]$Fixture, $prose)
            $idx | Should -BeGreaterThan 0
            $new[$idx] | Should -BeExactly $prose
        }

        It 'appends the directives and the Match Group administrators block when there is no Match block, because admin keys must still be found' {
            $lines = @('Port 22', 'Subsystem sftp sftp-server.exe')
            $new = Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives

            $new[0..1] | Should -Be $lines
            ($new[2..8] -join "`n") | Should -BeExactly ($Expected -join "`n")
            ($new[9..11] -join "`n") | Should -BeExactly ((@('') + $AdminBlock) -join "`n")
            $new.Count | Should -Be 12
        }

        It 'throws on two Match Group administrators blocks, because guessing which one sshd uses could lock admins out' {
            $lines = @('Port 22', '') + $AdminBlock + @('') + $AdminBlock
            { Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives } | Should -Throw '*more than one*'
        }

        It 'throws when the Match Group administrators block lacks the AuthorizedKeysFile line, because admin keys would never be read' {
            $lines = @('Port 22', '', 'Match Group administrators', '       PermitTTY yes')
            { Get-SshdConfigUpdate -Lines $lines -Directives $SshdDirectives } | Should -Throw '*AuthorizedKeysFile*'
        }

        It 'returns a string array for single-line input, because WriteAllLines and the change comparison need an array' {
            $new = Get-SshdConfigUpdate -Lines 'Port 22' -Directives $SshdDirectives

            ($new -is [string[]]) | Should -BeTrue
            $new[0] | Should -BeExactly 'Port 22'
        }
    }

    Context 'Test-AuthorizedKeyPresent' {
        It 'treats the same key with a different comment as present, so re-runs do not duplicate keys' {
            Test-AuthorizedKeyPresent -Lines @("$KeyType $KeyBlob someone@elsewhere") -PublicKey $PublicKey | Should -BeTrue
        }

        It 'treats the same key with an options prefix as present, so hand-added restrictions are not duplicated' {
            Test-AuthorizedKeyPresent -Lines @("from=`"10.0.0.0/8`",no-agent-forwarding $KeyType $KeyBlob") -PublicKey $PublicKey | Should -BeTrue
        }

        It 'treats a different key blob as absent, so the operator key is actually added' {
            Test-AuthorizedKeyPresent -Lines @("$KeyType AAAAB3NzaC1yc2EAAAADAQABAAABAQDdifferent other") -PublicKey $PublicKey | Should -BeFalse
        }

        It 'ignores commented and blank lines, because sshd does not honor a commented-out key' {
            Test-AuthorizedKeyPresent -Lines @("# $KeyType $KeyBlob", "#$KeyType $KeyBlob", '', '   ') -PublicKey $PublicKey | Should -BeFalse
        }

        It 'treats an empty file as absent, so a fresh box gets the key' {
            Test-AuthorizedKeyPresent -Lines @() -PublicKey $PublicKey | Should -BeFalse
        }
    }

    Context 'Assert-PublicKeyFormat' {
        It 'accepts an ssh-keygen RSA public key line, so a valid key is not rejected' {
            { Assert-PublicKeyFormat -PublicKey $PublicKey } | Should -Not -Throw
        }

        It 'rejects <Key>, so a bad key fails before anything is changed' -ForEach @(
            @{ Key = '' },
            @{ Key = 'garbage' },
            @{ Key = 'ssh-ed25519' }
        ) {
            { Assert-PublicKeyFormat -PublicKey $Key } | Should -Throw
        }
    }

    Context 'Get-ServiceExePath' {
        It 'parses <PathName> to <Expected>, because the flavor check and sshd -t depend on the real service binary' -ForEach @(
            @{ PathName = '"C:\Program Files\OpenSSH\sshd.exe"'; Expected = 'C:\Program Files\OpenSSH\sshd.exe' },
            @{ PathName = '"C:\Program Files\OpenSSH\sshd.exe" -f "C:\x\sshd_config"'; Expected = 'C:\Program Files\OpenSSH\sshd.exe' },
            @{ PathName = 'C:\WINDOWS\System32\OpenSSH\sshd.exe'; Expected = 'C:\WINDOWS\System32\OpenSSH\sshd.exe' },
            @{ PathName = 'C:\Program Files\OpenSSH\sshd.exe'; Expected = 'C:\Program Files\OpenSSH\sshd.exe' }
        ) {
            Get-ServiceExePath -PathName $PathName | Should -BeExactly $Expected
        }

        It 'throws on an unparseable PathName, because guessing the binary could validate the wrong sshd' {
            { Get-ServiceExePath -PathName 'nonsense' } | Should -Throw
        }
    }

    Context 'New-RandomPassword' {
        BeforeAll {
            function ConvertTo-PlainText {
                param([securestring]$Secure)
                [Net.NetworkCredential]::new('', $Secure).Password
            }
        }

        It 'returns a SecureString, because New-LocalUser -Password accepts only a SecureString' {
            New-RandomPassword | Should -BeOfType [securestring]
        }

        It 'returns 32 characters by default, so the unused password cannot be guessed' {
            (ConvertTo-PlainText (New-RandomPassword)).Length | Should -Be 32
        }

        It 'always includes an uppercase letter, a lowercase letter, a digit, and a symbol, because New-LocalUser fails when a local complexity policy rejects the password' {
            # Short passwords make a missing class likely, so this fails if the class check is removed.
            foreach ($i in 1..200) {
                $plain = ConvertTo-PlainText (New-RandomPassword -Length 4)
                $plain | Should -MatchExactly '[A-Z]'
                $plain | Should -MatchExactly '[a-z]'
                $plain | Should -Match '[0-9]'
                $plain | Should -Match '[^A-Za-z0-9]'
            }
        }

        It 'returns a different password on every call, so a constant or fixed-seed generator is caught' {
            $passwords = 1..20 | ForEach-Object { ConvertTo-PlainText (New-RandomPassword) }
            @($passwords | Sort-Object -CaseSensitive -Unique).Count | Should -Be 20
        }
    }

    Context 'Get-PowerSettingAcIndex' {
        BeforeAll {
            # Real 'powercfg /qh' output from a laptop where the lid close action is a hidden setting.
            $Lid = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'powercfg_qh_lidaction')
            $Sleep = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'powercfg_qh_standbyidle')
        }

        It 'reads the hidden lid close action from /qh output, because plain /query leaves hidden settings out' {
            Get-PowerSettingAcIndex -Lines $Lid | Should -Be 0
        }

        It 'reads the AC value and not the DC value, because battery behavior must be left alone' {
            $lines = $Lid -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x00000001' -replace 'Current DC Power Setting Index: 0x00000001', 'Current DC Power Setting Index: 0x00000000'
            Get-PowerSettingAcIndex -Lines $lines | Should -Be 1
        }

        It 'reads a sleep timeout of 0x0000012c as 300 seconds, so a 5 minute timeout is seen as needing a change' {
            $lines = $Sleep -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x0000012c'
            Get-PowerSettingAcIndex -Lines $lines | Should -Be 300
        }

        It 'reads 0xffffffff without overflowing, because timeouts can use the full 32-bit range' {
            $lines = $Sleep -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0xffffffff'
            Get-PowerSettingAcIndex -Lines $lines | Should -Be 4294967295
        }

        It 'throws when the AC value line is missing, because a hidden or localized setting must fail instead of being read as 0' {
            $lines = @($Lid | Where-Object { $_ -notmatch 'Current AC Power Setting Index' })
            { Get-PowerSettingAcIndex -Lines $lines } | Should -Throw '*found 0*'
        }

        It 'throws when the AC value line appears twice, because the output is not from a single setting' {
            { Get-PowerSettingAcIndex -Lines ($Lid + $Sleep) } | Should -Throw '*found 2*'
        }
    }

    Context 'Get-CardAuthKey' {
        BeforeAll {
            $Status = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'gpg_card_status_colons')
            $NoAuth = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'gpg_card_status_colons_noauth')
        }

        It 'picks field 4 of fpr and grp, because field 4 is the authentication slot and slots 2-3 are the signing and encryption keys, which SSH must never use' {
            $key = Get-CardAuthKey -Lines $Status

            $key.Fingerprint | Should -BeExactly 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF0BADF00D'
            $key.Keygrip | Should -BeExactly 'C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEE0000'
        }

        It 'throws when the auth slot is empty, because an empty keygrip would make READKEY fail with an unclear agent error, and the message tells the user how to fix it' {
            { Get-CardAuthKey -Lines $NoAuth } | Should -Throw '*no authentication key*Plug in a YubiKey*re-run*'
        }
    }

    Context 'ConvertFrom-ReadKeyOutput' {
        BeforeAll {
            $ReadKey = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'gpg_readkey_ssh')
            $AuthFpr = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF0BADF00D'
        }

        It 'returns the key type, the blob, and openpgp:0x plus the last 8 fingerprint digits, because Test-AuthorizedKeyPresent matches on the blob, and the comment keeps the format of keys already in administrators_authorized_keys' {
            $line = ConvertFrom-ReadKeyOutput -Lines $ReadKey -Fingerprint $AuthFpr

            $line | Should -BeExactly "ssh-rsa $KeyBlob openpgp:0x0BADF00D"
            Test-AuthorizedKeyPresent -Lines @($PublicKey) -PublicKey $line | Should -BeTrue
        }

        It 'throws on <Case>, because an empty key must never be written to administrators_authorized_keys' -ForEach @(
            @{ Case = 'an ERR line'; Lines = @('ERR 67108891 Not found <GPG Agent>'); Message = '*READKEY failed: ERR 67108891*' },
            @{ Case = 'no D line'; Lines = @('OK'); Message = '*returned no SSH key*' }
        ) {
            { ConvertFrom-ReadKeyOutput -Lines $Lines -Fingerprint $AuthFpr } | Should -Throw $Message
        }
    }

    Context 'Get-FirewallRuleUpdate' {
        It 'returns empty for an enabled, all-profile, local-subnet rule, so re-runs change nothing' {
            (Get-FirewallRuleUpdate -Enabled 'True' -Profile 'Any' -RemoteAddress @('LocalSubnet')).Count | Should -Be 0
        }

        It 'returns Enabled True for a disabled rule, because a disabled rule blocks SSH even when its profile and address are right' {
            $u = Get-FirewallRuleUpdate -Enabled 'False' -Profile 'Any' -RemoteAddress @('LocalSubnet')

            @($u.Keys) | Should -Be @('Enabled')
            $u.Enabled | Should -BeExactly 'True'
        }

        It 'returns Profile Any for a Private-only rule, because the OpenSSH install creates a Private-only rule and Public networks block it' {
            $u = Get-FirewallRuleUpdate -Enabled 'True' -Profile 'Private' -RemoteAddress @('LocalSubnet')

            @($u.Keys) | Should -Be @('Profile')
            $u.Profile | Should -BeExactly 'Any'
        }

        It 'returns RemoteAddress LocalSubnet for <Address>, because SSH must stay limited to the local subnet' -ForEach @(
            @{ Address = @('Any') },
            @{ Address = @('LocalSubnet', '192.0.2.0/24') }
        ) {
            $u = Get-FirewallRuleUpdate -Enabled 'True' -Profile 'Any' -RemoteAddress $Address

            @($u.Keys) | Should -Be @('RemoteAddress')
            $u.RemoteAddress | Should -BeExactly 'LocalSubnet'
        }
    }
}

Describe 'setup-ssh-user.ps1 Set-PowerForRemoteAccess' {
    BeforeAll {
        if (-not $env:ProgramData) { $env:ProgramData = '/ProgramData' }
        if (-not $env:WINDIR) { $env:WINDIR = '/Windows' }

        . (Join-Path $PSScriptRoot '..' 'setup-ssh-user.ps1')

        $LidZero = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'powercfg_qh_lidaction')
        $SleepZero = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'powercfg_qh_standbyidle')
        $VideoZero = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'powercfg_qh_videoidle')) -replace 'Current AC Power Setting Index: 0x[0-9a-f]+', 'Current AC Power Setting Index: 0x00000000'
        $LidSleep = $LidZero -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x00000001'
    }

    BeforeEach {
        $script:Changes = New-Object System.Collections.Generic.List[string]
        $script:LidSet = $false
        Mock Write-Step { }
    }

    It 'changes nothing when the lid action, sleep, and display timeout are already right, so a re-run leaves the power plan alone' {
        Mock Invoke-Powercfg { switch ($Arguments[3]) { 'LIDACTION' { , $LidZero } 'STANDBYIDLE' { , $SleepZero } default { , $VideoZero } } }

        Set-PowerForRemoteAccess

        Should -Invoke Invoke-Powercfg -Times 0 -Exactly -ParameterFilter { $Arguments[0] -ne '/qh' }
        $script:Changes.Count | Should -Be 0
    }

    It 'sets only the lid action when closing the lid would sleep, because that is what makes a closed laptop unreachable' {
        Mock Invoke-Powercfg {
            if ($Arguments[0] -eq '/setacvalueindex' -and $Arguments[3] -eq 'LIDACTION') { $script:LidSet = $true; return , @() }
            if ($Arguments[0] -ne '/qh') { return , @() }
            if ($Arguments[3] -eq 'STANDBYIDLE') { return , $SleepZero }
            if ($Arguments[3] -eq 'VIDEOIDLE') { return , $VideoZero }
            if ($script:LidSet) { , $LidZero } else { , $LidSleep }
        }

        Set-PowerForRemoteAccess

        Should -Invoke Invoke-Powercfg -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' -and $Arguments[3] -eq 'LIDACTION' -and $Arguments[4] -eq '0' }
        Should -Invoke Invoke-Powercfg -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' -and $Arguments[3] -ne 'LIDACTION' }
        Should -Invoke Invoke-Powercfg -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/setactive' }
        @($script:Changes) | Should -Be @('set lid close action on AC power to Do nothing')
    }

    It 'sets all three values with their own subgroup when none is right, because each one alone can make a closed laptop unreachable' {
        $wrong = @{
            LIDACTION   = $LidSleep
            STANDBYIDLE = $SleepZero -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x0000012c'
            VIDEOIDLE   = $VideoZero -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x0000012c'
        }
        $right = @{ LIDACTION = $LidZero; STANDBYIDLE = $SleepZero; VIDEOIDLE = $VideoZero }
        $script:Set = @{}
        Mock Invoke-Powercfg {
            if ($Arguments[0] -eq '/setacvalueindex') { $script:Set[$Arguments[3]] = $true; return , @() }
            if ($Arguments[0] -ne '/qh') { return , @() }
            if ($script:Set[$Arguments[3]]) { , $right[$Arguments[3]] } else { , $wrong[$Arguments[3]] }
        }

        Set-PowerForRemoteAccess

        foreach ($pair in @(@('SUB_BUTTONS', 'LIDACTION'), @('SUB_SLEEP', 'STANDBYIDLE'), @('SUB_VIDEO', 'VIDEOIDLE'))) {
            $sub, $setting = $pair
            Should -Invoke Invoke-Powercfg -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' -and $Arguments[1] -eq 'SCHEME_CURRENT' -and $Arguments[2] -eq $sub -and $Arguments[3] -eq $setting -and $Arguments[4] -eq '0' }
        }
        $script:Changes.Count | Should -Be 3
    }

    It 'sets the display timeout to Never when it is 5 minutes, because on Modern Standby laptops the display timeout starts standby, which later drops the network' {
        $VideoFive = $VideoZero -replace 'Current AC Power Setting Index: 0x00000000', 'Current AC Power Setting Index: 0x0000012c'
        Mock Invoke-Powercfg {
            if ($Arguments[0] -eq '/setacvalueindex' -and $Arguments[3] -eq 'VIDEOIDLE') { $script:VideoSet = $true; return , @() }
            if ($Arguments[0] -ne '/qh') { return , @() }
            switch ($Arguments[3]) { 'LIDACTION' { , $LidZero } 'STANDBYIDLE' { , $SleepZero } default { if ($script:VideoSet) { , $VideoZero } else { , $VideoFive } } }
        }
        $script:VideoSet = $false

        Set-PowerForRemoteAccess

        Should -Invoke Invoke-Powercfg -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' -and $Arguments[3] -eq 'VIDEOIDLE' -and $Arguments[4] -eq '0' }
        @($script:Changes) | Should -Be @('set display turn-off on AC power to Never')
    }

    It 'throws when the lid action has not changed after setting it, because the summary must not claim a change that did not happen' {
        Mock Invoke-Powercfg {
            if ($Arguments[0] -ne '/qh') { return , @() }
            switch ($Arguments[3]) { 'STANDBYIDLE' { , $SleepZero } 'VIDEOIDLE' { , $VideoZero } default { , $LidSleep } }
        }

        { Set-PowerForRemoteAccess } | Should -Throw '*LIDACTION on AC power is 1*'
        $script:Changes.Count | Should -Be 0
    }
}

Describe 'setup-ssh-user.ps1 Invoke-Main' {
    BeforeAll {
        if (-not $env:ProgramData) { $env:ProgramData = '/ProgramData' }
        if (-not $env:WINDIR) { $env:WINDIR = '/Windows' }

        . (Join-Path $PSScriptRoot '..' 'setup-ssh-user.ps1')

        # Dot-sourcing puts the parameters in this scope. Remove them so the tests set them in
        # script scope, where they live on a real run and where Invoke-Main stores the card key.
        Remove-Variable -Name UserName, PublicKey
        $TestKey = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'test_key.pub') -Raw).Trim()
        $Steps = 'Install-OpenSSHServer', 'Start-OpenSSHService', 'Set-SshUserAccount', 'Set-AdminAuthorizedKey', 'Set-DefaultShell', 'Set-SshdConfig', 'Set-PowerForRemoteAccess', 'Test-SshListener', 'Set-SshFirewallRule', 'Write-Summary'
    }

    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $script:UserName = 'ssh-test'
        $script:PublicKey = ''
        $script:WrittenKey = $null
        Mock Test-IsDesktopEdition { $true }
        Mock Test-IsAdmin { $true }
        Mock Write-Step { }
        Mock New-Item { $script:Calls.Add('New-Item') }
        Mock Start-Transcript { $script:Calls.Add('Start-Transcript') }
        Mock Stop-Transcript { }
        Mock Get-CardSshPublicKey { $script:Calls.Add('Get-CardSshPublicKey'); $TestKey }
        foreach ($step in $Steps) { Mock $step { } }
        Mock Install-OpenSSHServer { $script:Calls.Add('Install-OpenSSHServer') }
        Mock Set-AdminAuthorizedKey { $script:WrittenKey = $PublicKey }
    }

    It 'throws on an empty -UserName before any system function runs, because there is no default account name to fall back to' {
        $script:UserName = ''

        { Invoke-Main } | Should -Throw '*Pass -UserName ssh-<name>.*'
        Should -Invoke Get-CardSshPublicKey -Times 0 -Exactly
        Should -Invoke New-Item -Times 0 -Exactly
        Should -Invoke Start-Transcript -Times 0 -Exactly
        foreach ($step in $Steps) { Should -Invoke $step -Times 0 -Exactly }
    }

    It 'reads the card before the log folder, the transcript, and Install-OpenSSHServer, and installs that key, so a missing YubiKey fails before any change' {
        Invoke-Main

        $script:Calls[0] | Should -BeExactly 'Get-CardSshPublicKey'
        $script:Calls.IndexOf('Install-OpenSSHServer') | Should -BeGreaterThan 0
        $script:WrittenKey | Should -BeExactly $TestKey
    }

    It 'never reads the card when -PublicKey is given, because the override must work without a card' {
        $script:PublicKey = $TestKey
        Mock Get-CardSshPublicKey { throw 'Get-CardSshPublicKey must not run with -PublicKey' }

        Invoke-Main

        Should -Invoke Get-CardSshPublicKey -Times 0 -Exactly
        $script:WrittenKey | Should -BeExactly $TestKey
    }
}
