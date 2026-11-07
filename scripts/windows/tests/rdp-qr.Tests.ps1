BeforeDiscovery {
    $Fixtures = @(Get-ChildItem (Join-Path $PSScriptRoot 'fixtures' 'qr') -Filter '*.matrix' | ForEach-Object { @{ Name = $_.BaseName } })
}

Describe 'rdp-qr.ps1' {
    BeforeAll {
        # enable-rdp.ps1 runs under strict mode and rdp-qr.ps1 must not set it itself, so set it here.
        Set-StrictMode -Version 3.0
        $ScriptPath = Join-Path $PSScriptRoot '..' 'rdp-qr.ps1'
        . $ScriptPath

        # Fixtures come from segno (byte mode, level L, smallest version, automatic mask);
        # the sms-* ones are the codes that were scanned on the phone.
        function Read-QrFixture {
            param([Parameter(Mandatory)][string]$Name)
            $dir = Join-Path $PSScriptRoot 'fixtures' 'qr'
            $lines = @([IO.File]::ReadAllLines((Join-Path $dir "$Name.matrix")) | Where-Object { $_ })
            if ($lines[0] -notmatch '^version=(\d+) mask=(\d+)$') { throw "Bad fixture header in $Name.matrix: $($lines[0])" }
            return [pscustomobject]@{
                Text    = [IO.File]::ReadAllText((Join-Path $dir "$Name.input"), [Text.UTF8Encoding]::new($false))
                Version = [int]$Matches[1]
                Mask    = [int]$Matches[2]
                Rows    = $lines[1..($lines.Count - 1)]
            }
        }
    }

    It 'reproduces the <Name> fixture exactly with its mask, because any encoding, EC, placement, or format bit error gives a code that does not scan' -ForEach $Fixtures {
        $fixture = Read-QrFixture -Name $Name

        $qr = New-QrMatrix -Text $fixture.Text -Mask $fixture.Mask

        $qr.Version | Should -Be $fixture.Version
        ($qr.Rows -join "`n") | Should -Be ($fixture.Rows -join "`n")
    }

    It 'picks the same mask as segno for the <Name> fixture, because the automatic choice must give the code that was verified on the phone' -ForEach $Fixtures {
        $fixture = Read-QrFixture -Name $Name

        $qr = New-QrMatrix -Text $fixture.Text

        $qr.Mask | Should -Be $fixture.Mask
        ($qr.Rows -join "`n") | Should -Be ($fixture.Rows -join "`n")
    }

    It 'fits 858 bytes in version 20 and throws at 859, because the encoder only has tables up to version 20-L and must not emit a broken code' {
        (New-QrMatrix -Text ('x' * 858) -Mask 0).Version | Should -Be 20

        { New-QrMatrix -Text ('x' * 859) } | Should -Throw '*version 20*'
    }

    It 'needs 77 columns by 39 lines for the sms-ip-deviceid code, because enable-rdp.ps1 warns when the window is smaller and the largest verified code is version 13' {
        $size = Get-QrConsoleSize -Rows (Read-QrFixture -Name 'sms-ip-deviceid').Rows

        $size.Width | Should -Be 77
        $size.Height | Should -Be 39
    }

    It 'prints two module rows per line in black on white inside a 4-module quiet zone, because the phone camera needs dark modules on a light background with a margin' {
        $script:Printed = [Collections.Generic.List[string]]::new()
        Mock Write-Host { $script:Printed.Add([string]$Object) }

        Write-QrCode -Rows @('10', '01')

        Should -Invoke Write-Host -Times 5 -Exactly
        Should -Invoke Write-Host -Times 5 -Exactly -ParameterFilter { $ForegroundColor -eq 'Black' -and $BackgroundColor -eq 'White' }
        $script:Printed[2] | Should -BeExactly ('    ' + [char]0x2580 + [char]0x2584 + '    ')
    }

    It 'contains only ASCII bytes, because Windows PowerShell 5.1 reads BOM-less files as Windows-1252 and silently drops the code around non-ASCII characters' {
        $nonAscii = @([IO.File]::ReadAllBytes($ScriptPath) | Where-Object { $_ -gt 0x7F })
        $nonAscii.Count | Should -Be 0
    }
}
