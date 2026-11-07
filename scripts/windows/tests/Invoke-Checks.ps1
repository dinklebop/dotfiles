# Runs PSScriptAnalyzer and Pester for setup-remote-access.ps1, setup-ssh-user.ps1, enable-rdp.ps1, and rdp-qr.ps1. Exits non-zero on any finding or failure.
# From the repo root on the Mac:
#   docker run --rm -v "$PWD/scripts/windows:/w" -w /w mcr.microsoft.com/dotnet/sdk:8.0 pwsh -NoProfile -File tests/Invoke-Checks.ps1

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module Pester -RequiredVersion 6.2.0 -Scope CurrentUser -Force
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser -Force
Import-Module Pester -RequiredVersion 6.2.0
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0

$settings = @{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSUseShouldProcessForStateChangingFunctions')
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}

$findings = @(foreach ($name in 'setup-remote-access.ps1', 'setup-ssh-user.ps1', 'enable-rdp.ps1', 'rdp-qr.ps1') { Invoke-ScriptAnalyzer -Path (Join-Path $PSScriptRoot '..' $name) -Settings $settings })
foreach ($finding in $findings) {
    [Console]::Out.WriteLine("$($finding.ScriptName) $($finding.RuleName) line $($finding.Line): $($finding.Message)")
}
[Console]::Out.WriteLine("PSScriptAnalyzer findings: $($findings.Count)")

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $config

if ($findings.Count -gt 0 -or $result.FailedCount -gt 0) {
    exit 1
}
exit 0
