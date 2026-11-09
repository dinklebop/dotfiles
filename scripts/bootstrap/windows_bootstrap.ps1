# windows_bootstrap.ps1: install Gpg4win and chezmoi, then decrypt and run the
# YubiKey-gated highlander payload, which applies these dotfiles.
#
# Run from an elevated Windows PowerShell or PowerShell 7 window (Run as
# administrator), with the YubiKey plugged in:
#
#   irm https://dinklebop.com/bootstrap | iex
#
# To test a branch:
#
#   $env:DOTFILES_BRANCH = '<branch>'; irm https://raw.githubusercontent.com/dinklebop/dotfiles/<branch>/scripts/bootstrap/windows_bootstrap.ps1 | iex
#
# It does not self-elevate; it stops if the window is not elevated.

& {
    Set-StrictMode -Version 3.0
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $Fingerprint = '77D8616541A323FF03E6639947BEA857F03AFE90'
    $Branch = if ($env:DOTFILES_BRANCH) { $env:DOTFILES_BRANCH } else { 'main' }
    $Raw = "https://raw.githubusercontent.com/dinklebop/dotfiles/$Branch/scripts/bootstrap"
    $GpgBin = 'C:\Program Files\GnuPG\bin'

    function Write-Banner {
        param([Parameter(Mandatory)][string]$Message)
        Write-Host ''
        Write-Host $Message -ForegroundColor Red
        Write-Host ''
    }

    function Write-Step {
        param([Parameter(Mandatory)][string]$Message)
        Write-Host $Message -ForegroundColor Green
    }

    function Test-IsAdmin {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Update-SessionPath {
        $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $user = [Environment]::GetEnvironmentVariable('Path', 'User')
        $env:Path = "$machine;$user"
        if ((Test-Path -LiteralPath $GpgBin) -and (($env:Path -split ';') -notcontains $GpgBin)) {
            $env:Path = "$GpgBin;$env:Path"
        }
    }

    function Get-Winget {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        $path = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $path) { return $path }
        throw 'winget not found; install App Installer from the Microsoft Store, then re-run.'
    }

    function Install-WingetPackage {
        param([Parameter(Mandatory)][string]$Id)
        Write-Step "Installing $Id with winget..."
        & (Get-Winget) install --id $Id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
        if ($LASTEXITCODE -ne 0) { throw "winget install $Id failed ($LASTEXITCODE)." }
    }

    function Invoke-Gpg {
        param([Parameter(Mandatory)][string[]]$Arguments)
        & "$GpgBin\gpg.exe" @Arguments
        if ($LASTEXITCODE -ne 0) { throw "gpg $($Arguments -join ' ') failed ($LASTEXITCODE)" }
    }

    if (-not (Test-IsAdmin)) {
        throw 'Run this from an elevated PowerShell window (Run as administrator).'
    }

    Write-Banner "Windows bootstrap from dinklebop/dotfiles ($Branch)"

    $savedPath = $env:Path
    try {
        if (-not (Test-Path -LiteralPath "$GpgBin\gpg.exe")) {
            Install-WingetPackage GnuPG.Gpg4win
        }
        Update-SessionPath

        if ($null -eq (Get-Command chezmoi.exe -ErrorAction SilentlyContinue)) {
            Install-WingetPackage twpayne.chezmoi
            Update-SessionPath
            if ($null -eq (Get-Command chezmoi.exe -ErrorAction SilentlyContinue)) {
                throw 'chezmoi not on PATH after install; open a new elevated window and re-run.'
            }
        }

        $ws = Join-Path ([IO.Path]::GetTempPath()) ('highlander-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $ws | Out-Null

        $savedModulePath = $env:PSModulePath
        $savedPolicy = $env:PSExecutionPolicyPreference
        try {
            try {
                Invoke-Gpg @('--keyserver', 'hkps://keyserver.ubuntu.com', '--recv-keys', $Fingerprint)
            } catch {
                Write-Step 'Keyserver failed; importing the key from the repo.'
                Invoke-WebRequest -UseBasicParsing "$Raw/$Fingerprint.asc" -OutFile "$ws\key.asc"
                Invoke-Gpg @('--import', "$ws\key.asc")
            }

            [IO.File]::WriteAllText("$ws\ownertrust.txt", "${Fingerprint}:6:`n", [Text.UTF8Encoding]::new($false))
            Invoke-Gpg @('--import-ownertrust', "$ws\ownertrust.txt")

            Write-Step 'Reading the YubiKey...'
            try {
                Invoke-Gpg @('--card-status')
            } catch {
                throw 'No OpenPGP card found; plug in your YubiKey and re-run.'
            }

            Invoke-WebRequest -UseBasicParsing "$Raw/highlander-windows.asc" -OutFile "$ws\highlander.asc"

            Write-Banner 'THERE CAN BE ONLY ONE!!!'
            Write-Step 'Enter your YubiKey PIN when asked; touch the YubiKey if it blinks.'
            Invoke-Gpg @('--output', "$ws\highlander.ps1", '--decrypt', "$ws\highlander.asc")

            $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
            $env:PSExecutionPolicyPreference = 'Bypass'
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$ws\highlander.ps1"
            if ($LASTEXITCODE -ne 0) {
                throw "Highlander payload failed with exit code $LASTEXITCODE."
            }

            Write-Step 'Done.'
        } finally {
            Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $ws) {
                Write-Warning "Could not remove $ws; delete it by hand, it holds the decrypted payload."
            }
            $env:PSModulePath = $savedModulePath
            if ($null -eq $savedPolicy) {
                Remove-Item Env:\PSExecutionPolicyPreference -ErrorAction SilentlyContinue
            } else {
                $env:PSExecutionPolicyPreference = $savedPolicy
            }
        }
    } finally {
        $env:Path = $savedPath
    }
}
