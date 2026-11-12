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

    function Invoke-WindowsPowerShell {
        # Runs a command in Windows PowerShell 5.1, where the Appx cmdlets work, with the Machine
        # module path so a PowerShell 7 parent's modules don't break the child. -EncodedCommand
        # avoids quoting problems. Returns $true when the child exits 0.
        param([Parameter(Mandatory)][string]$Command)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
        $savedModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand $encoded | Out-Host
            return $LASTEXITCODE -eq 0
        } finally {
            $env:PSModulePath = $savedModulePath
        }
    }

    function Get-Winget {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        $path = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $path) { return $path }

        # On a freshly enrolled PC, App Installer is often staged but not yet registered for this
        # user, so register it.
        $register = 'Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
        Write-Step 'winget not found; registering App Installer for this user...'
        $registered = Invoke-WindowsPowerShell -Command $register
        for ($i = 0; $registered -and $i -lt 10; $i++) {
            if (Test-Path -LiteralPath $path) { return $path }
            Start-Sleep -Seconds 1
        }
        throw "winget not found; install or update App Installer from the Microsoft Store, or run: $register"
    }

    function Install-WingetSource {
        # This user has no winget source package, and winget can't install it itself from an
        # elevated run-as session (AppX 0x80073D19, no logged-on user). Install Microsoft's
        # package directly, refusing it unless Microsoft signed it.
        Write-Step 'Installing the winget source package for this user...'
        $msix = Join-Path ([IO.Path]::GetTempPath()) ('winget-source-' + [guid]::NewGuid().ToString('N') + '.msix')
        try {
            Invoke-WebRequest -UseBasicParsing 'https://cdn.winget.microsoft.com/cache/source.msix' -OutFile $msix
            $sig = Get-AuthenticodeSignature -LiteralPath $msix
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike 'CN=Microsoft Corporation,*') {
                throw "The downloaded winget source package is not signed by Microsoft ($($sig.Status)); not installing it."
            }
            if (-not (Invoke-WindowsPowerShell -Command ("Add-AppxPackage -Path '{0}'" -f $msix.Replace("'", "''")))) {
                throw 'Could not install the winget source package; update App Installer from the Microsoft Store, then re-run.'
            }
        } finally {
            Remove-Item -LiteralPath $msix -Force -ErrorAction SilentlyContinue
        }
    }

    function Install-WingetPackage {
        param([Parameter(Mandatory)][string]$Id)
        Write-Step "Installing $Id with winget..."
        $winget = Get-Winget
        # On a freshly enrolled PC the source package is missing, and winget would fail with
        # 0x8a15000f. Install it first, so a normal run shows no error.
        if (-not (Invoke-WindowsPowerShell -Command 'if (Get-AppxPackage -Name Microsoft.Winget.Source) { exit 0 } else { exit 1 }')) {
            Install-WingetSource
        }
        $installArgs = @('install', '--id', $Id, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
        & $winget @installArgs
        if ($LASTEXITCODE -eq -1978335217) {
            # Backstop: 0x8a15000f, "Data required by the source is missing", even though the
            # check passed. Reinstall the source package, then retry once.
            Install-WingetSource
            & $winget @installArgs
        }
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
