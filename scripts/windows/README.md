# Windows remote access

These scripts set up SSH and RDP into a Windows PC for one account on it.

- `setup-remote-access.ps1` lists the Entra, local, and Microsoft-account profiles on the PC. You
  pick one, and it runs the two scripts below for it.
- `setup-ssh-user.ps1` creates a key-only local admin `ssh-<name>`, installs and configures
  OpenSSH Server and PowerShell 7, and keeps the PC awake on AC power. The key comes from the
  YubiKey's OpenPGP authentication slot; `-PublicKey` overrides it.
- `enable-rdp.ps1` turns RDP on where no policy does, and adds the account to Administrators and
  Remote Desktop Users. Then it prints a Mac connection-file command and, through `rdp-qr.ps1`,
  a QR code for it.

## Prerequisites

- An elevated Windows PowerShell 5.1 window (Run as administrator). None of the scripts
  self-elevate.
- Gpg4win (`winget install --id GnuPG.Gpg4win`), and a YubiKey with an OpenPGP authentication
  subkey. Not needed with `-PublicKey`.
- Windows Pro or higher for RDP. On Home, SSH is still set up, then the RDP half fails.
- Windows App on the Mac.

## Through chezmoi

On Windows, `chezmoi apply` runs `.chezmoiscripts/run_onchange_after_50-windows-remote-access.ps1.tmpl`.
It starts `setup-remote-access.ps1` in a clean Windows PowerShell 5.1, and re-runs it whenever one
of the four scripts changes. A failed run is retried on the next apply. The picked account is
saved in `C:\ProgramData\SshUserSetup\selection.json`, so later runs don't prompt. To pick again,
run the script with `-Reselect`. The old `ssh-<name>` account stays; the script prints how to
remove it.

## Standalone

    powershell.exe -ExecutionPolicy Bypass -File .\setup-remote-access.ps1 [-Reselect] [-PublicKey '<ssh key>']
    powershell.exe -ExecutionPolicy Bypass -File .\setup-ssh-user.ps1 -UserName ssh-<name> [-PublicKey '<ssh key>']
    powershell.exe -ExecutionPolicy Bypass -File .\enable-rdp.ps1 -Principal 'AzureAD\user@example.com' -AccountType Entra
    powershell.exe -ExecutionPolicy Bypass -File .\enable-rdp.ps1 -Principal "$env:COMPUTERNAME\alice" -AccountType Local
    powershell.exe -ExecutionPolicy Bypass -File .\enable-rdp.ps1 -Principal "$env:COMPUTERNAME\alice" -AccountType MicrosoftAccount -RdpUserName 'MicrosoftAccount\user@example.com'

`rdp-qr.ps1` has no command of its own; `enable-rdp.ps1` dot-sources it, so it must sit in the same folder.

## Networking

If an MDM (Intune) firewall rule already allows TCP 22 or 3389, that side isn't changed. If not,
the OpenSSH rule and the two built-in Remote Desktop UserMode rules are enabled on every network
profile, but only for the local subnet. Hosts outside the PC's subnet can't connect.

## Signing in

- **Entra:** the Entra connection files carry `enablerdsaadauth:i:1`, which turns on "Use
  Microsoft Entra authentication" in Windows App. Sign in with the Entra account in the web
  prompt, and allow the remote desktop connection the first time you're asked.
- **Local and Microsoft accounts:** sign in with the account password; RDP needs the password,
  not a PIN or Windows Hello. A Microsoft account that has only ever used a PIN or Windows Hello
  needs one password sign-in first.
- **Local accounts on an Entra-joined PC:** if a policy adds the tenant domain to sign-in names,
  the first sign-in in the RDP window fails with an incorrect-password error, even though the
  connection file is right. Choose Other user and type `.\<name>` or `<COMPUTER>\<name>` with
  the password.

## Writing a connection file by hand

Save these lines as `<name>.rdp`, then open the file with Windows App.

- **Entra, hostname:** `full address:s:<host name>`, `enablerdsaadauth:i:1`, `screen mode id:i:1`
- **Entra, IP by device name:** `full address:s:<IPv4>`, `enablerdsaadauth:i:1`,
  `server identity:s:<host name>`, `server identity type:s:Entra ID Device Name`,
  `screen mode id:i:1`
- **Entra, IP by device ID:** as above, with `server identity:s:<DeviceId from dsregcmd /status>`
  and `server identity type:s:Entra ID Device ID`
- **Local or Microsoft account, ip or hostname:** `full address:s:<IPv4 or host name>`,
  `username:s:<COMPUTER\name or MicrosoftAccount\email>`, `screen mode id:i:1`

## Tests

From the repo root on the Mac, with Docker running:

    docker run --rm -v "$PWD/scripts/windows:/w" -w /w mcr.microsoft.com/dotnet/sdk:8.0 pwsh -NoProfile -File tests/Invoke-Checks.ps1

## Using this on your own branch

These scripts and the chezmoi wrapper arrive in one commit with no per-user values. Apply it to
your branch with `git format-patch -1 <commit> --stdout | git am`. Note the conflict with
chernand's windows-pwsh branch: this sets OpenSSH `DefaultShell` to `pwsh.exe` and uses the
built-in OpenSSH Optional Feature, while that branch sets `DefaultShell` to `shell-wrapper.bat`
and assumes `Microsoft.OpenSSH.Preview`. Carrying both flips `DefaultShell` on each run and hits
the flavor check, so pick one.
