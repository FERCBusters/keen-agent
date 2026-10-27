# Workstation setup

Install the package and open **KEEN Setup** from Applications (macOS), the Start
menu (Windows), or the application menu (Linux). Run the UI as the signed-in
user, not root/Administrator. Enter the main HTTPS KEEN domain and the individual
token registered for this workstation. KEEN administrators can associate that
workstation token with a Person. Enrollment profile keys are not supported.

Choose **Connect workstation** and approve the operating system's administrator
prompt. Setup verifies the token with KEEN's authenticated heartbeat endpoint,
saves the credentials in protected files, enables boot startup and starts the
service. “Connected” confirms credential verification and service activation;
the first full posture report is collected asynchronously. Close the window
when setup finishes. Only the Go service and the scheduled collectors remain.
No Electron process, local HTTP server or tray app is needed afterwards.

Checks run hourly. Linux desktop checks require a graphical login and run as
the user who completes setup; host checks run from boot without a login. The
setup app enables that user's systemd timer and an XDG login startup entry for
desktops that do not activate graphical-session.target. Other users can enable
the same session timer in their own session. The Linux log sender's polling and
health heartbeat are independent of the hourly posture schedule.

## Build Linux packages

On the Linux workstation/build host, install Node.js 22.12+ (or a supported newer
LTS), npm, Docker/BuildKit, then use the existing native package builder:

```
sh packaging/build-workstation.sh debian13
sh packaging/build-workstation.sh fedora44
```

The script packages Electron for the host's x64/arm64 architecture and includes
it in the normal keen-agent DEB/RPM. The Docker builds compile and test Go and
build the matching setup helper. See packaging/build-packages.sh for supported
distributions, including Ubuntu targets. Install the resulting package using
apt or dnf so its GTK/NSS/Polkit dependencies are installed. A desktop Polkit
authentication agent and a systemd user session must be available.

Ordinary server package builds can omit the Electron app: remove dist/setup-app
before running packaging/build-packages.sh directly. The GUI adds Electron's
runtime size to the installer, but consumes no memory after it is closed.

The app uses /usr/libexec/keen-setup-helper through pkexec. It creates
/etc/keen-workstation/config.yaml and token (root:keen-agent, 0640), and enables
keen-workstation.service with its independent /var/lib/keen-workstation queue.
The existing /etc/keen-agent log configuration is never overwritten. The package
installs the hourly host and session timers. If upgrading an already active
session collector, reload and restart it as that desktop user:

```
systemctl --user daemon-reload
systemctl --user restart keen-posture-session.timer
```

## Build macOS

Build on macOS with Go 1.26+, Node.js 22.12+, npm, Xcode command-line tools and the
Developer ID Application/Installer identities in the keychain. Configure the
notarytool keychain profile separately, then:

```
export APPLICATION_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)'
export INSTALLER_IDENTITY='Developer ID Installer: YOUR NAME (TEAMID)'
export NOTARY_PROFILE='keen-notary'
./packaging/macos/build-sign-notarize.sh
```

This builds universal Intel/Apple Silicon Go binaries and the Electron app,
signs the app's nested components with hardened runtime, signs the Go helper and
collector, builds and signs the PKG, notarises it and staples the result.
Output: dist/macos/keen-posture-0.1.9.pkg. The application is installed at
/Applications/KEEN Setup.app. Credentials remain root-only under
/Library/Application Support/KEEN/Posture. launchd starts collection at boot
and schedules it hourly.

For development before acquiring certificates:

```
UNSIGNED=1 ./packaging/macos/build-sign-notarize.sh
```

This creates keen-posture-0.1.9-unsigned.pkg with local ad-hoc application/binary
signatures, without notarisation or a trusted installer signature. Test on a Mac
where you deliberately approve your own development build using the OS's normal
application approval controls. HTTPS certificate verification remains enabled.

## Build Windows with a Harica hardware token

Build on Windows with Go 1.26+, Node.js 22.12+, npm, WiX 4+ and Windows SDK
SignTool installed. Install the hardware token's vendor middleware and expose its
certificate in CurrentUser\\My (or use -MachineStore for LocalMachine\\My).
The hardware middleware prompts for the PIN; no PIN or private key enters this
repository or the script arguments.

```
.\packaging\windows\build-sign.ps1 -Architecture amd64 -CertificateThumbprint YOUR40HEXTHUMBPRINT -TimestampUrl https://YOUR-TSA
```

The script packages Electron, signs its executable and executable helpers plus
the Go collector/setup helper, generates explicit WiX file components, builds
the MSI, signs it and verifies the signatures. SHA-256 signature and timestamp
digests are retained. Use -Architecture arm64 for an ARM64 Windows build. Test
on each architecture you distribute.

For certificate-free development builds:

```
.\packaging\windows\build-sign.ps1 -Architecture amd64 -Unsigned
```

Install the MSI, then open **KEEN Setup** from Start. The UI runs normally;
UAC elevates only the installed Go helper. ProgramData\\KEEN\\Posture credentials
and state allow SYSTEM and Administrators only. The Windows service runs as
LocalSystem, starts automatically at boot and checks hourly. Before setup,
the unconfigured service cannot collect or send; a boot-time start will stop
until configuration exists. MSI upgrades retain credentials and state and stop
the service while replacing files; restart KeenPosture after an upgrade (or
reboot) to start the new binary immediately. Automatic boot startup is retained.

## Development and checks

```
make test
npm ci --prefix onboarding
npm test --prefix onboarding
npm start --prefix onboarding
```

npm start previews the UI. Test actual onboarding from an installed package,
where the fixed privileged helper and service definitions are present. The
Windows development Electron path is not the installed helper location.

Test on each OS: initial connection, rejected/expired token, invalid certificate,
cancelled elevation, retry, reboot before login, login/session collection and
one-hour spacing in KEEN's evidence timestamps. Check the first report in KEEN;
a credential heartbeat alone does not establish that every collector succeeded.

## Credentials, retries and removal

The Electron renderer is sandboxed and isolated, with no Node integration,
remote navigation, external content or generic command IPC. Tokens are never
command-line arguments. A short-lived request file is readable only by the
signed-in user and administrators, and is removed after completion/cancellation.
An abrupt crash/power loss can leave that protected temporary file; administrators
can remove an abandoned keen-setup-* temporary directory. JavaScript strings are
not guaranteed secure-memory erasure.

The elevated helper accepts only URL/token fields, bounds the request, validates
HTTPS again, refuses redirects and environment proxies, and never disables TLS
certificate or hostname verification. No remote response body or token is printed.
It writes only fixed protected paths and enables fixed installed services.

Setup refuses a different existing connection. Retrying identical credentials
can finish service activation after an error. A stale setup.lock after a crash
requires administrator removal only after confirming no setup helper is running.
For token rotation, stop the service, replace the protected token as an
administrator, then restart. Keep existing queue data with the same KEEN identity.
When changing KEEN instance/device identity, archive its old config and queue and
start fresh; do not send an old queue to a different identity or installation.
Individual token expiry still applies; enrollment and automatic renewal are not
implemented by this app.

Uninstalling the package stops/removes its machine service and UI, while private
credentials and queued data are retained for deliberate administrator cleanup.
On macOS stop/unload system/net.keen.posture before removing its plist and binaries.
On Linux also disable the current user's keen-posture-session.timer and remove
~/.config/autostart/keen-posture-session.desktop if no longer collecting posture.
