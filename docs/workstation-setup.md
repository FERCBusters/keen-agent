# Workstation setup

Register the workstation in KEEN first: **Admin → Keen Agents → Register a
collector**, device type **Workstation**, linked to its person. KEEN shows a
single-use enrolment code, valid for 24 hours.

Install the package (see [keen.cloud/agent](https://keen.cloud/agent)) and
open **KEEN Setup** from Applications (macOS), the Start menu (Windows) or the
application menu (Linux). Run it as the signed-in user, not
root/Administrator. Enter the KEEN address and the enrolment code and choose
**Connect workstation**, then approve the operating system's administrator
prompt.

The elevated helper generates the device's Ed25519 key pair and pairwise
pseudonym key in the collector's private state directory, enrols the public
key with the code (proving possession of the private key), writes the
collector's configuration without any credential, enables boot startup and
starts the service. “Connected” confirms that KEEN bound the key and the
service started; the first posture run is collected asynchronously. Close the
window when setup finishes. Only the Go service and the scheduled collectors
remain; no Electron process, local HTTP server or tray app runs afterwards.

The code is used once. If setup fails after KEEN bound the key (for example
the service could not start), run it again with the same code: KEEN returns
the same binding for the same key. A code that has expired, or was used by
another device, needs a new code from KEEN (**Issue enrolment code** on the
agent's card); the device's previous key keeps working until the new code is
used.

Checks run hourly. Each run sends one observation per measured setting and a
coverage record of what it attempted, measured and could not measure. Linux
desktop checks require a graphical login and run as the user who completes
setup; host checks run from boot without a login. The setup app enables that
user's systemd timer and an XDG login startup entry for desktops that do not
activate graphical-session.target. Other users can enable the same session
timer in their own session.

## Where things are kept

| Platform | Configuration | Identity and queue |
| --- | --- | --- |
| Windows | `%ProgramData%\KEEN\Posture\config.json` | `%ProgramData%\KEEN\Posture\state\` (SYSTEM and Administrators only) |
| macOS | `/Library/Application Support/KEEN/Posture/config.json` | `/Library/Application Support/KEEN/Posture/state/` (root only) |
| Linux | `/etc/keen-workstation/config.yaml` | `/var/lib/keen-workstation/` (owned by `keen-agent`, mode 0700) |

On Linux, workstation posture runs as `keen-workstation.service`, a separate
`keen-agent` instance with its own identity and queue; an existing
`/etc/keen-agent` server configuration is never touched. If upgrading an
already active session collector, reload and restart it as that desktop user:

```
systemctl --user daemon-reload
systemctl --user restart keen-posture-session.timer
```

## Credentials, retries and removal

The Electron renderer is sandboxed and isolated, with no Node integration,
remote navigation, external content or generic command IPC. The code is never
a command-line argument: a short-lived request file readable only by the
signed-in user and administrators carries it to the helper and is removed after
completion or cancellation. An abrupt crash can leave that protected temporary
file; administrators can remove an abandoned `keen-setup-*` directory.

The helper accepts only the address and code, validates HTTPS, refuses
redirects and environment proxies, never disables TLS certificate or hostname
verification and prints no remote response body. It writes only fixed protected
paths and enables fixed installed services. Setup refuses to replace an
existing connection to a different KEEN address; a stale `setup.lock` after a
crash needs an administrator to remove it, after confirming no setup helper is
running.

The private key never leaves the device and the collector renews it before it
expires. To move a device to another KEEN identity or installation, stop the
service, archive and remove its configuration and state directory, then run
setup with a new code. Never copy a state directory to another device.

Uninstalling the package stops and removes its service and setup app, and keeps
the private configuration, identity and queued evidence for deliberate
administrator cleanup. On macOS stop `system/net.keen.posture` before removing
its plist and binaries. On Linux also disable the user's
`keen-posture-session.timer` and remove
`~/.config/autostart/keen-posture-session.desktop` if no longer collecting
posture.

## Building

[Releasing](releasing.md) covers building and signing the Windows MSI, the
macOS package and the Linux packages with the setup app
(`sh packaging/build-workstation.sh debian13`). For development:

```
make test
npm ci --prefix onboarding
npm test --prefix onboarding
npm start --prefix onboarding
```

`npm start` previews the UI. Test actual onboarding from an installed package,
where the fixed privileged helper and service definitions are present.

Test on each platform: initial connection, a rejected and an expired code, an
invalid certificate, cancelled elevation, retry with the same code, reboot
before login, login and session collection, and one-hour spacing of evidence
in KEEN. Open the first posture evidence in KEEN and check it shows **Signature
verified** and a started or continuous chain.

The packaged setup app uses the supplied KEEN mitigator artwork for macOS ICNS,
Windows ICO and Linux PNG icons.

### macOS screen-lock detection

The collector queries `sysadminctl -screenLock status` inside the active console
user's launchd session, with that user's identity. Normal status on stderr is
captured only for this fixed read-only query; raw command output is not uploaded.
A recognised result supplies `password_required` and `password_delay_seconds`.
For example, `screenLock delay is 300 seconds` means password protection is
configured with a five-minute grace period after screen saver/display sleep.
This is separate from `idle_seconds`, and does not itself establish an inactivity
timeout or a policy pass/fail. Legacy managed/ByHost/user preferences remain the
fallback when the status query fails or its output is not recognised. No user's
password is requested and no screen-lock setting is changed.

The packaged setup app uses the supplied KEEN mitigator artwork for macOS ICNS,
Windows ICO and Linux PNG icons. The 64-pixel source is scaled to 256 pixels for
packaging, so large Dock/Explorer icons will have the source image's resolution
limits. Rebuild/reinstall the native package to update both collector and icon;
no token re-entry is required for an already configured installation.
