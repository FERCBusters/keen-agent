# macOS and Windows posture companion

`cmd/keen-posture` is the native workstation companion for macOS and Windows. It
measures posture with the same observation model as the Linux collectors and
sends each measured setting as a signed UEU observation
([evidence format](evidence-format.md)), with its own enrolled identity and
key. It has no log collection.

## Implemented coverage

| Control | macOS | Windows |
|---|---|---|
| Disk | FileVault startup volume status, off/on and transition | BitLocker per-volume conversion/protection state, percentage, suspended protection distinguished from encrypted bytes |
| Firewall | Application Firewall global state and PF enabled state separately | ActiveStore policy for Domain, Private and Public profiles; raw defaults preserved |
| Malware | Apple XProtect package receipts/version, Defender health when installed | Defender service/realtime/signatures/scan dates, SecurityCenter registered third-party products |
| Updates | Explicit managed or local software-update and App Store preferences, last successful check | Legacy WUA settings and successful check/install history, AU Group Policy, modern Update MDM values |
| Screen lock | Console user password requirement and delay (`sysadminctl`), screen-saver idle time and display sleep per power profile (`pmset`), combined into a lock time; machine managed preferences take precedence | One result per loaded local/domain/Entra user hive combining the machine inactivity limit, a password-protected selected screen saver (per-user policy overrides preferences) and sleep with sign-in on wake for the active power plan (power Group Policy overrides the plan) |

These are observations, not a single compliance verdict; KEEN judges them with
versioned rules and, where an organisation sets them, its own targets. Examples: Windows
BitLocker can be fully encrypted with protection suspended; registering an AV
product differs from Defender reporting realtime enabled; an update schedule
and a successful installation timestamp answer different questions. Windows
unknown/NotConfigured states are not coerced to enabled. macOS missing defaults
are unknown, not automatically disabled. macOS FileVault only covers the startup
volume, not every external/data volume. XProtect receipts report installed
components, not an inferred realtime state. PF enabled does not establish a
particular rule policy. An inactive Windows network profile can still have an
enabled firewall policy; profile scope is retained.

Legacy WUA settings may not reflect Windows Update for Business/MDM effective
behavior. MDM registry values are reported separately, without pretending to
resolve every precedence rule. Modern macOS declarative management and all
per-user managed screensaver domains are not fully resolved. macOS examines the
current console user; Windows examines loaded user hives (including disconnected
sessions), not every account. Neither claims that an absent idle preference
means there is no other lock mechanism. Windows reports
`automatic_lock_configured=true` with `lock_after_seconds` and `lock_paths` when
one path is confirmed, and otherwise omits it. `ScreenSaveActive` is 1 in a
default profile with no screen saver selected, so `screensaver_selected` is
reported separately and the executable path is never reported. Sleep is
confirmed only on S1-S3 platforms where every power source in use (mains, and
battery when batteries are present) requires sign-in on wake and sleeps after a
finite timeout; the longest timeout applies. Modern Standby sign-in, Dynamic
Lock and MDM device-lock policy are not resolved. Sleep capability comes from
`GetPwrCapabilities`, called by the executable through `powrprof.dll` from the
system directory; the script compiles no code. A device with no interactive session
may produce no user screen-lock observation.

macOS reports `automatic_lock_configured`, `lock_after_seconds` and `lock_paths`
the same way. The password is required `password_delay_seconds` after the screen
saver starts or the display turns off, so a path is the screen saver's idle time
(when set) or the display turning off: the earlier of display sleep and system
sleep in `pmset -g custom`, counted only when every power profile (mains, and
battery on a laptop) turns the display off, using the slowest profile. The lock
time is the quickest path plus the password delay. An unset screen saver time is
not treated as "never", and power assertions that keep a display awake (video,
`caffeinate`) are not resolved.

## Build and preview

Requires Go matching go.mod. Build on the target platform:

```
go build -trimpath -o keen-posture ./cmd/keen-posture
```

Use `keen-posture.exe` as the output name on Windows. From an elevated shell:

macOS:
```
sudo ./keen-posture -command report -diagnostics > mac-posture.json
sudo ./keen-posture -command preview > mac-envelopes.json
```

Windows PowerShell:
```
.\keen-posture.exe -command report -diagnostics | Out-File -Encoding utf8 windows-posture.json
.\keen-posture.exe -command preview | Out-File -Encoding utf8 windows-envelopes.json
```

`report` prints the raw observations (`-diagnostics` adds unavailable probes);
`preview` prints the UEU envelopes a run would send, including the coverage
record, with account identifiers pseudonymised by a throwaway key. Neither
needs configuration or contacts KEEN. Reports include drive identifiers,
account UID/SID, product names and timestamps; no recovery keys, credentials,
usernames, browser history, full registry export or system profiler dump is
collected. Review reports before sharing them.

## Workstation setup

The installers include **KEEN Setup**. Open it after installation and enter
the KEEN address and the single-use enrolment code issued for the workstation.
It enrols the companion, writes the protected configuration, enables boot
startup and starts the collector. See [workstation setup](workstation-setup.md).
Administrators can also provision manually, below.

## Enrolment and delivery

The configuration (`packaging/macos/config.example.json`,
`packaging/windows/config.example.json`) names the HTTPS endpoint (ending in
`/v1/otlp/logs`, no credentials, query or fragment), the private state
directory, `interval_seconds` (300..86400; default 3600) and, until the
device has enrolled, `enrollment_code_file`. System CA trust only; no insecure
mode, redirect following or environment proxy.

`-command enroll -config ABSOLUTE_PATH` generates the device's Ed25519 key pair
and pairwise pseudonym key in the state directory and binds the public key with
the code. After that the code file can be deleted and removed from the
configuration: the key is the credential, and the companion renews it before it
expires. `-command once` collects, seals and delivers; `run` repeats at
`interval_seconds`; Windows `service` integrates with the service manager.
macOS uses a launchd hourly oneshot; change `StartInterval` in its plist to
change that schedule.

Config, code file and state must be private: on macOS root-owned, mode 0600
files and a 0700 state directory with trusted parents; on Windows owned by
SYSTEM or Administrators with a DACL granting only those principals, and no
junctions or reparse points. Provision under the installer-created private
directory.

Each run's observations and its coverage record are sealed into the chained
queue (`pending.db`, at most 4,096 envelopes; a full queue refuses new runs and
keeps older evidence), then sent in signed batches of up to 64. An envelope
leaves the queue only on an unambiguous acknowledgement, keeping its evidence
ID and bytes across retries. After delivery the companion sends a signed
heartbeat with its version, queue size and chain position. A run has a
five-minute deadline; retries wait for the next run.

### Upgrading a workstation from 0.1

Install the new package over the old one, choose **Move to key** on the
device's card in KEEN, and run KEEN Setup with the same instance and the new
code. Setup enrols the device's key, replaces the configuration 0.1 wrote for
that instance and removes its token file. A configuration for another KEEN
instance is left alone, and Setup reports it. Posture reports 0.1 had queued
but not sent are dropped; the next hourly run measures the device again.

### Manual provisioning on macOS

The package installs `/usr/local/libexec/keen-posture`, the launch daemon and
`/Library/Application Support/KEEN/Posture` with its state directory, and does
not start delivery. As root, write the configuration and the code (mode 0600,
without putting the code in shell history), then:

```
sudo /usr/local/libexec/keen-posture -command enroll -config '/Library/Application Support/KEEN/Posture/config.json'
sudo rm '/Library/Application Support/KEEN/Posture/enrollment-code'
sudo /usr/local/libexec/keen-posture -command once -config '/Library/Application Support/KEEN/Posture/config.json'
sudo launchctl bootstrap system /Library/LaunchDaemons/net.keen.posture.plist
```

Remove `enrollment_code_file` from the configuration once enrolled. Stop with
`launchctl bootout system/net.keen.posture` before removing files. Upgrades keep
the configuration, identity and queue; the next launchd run uses the updated
binary.

### Manual provisioning on Windows

Install the MSI elevated. It creates an automatic-start LocalSystem service and
a private ProgramData directory, and does not start unconfigured collection.
Then, elevated:

```
.\packaging\windows\provision.ps1 -Endpoint https://keen.example/api/v1/otlp/logs
```

This prompts (masked) for the enrolment code, writes the protected
configuration, enrols, deletes the code and starts the service. It refuses to
overwrite an existing configuration or state. MSI upgrades stop the service;
start it afterwards. Uninstallation removes the service and binaries but keeps
the private directory, so the identity and queued evidence are not silently
lost.

Windows collection uses an embedded fixed PowerShell script via the system
Windows PowerShell executable, `-NoProfile`, fixed system module paths, and no
ExecutionPolicy bypass. Restricted language mode, WDAC/AppLocker, disabled WMI
providers or missing Defender/SecurityCenter yield diagnostics and appear in
the run's coverage record as unavailable. The command timeout terminates
PowerShell; it does not yet use a Job Object to kill all possible provider
descendants. No arbitrary script, path or plugin execution is exposed.

## Building signed installers

[Releasing](releasing.md) describes building and signing the MSI (Authenticode,
with a hardware token) and the macOS package (Developer ID, notarised), and
publishing them with OpenPGP signatures.

References: [SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool),
[WiX service schema](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[WiX ACL schema](https://docs.firegiant.com/wix/schema/wxs/permissionex/),
[Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution),
[Apple screensaver schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.screensaver.yaml).
