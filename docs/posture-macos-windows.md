# macOS and Windows posture companion

`cmd/keen-posture` is a standalone Go companion using the same observation schema
and KEEN OTLP attributes as the Linux agent. It does not port the Linux journal,
file-tail or enrollment machinery.

## Implemented coverage

| Control | macOS | Windows |
|---|---|---|
| Disk | FileVault startup volume status, off/on and transition | BitLocker per-volume conversion/protection state, percentage, suspended protection distinguished from encrypted bytes |
| Firewall | Application Firewall global state and PF enabled state separately | ActiveStore policy for Domain, Private and Public profiles; raw defaults preserved |
| Malware | Apple XProtect package receipts/version, Defender health when installed | Defender service/realtime/signatures/scan dates, SecurityCenter registered third-party products |
| Updates | Explicit managed or local software-update and App Store preferences, last successful check | Legacy WUA settings and successful check/install history, AU Group Policy, modern Update MDM values |
| Screen lock | Console user screen-saver password/delay/idle preferences; machine managed preferences take precedence | Machine inactivity policy and loaded local/domain/Entra user hive screen-saver settings, per-user policy overrides preferences |

These are observations, not a single compliance verdict. Examples: Windows
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
means there is no other lock mechanism. A device with no interactive session
may produce no user screen-lock observation.

## Build and generate reports

Requires Go matching go.mod (1.26+). Build on the target platform:

```
go build -trimpath -o keen-posture ./cmd/keen-posture
```

Use `keen-posture.exe` as the output name on Windows. From an elevated shell:

macOS:
```
sudo ./keen-posture -command report -diagnostics > mac-posture.json
```

Windows PowerShell:
```
.\keen-posture.exe -command report -diagnostics | Out-File -Encoding utf8 windows-posture.json
```

Omit `-diagnostics` for observed-only output. `-command otlp` prints a KEEN OTLP
JSON request without sending it. `report` and `otlp` require no token/config and
do not contact KEEN. Reports include relevant drive identifiers, account UID/SID,
product names and timestamps; no recovery keys, tokens, usernames, browser
history, full registry export or full system profiler dump is collected.
Review reports before sharing them. They are the intended input for refining
coverage on real macOS/Windows installations.

## Delivery

`-command once -config ABSOLUTE_PATH` collects, queues and delivers; `run` repeats
at `interval_seconds` (300..86400; default 3600). Windows `service` integrates
with SCM. macOS uses a launchd hourly oneshot; change StartInterval in its plist
to change that schedule (the config interval only controls run/service).

Config examples are under `packaging/macos` and `packaging/windows`. Endpoint must
be HTTPS ending in `/v1/otlp/logs`, with no embedded credentials/query/fragment.
System CA trust only; no insecure mode, redirect following or environment proxy.
Config and token must be protected; on macOS root-owned mode 0600 with trusted
parents, state directory 0700. On Windows ownership must be SYSTEM or
Administrators and the DACL must grant access only to these principals; directory
junctions/reparse points are rejected. Provision under the installer-created
private directory. Do not use user-writable parents/custom paths.

The Bolt queue retains up to 128 reports, each at most 900 KB. No oldest-record
eviction. On saturation a new report fails; old reports remain. Existing reports
are drained before new ones so the queue can recover. IDs and timestamps are
stable on retries. A whole report is acknowledged only on HTTP 200 with a JSON
object and no reported partial failure. Partial rejection retains the report;
correct the receiver/configuration before retrying. Delivery is at least once;
KEEN should deduplicate IDs. Retries occur at the scheduled interval (no tight
retry loop). A collection/delivery pass has a five-minute deadline. No heartbeat,
automatic enrollment, token refresh, custom CA option or queue repair CLI is
implemented in this companion yet.

## macOS signed and notarized installer

Run `packaging/macos/build-sign-notarize.sh` **on macOS** with:

```
export APPLICATION_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)'
export INSTALLER_IDENTITY='Developer ID Installer: YOUR NAME (TEAMID)'
export NOTARY_PROFILE='keen-notary'
./packaging/macos/build-sign-notarize.sh
```

Create the named notarytool keychain profile beforehand using Apple's supported
credential flow. The script builds a universal Intel/Apple Silicon executable,
signs with hardened runtime/timestamp, packages, signs the PKG, submits and checks
notarization, staples, then verifies the package. No Apple password is embedded
in source or passed by this script. Output: `dist/macos/keen-posture-0.1.8.pkg`.

The installer creates `/Library/Application Support/KEEN/Posture` and its state
directory, installs `/usr/local/libexec/keen-posture` and the launch daemon, and
**does not enable delivery automatically**. Copy/edit the example config into
that private directory and provision the token without putting it in shell
history. Set config/token root:wheel mode 0600. Test:

```
sudo /usr/local/libexec/keen-posture -command once -config '/Library/Application Support/KEEN/Posture/config.json'
sudo launchctl bootstrap system /Library/LaunchDaemons/net.keen.posture.plist
```

Stop with `launchctl bootout system/net.keen.posture` before removing files. Keep
or deliberately destroy the private config/token/state separately. No automatic
credential removal is performed by upgrades. On an upgrade, the next launchd
invocation uses the updated binary.

## Windows MSI and Harica hardware-token signing

Requires Go, Windows SDK SignTool, .NET and a separately installed WiX CLI
supporting the v4 schema (`wix build`, WiX 4+). Pin the exact WiX/SDK toolchain in
your release environment; this script does not download tools or certificates.
Install Harica's token middleware/CSP/KSP and its certificate into the Windows
certificate store. The private key remains on the token. Use the certificate
thumbprint (SHA-1 **selection identifier**, not signature algorithm) and your
chosen RFC3161 timestamp URL:

```
.\packaging\windows\build-sign.ps1 -Architecture amd64 -CertificateThumbprint YOUR40HEXTHUMBPRINT -TimestampUrl https://YOUR-TSA
```

Use `-MachineStore` only when the certificate is in LocalMachine\My. Otherwise
CurrentUser\My is used. The token middleware handles PIN prompting; the script
has no PIN/private-key parameter. It signs EXE first, builds the MSI containing
that EXE, signs MSI, then verifies both with SignTool. Both signature and timestamp
digests use SHA-256. `-Unsigned` explicitly produces development artifacts.
`-Architecture arm64` builds native ARM64 separately; validate PowerShell module
availability on your ARM installation. Keep MSI product architecture consistent
for an upgrade; do not install both architectures on one machine.

Install the MSI elevated. It creates a demand-start LocalSystem service and a
private ProgramData directory; it does not start unconfigured collection. Then:

```
.\packaging\windows\provision.ps1 -Endpoint https://keen.example/api/v1/otlp/logs
```

This prompts for the token, writes protected config/state, enables automatic
startup and starts the service. It refuses to overwrite existing credentials.
For rotation, stop the service, edit protected files as Administrator, then
restart. MSI upgrades stop the service; start it explicitly afterwards and
confirm its startup mode. Uninstallation removes the service/binary but retains
private data so credentials/queued evidence are not silently lost.

Windows collection uses an embedded fixed PowerShell script via the system
Windows PowerShell executable, `-NoProfile`, fixed system module paths, and no
ExecutionPolicy bypass. Restricted language mode, WDAC/AppLocker, disabled WMI
providers or missing Defender/SecurityCenter will yield diagnostics. The Windows
command timeout terminates PowerShell; it does not yet use a Job Object to kill
all possible provider descendants. No arbitrary script/path/plugin execution
is exposed by the companion.

References: [SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool),
[WiX service schema](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[WiX ACL schema](https://docs.firegiant.com/wix/schema/wxs/permissionex/),
[Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution),
[Apple screensaver schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.screensaver.yaml).
