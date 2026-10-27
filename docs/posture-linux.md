# Workstation posture

The optional collectors observe security settings. They do not enforce settings,
install updates, scan files for malware, change firewall rules, mount volumes,
read encryption keys, or produce compliance verdicts. Disabled by default.
Existing log collection and its systemd privilege restrictions are unchanged.

## Enable on a packaged installation

Add this source to `/etc/keen-agent/config.yaml` (or use the posture-only example):

```yaml
sources:
  - name: workstation-posture
    kind: journal
    parser: posture
```

Do not specify `units`, `paths`, or a file source for this parser. The agent selects
the two recognised units itself. It needs journal read access (normally membership
of `systemd-journal`, configured by the existing packaging setup).

```sh
sudo -u keen-agent /usr/bin/keen-agent -command check
sudo systemctl restart keen-agent.service
sudo systemctl enable --now keen-posture-host.timer
# Optional immediate host observation:
sudo systemctl start keen-posture-host.service
```

As EACH graphical desktop user, without sudo:

```sh
systemctl --user daemon-reload
systemctl --user enable --now keen-posture-session.timer
```

For desktops that do not start `graphical-session.target` (some Xfce/MATE setups),
install the supplied opt-in XDG autostart file for that user:

```sh
mkdir -p ~/.config/autostart
cp /usr/share/doc/keen-agent/keen-posture-session.desktop ~/.config/autostart/
```

On distributions that compress documentation, use the source package's
`packaging/keen-posture-session.desktop` instead. The autostart file starts only
the timer; it does not run a shell or pass desktop environment variables into a
privileged process. It is NOT installed globally or enabled automatically.

Host and desktop checks run hourly. Timers include jitter.
The session collector returns an unknown result for multiple graphical sessions
owned by the same UID because a shared user bus cannot reliably attribute the
settings to an individual session. Different users are reported separately.
Logind inventory is emitted by the host collector so missing session coverage
can be identified independently of desktop helpers.

Manual builds: install the existing main service as documented in README, the
host service/timer in `/etc/systemd/system/`, and the session service/timer in
`/etc/systemd/user/`. The source units reference `/usr/local/bin/keen-agent`;
packages rewrite them to `/usr/bin/keen-agent`.

## Preview and diagnose

```sh
# Read-only JSON observations; no config or KEEN credential is read:
sudo /usr/local/bin/keen-agent -command posture-host
# Run as the desktop user inside their graphical session:
/usr/bin/keen-agent -command posture-session

sudo journalctl -u keen-posture-host.service --since today
journalctl --user -u keen-posture-session.service --since today
sudo -u keen-agent /usr/bin/keen-agent -command status
```

Direct terminal output is for inspection. The posture parser only accepts stdout
records journal-attested to the shipped collector units. Redirecting terminal
JSON into `logger` does not create trusted posture evidence. The preview may
have different visibility from a sandboxed unit; inspect the unit's output too.
User journals must be available to the system collector. If local journald
storage/ACL policy prevents this, fix that policy rather than granting the sender
root. Persistent journaling may be needed to retain observations across reboots.

## Coverage and limitations

| Provider | Observations | Boundaries |
| --- | --- | --- |
| LUKS/dm-crypt | Mount/device ancestry; LUKS1/2; LVM above/below encryption; all RAID branches; Btrfs device enumeration | Plain dm-crypt without verified cipher, loop devices, unresolved graphs and missing access are unknown. No encryption key extraction; lsblk may probe storage metadata. |
| Swap | Active swap partitions and files, including containing filesystem; zram | No active swap is not applicable. Unconfigured/inactive swap is not audited. |
| ZFS | Native dataset encryption algorithm and key status for mounted datasets | Native encryption off does not prove the pool's underlying devices are unencrypted. |
| Mount scope | Root, home when separately mounted, and other recognised local block mounts | `/boot`, `/boot/efi`, `/efi` are explicitly excluded; remote filesystems, unmounted volumes, per-directory fscrypt/eCryptfs and cloud/hypervisor encryption need separate evidence. |
| UFW | Runtime active/inactive and defaults | Does not prove traffic is blocked or that all interfaces/families are covered. |
| firewalld | Service state, runtime active/default zones, ACCEPT-target zone count | Count includes inactive zones; it is diagnostic, not a failure verdict. Runtime rule effectiveness is not proved. |
| nftables | Input/forward base-chain counts, input drop-policy counts, rule count | Docker-only forward rules do not establish host input protection. Jumps, priorities, expressions and interfaces are not simulated. |
| iptables/ip6tables | Filter INPUT policy and rule count, separately for IPv4/IPv6 | Can coexist with nftables; no inferred overall firewall pass. |
| APT | Effective merged APT settings, install/refresh intervals, origin/exclusion counts, package presence, scheduler, reboot marker | Last successful/no-op unattended run and later error extracted from bounded current/previous log suffixes. Local timestamps retain their unspecified offset. Custom cron/management systems require other evidence. |
| DNF4/DNF5 | Standard automatic config, security/all scope, timer and service results; DNF4 install-only timer override | Standard `/etc/dnf/automatic.conf`, with DNF5 vendor defaults merged from `/usr/share/dnf5/dnf5-plugins/automatic.conf`. Custom unit commands/config paths are not interpreted. Download-only does not mean install. |
| rpm-ostree | none/check/stage/apply policy and automatic timer/service | Staged deployment is not active; running deployment/reboot still needs verification. |
| Defender for Linux | Whitelisted vendor JSON health, real-time/passive state, definition metadata | No tenant IDs, raw health dumps or licensed-account details. Query failure is unknown. |
| ClamAV | clamd/clamonacc/freshclam service/process presence, on-access config counts, signature metadata/age | clamd alone does not establish on-access scanning. Coverage, exclusions, scheduled scans and malware cleanliness are not attested. |
| Other endpoint products | Sophos SPL/legacy, CrowdStrike, SentinelOne, ESET service presence | Presence only; CrowdStrike is labelled EDR, not automatically antivirus. Vendor health needs additional adapters. |
| GNOME/Cinnamon/MATE | Effective GSettings, idle/lock delays, locker bus ownership; GNOME lockdown override | Configured policy, not proof that a lock successfully happened. Runtime inhibitors are not evaluated. MATE delays converted from minutes. |
| Xfce | Xfconf effective explicit values, saver/lock switches, minute delays, suspend and fullscreen settings | Missing compiled defaults remain unknown. Alternative locker may differ; no default assumptions. |
| KDE Plasma 5/6 | KConfig layering, available installed schema defaults, fractional-minute timeout, grace/resume/password preferences | Kiosk restrictions, runtime reload and exact locker identity unverified. No automatic-protection assertion. Missing defaults unknown. |
| XScreenSaver | Own-user process, `.xscreensaver` lock/mode/delays | Configuration only; X resources, command-line overrides, runtime reload and compiled defaults are not resolved. |

Missing commands, denied access, malformed output, unsupported versions and
partial inventories must never be interpreted as control failure or success.
`not_detected` means no supported component/service was found with available
visibility, not proof that no security product exists. False facts refer only to
the named mechanism (e.g. guest block encryption); they are not universal claims.
The helper reports components independently rather than selecting one apparent
winner when multiple tools coexist.

## Wire format and KEEN mapping

Each observation is one ordinary OTLP log event through the existing durable
queue.

Example event fields (all strings as in the existing protocol):

```text
action: posture.screen_lock
outcome: info
posture.schema_version: 1
posture.check: screen_lock
posture.provider: gnome
posture.scope: session:2
posture.status: observed
posture.reason: effective_user_settings_queried
posture.authority: user_session
posture.subject_uid: 1000
posture.observed_at: <journal timestamp, UTC>
posture.lock_enabled: true
posture.idle_seconds: 300
posture.lock_delay_seconds: 0
posture.automatic_lock_configured: true
```

Statuses: `observed`, `unknown`, `unsupported`, `error`, `not_detected`,
`not_applicable`. `observed` means facts were collected, NOT that the check passed.
In particular it includes explicitly disabled controls. There are no pass/fail
statuses. `outcome=info` intentionally avoids treating data collection success as
compliance. `posture.authority` and subject UID come from journal metadata; JSON
cannot overwrite them. Invalid/untrusted records advance the checkpoint and
increment the existing rejected counter instead of poisoning delivery.

## Security model

The main agent remains unprivileged with `ProtectHome=yes`, no capabilities and
no new socket/listener. It still only launches `journalctl`. The root helper is a
separate short-lived systemd service, with no network address families except
Unix sockets and Netlink, no credentials, and a read-only filesystem sandbox.
`CAP_NET_ADMIN` and `CAP_NET_RAW` are retained for inspecting kernel firewall rules
(the latter for legacy iptables sockets). 

This capability is NOT intrinsically read-only: the fixed program/arguments and service
separation are essential. To avoid it entirely, remove it in a unit override and
accept unknown nftables/iptables results. Do not add it to `keen-agent.service`.

The desktop helper runs as the user and receives no KEEN credential. Users can
change their own services, settings and reports; these observations are explicitly
labelled user-session evidence, not root attestation. Root can also falsify host
state/logs. This is collection with provenance, not tamper-proof attestation.

Commands are allowlisted, resolved from fixed system paths and checked for root
ownership/non-writable ancestry. No shell, PATH-based execution, user-supplied
command, plugin or remote-execution facility is introduced. Child processes have
5-second timeouts and 1 MiB output caps; an entire pass has a 100-second deadline.
Fixed log suffixes are bounded at 128 KiB. Inputs, graph depth, session/mount
counts, observation fields and JSON schemas are bounded. Potential secrets,
raw rulesets, process command lines, user file contents and malware scan contents
are not sent. Mount paths, session IDs, UIDs and selected configuration facts are
sent as evidence and should be considered in local privacy policy.

The collector does not run `apt update`, an unattended-upgrade dry run, DNF
transactions, antivirus scans, lock commands or firewall modifications. Some
query tools may activate desktop configuration services on D-Bus; they do not
request setting changes. Locker ownership is checked using GetNameOwner, which
does not start the locker.

## Disable / uninstall

```sh
sudo systemctl disable --now keen-posture-host.timer
sudo systemctl stop keen-posture-host.service
# Each desktop user:
systemctl --user disable --now keen-posture-session.timer
systemctl --user stop keen-posture-session.service
rm -f ~/.config/autostart/keen-posture-session.desktop
```

Remove the posture source and restart the main agent if no longer collecting it.
Package removal stops system units but cannot reliably contact every user's
session manager; disable the user timers/autostart before removing the package.
Existing already-queued evidence is retained under normal agent queue semantics.

## Development validation

Run `make test` for race-enabled unit tests and vet. The fixture suite covers
storage graphs, RAID/Btrfs mixed encryption, swapfiles, ZFS, policy overrides,
missing tools, download-only updates, successful no-op updates followed by errors,
multiple sessions, desktop time units/defaults, health redaction, hostile JSON and
journal provenance. Fuzz targets exercise nftables JSON, INI and posture ingestion.
VM integration tests on real distribution/desktop combinations remain necessary;
fixture coverage alone is not a claim of certification across Linux versions.


## Provider references

- [GNOME lock policy](https://help.gnome.org/system-admin-guide/desktop-lockscreen.html)
- [Xfce preferences and defaults](https://github.com/xfce-mirror/xfce4-screensaver/blob/master/src/gs-prefs.h)
- [Plasma locker schema](https://github.com/KDE/kscreenlocker/blob/master/settings/kscreenlockersettings.kcfg)
- [DNF5 automatic configuration](https://dnf5.readthedocs.io/en/stable/dnf5_plugins/automatic.8.html)
- [OpenZFS encryption properties](https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html)
- [ClamAV on-access scanning](https://docs.clamav.net/manual/OnAccess.html)
- [Qubes firewall](https://doc.qubes-os.org/en/latest/user/security-in-qubes/firewall.html),
- [Qubes GUI domain](https://doc.qubes-os.org/en/latest/user/advanced-topics/gui-domain.html).
