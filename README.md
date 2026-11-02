# KEEN Agent

KEEN Agent sends signed evidence to [KEEN](https://keen.cloud): recognised
activity from server logs and, on workstations, measured security settings.
Each item is a Universal Evidence Utility (UEU) envelope: a typed record named
by an event type from an event catalogue, with pseudonymous subjects in place
of account names, chained to the agent's previous evidence and signed with the
agent's own Ed25519 key. Everything the agent sends is encrypted end to end to
the KEEN that issued its enrolment code, not just to whatever terminates TLS. KEEN checks every signature, envelope and chain
position, stores the evidence with its provenance and applies the
organisation's framework mapping rules.

- **Servers** (Linux): package changes, SSH, console, su, sudo and Drupal
  sign-ins, privileged commands, refused access (audit, SELinux, AppArmor,
  sudo), account and group changes, kernel and service faults (out-of-memory
  kills, I/O and filesystem errors, crashes, failed units), clock
  synchronisation, name-resolution problems, PHP and Drupal errors, the daily
  apt upgrade job completing, AppArmor profiles loaded at boot, and fail2ban
  and OSSEC alerts, recognised in selected logs. Each source chooses
  whether to send recognised events only, events with their redacted source
  lines, or every line.
- **Workstations** (Windows, macOS, Linux): disk encryption, screen locking,
  antivirus, firewall and automatic updates, measured hourly, with a record of
  what each run could and could not measure.

The evidence format, catalogue and protocol are specified in
[docs/evidence-format.md](docs/evidence-format.md).

## Install

Download pages, installers and signature verification instructions are at
[keen.cloud/agent](https://keen.cloud/agent).

### Debian 12 and 13

```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://mig5.net/static/mig5.asc | sudo gpg --dearmor -o /usr/share/keyrings/mig5.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mig5.gpg] https://apt.mig5.net $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mig5.list
sudo apt update
sudo apt install keen-agent
```

### Fedora 43 and 44

```bash
sudo rpm --import https://mig5.net/static/mig5.asc
sudo tee /etc/yum.repos.d/mig5.repo > /dev/null << 'EOF'
[mig5]
name=mig5 Repository
baseurl=https://rpm.mig5.net/$releasever/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mig5.net/static/mig5.asc
EOF
sudo dnf upgrade --refresh
sudo dnf install keen-agent
```

The release key's fingerprint is
`54A9 1143 AE0A B4F7 743B  01FE 888E D1B4 23A3 BC99`.

### Windows and macOS

Download the signed installer (`keen-posture-<version>-windows-amd64.msi`,
`-windows-arm64.msi` or `-macos-universal.pkg`) from
[keen.cloud/agent](https://keen.cloud/agent), verify it, install it and open
**KEEN Setup**. See [workstation setup](docs/workstation-setup.md).

## Enrol a server

1. In KEEN, open **Admin → Keen Agents → Register a collector**, choose **Keen
   Agent (signed evidence)**, and copy the single-use enrolment code. It is
   valid for 24 hours.
2. Edit `/etc/keen-agent/config.yaml`: set `endpoint`, enable the sources that
   exist on the server and choose an `evidence_mode`.
3. Save the code and enrol:

   ```sh
   sudo install -o root -g keen-agent -m 0640 /dev/null /etc/keen-agent/enrollment-code
   sudoedit /etc/keen-agent/enrollment-code
   sudo -u keen-agent keen-agent -command check
   sudo -u keen-agent keen-agent -command enroll
   sudo rm /etc/keen-agent/enrollment-code
   ```

4. Grant the `keen-agent` account read access to the selected logs (for
   journald, `sudo usermod -aG systemd-journal keen-agent`), then start it:

   ```sh
   sudo systemctl enable --now keen-agent
   sudo -u keen-agent keen-agent -command status
   ```

Enrolment generates the agent's key pair in `/var/lib/keen-agent/identity.json`
(mode 0600) and binds its public key to the KEEN identity; the private key
never leaves the machine. The code ends with the fingerprint of KEEN's
identity key: before sending anything, the agent checks that the server it
reached holds that key, and refuses one that does not. The agent renews its key before it expires. For
autoscaling fleets, use an enrollment profile's bootstrap key instead
(`enrollment.bootstrap_key_file`; see [examples/autoscale.yaml](examples/autoscale.yaml)):
each machine enrols itself with its own key.

The packaged service runs as the unprivileged `keen-agent` user with a hardened
systemd unit. Packages install `/usr/bin/keen-agent`, the unit and
`/etc/keen-agent/config.yaml`; first installation never starts the service,
upgrades keep configuration, identity and queue, and removal keeps them for
deliberate cleanup.

### Upgrade to 0.3

KEEN Agent 0.3 encrypts every request to KEEN's own key and needs a KEEN
release that supports it; neither talks to the other's earlier release.
Codes and bootstrap keys from earlier KEEN releases carry no fingerprint, and
identities enrolled by 0.2 pinned no KEEN key, so set each agent up afresh:

1. Let 0.2 deliver what it has queued while KEEN is still on its earlier
   release, if that matters to you (`keen-agent -command status`).
2. Stop the service and remove the contents of the state directory
   (`/var/lib/keen-agent`): identity, chain and queue. Anything still queued
   is discarded.
3. Upgrade the package, issue a new code (**Issue enrolment code** on the
   agent's card) or a new bootstrap key, save it and enrol as above.

The agent refuses to start with a 0.2 identity, and says why. The same
applies to every agent if KEEN's identity key is ever replaced.

### Upgrade a server from 0.1

KEEN Agent 0.1 authenticated with a bearer token and sent every parsed line.
After upgrading the package, and before restarting the service:

1. In KEEN, choose **Move to key** on the agent's card. Its token stops
   working at once; KEEN shows a single-use enrolment code.
2. In `/etc/keen-agent/config.yaml`, replace `token_file` with
   `enrollment.code_file: /etc/keen-agent/enrollment-code`. The agent refuses
   to start while `token_file` is present, and says why.
3. To keep sending every line, set `evidence_mode: all_lines` (globally or per
   source) and raise the agent's evidence mode limit in KEEN to match; the
   default sends recognised events only.
4. Save the code, enrol and restart, as in steps 3 and 4 above, then remove
   `/etc/keen-agent/token`.

Source positions are kept, so collection resumes where 0.1 stopped. Records
0.1 had queued but not delivered are sealed as signed evidence after
enrolment and sent first.

## Configure

[examples/config.yaml](examples/config.yaml) documents every setting. Unknown
keys and parsers are rejected; the configuration must not be writable by group
or others; source paths are restricted to `/var/log`, and symlinks and
non-regular files are refused.

| Parser | Recognised events |
| --- | --- |
| `dpkg`, `apt`, `dnf` | `software.package.changed` |
| `syslog` (journal or file) | `user.authenticated` (SSH, su, sudo, console and Drupal sign-ins), `privileged.action.completed` (sudo, su), `access.denied` (sudo refusals, AppArmor, SELinux), `security.alert.generated` (fail2ban bans), and with KEEN's 2026.11 catalogue: `system.fault.detected`, `clock.sync.changed`, `dns.lookup.failed`, `application.error.logged`, `user.account.changed`, `routine.task.completed`, `system.protection.activated` |
| `auditd` | `user.authenticated`, `privileged.action.completed`, `access.denied` (including SELinux and AppArmor) |
| `php` | `application.error.logged` (fatal, parse and recoverable errors; 2026.11 catalogue) |
| `ossec` | `security.alert.generated` ([docs/ossec.md](docs/ossec.md)) |
| `raw`, `json`, `nginx` | lines only (`all_lines` mode) |

The `syslog` parser recognises these messages:

| Event type | Messages |
| --- | --- |
| `system.fault.detected` | kernel out-of-memory kills, I/O and filesystem (ext4, XFS, Btrfs) errors, segfaults, hung tasks, kernel oopses and panics, hardware (MCE, EDAC) errors; failed systemd units; core dumps; PHP-FPM reaching `pm.max_children`; `No space left on device` from any program |
| `clock.sync.changed` | chrony selecting a source and systemd-timesyncd contacting a time server or first synchronising the clock (outcome `success`); chrony, ntpd, ntpsec's ntpdate and systemd-timesyncd losing their sources, stepping the clock, reporting an offset, a spike (jitter), a frequency error or an unsynchronised clock (outcome `failure`); offsets are sent in milliseconds and the time servers are not sent |
| `dns.lookup.failed` | `Temporary failure in name resolution`, `Could not resolve host`, failed `getaddrinfo`, and systemd-resolved falling back to a degraded feature set or failing DNSSEC validation; the name looked up is not sent |
| `application.error.logged` | PHP fatal, parse and recoverable errors from any program, and Drupal watchdog entries (syslog module) of priority error or worse, or PHP-type errors |
| `user.account.changed` | `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`, `gpasswd`, `passwd` and `chpasswd`, and Drupal accounts created, deleted or blocked |
| `routine.task.completed` | systemd finishing `apt-daily-upgrade.service`, the daily apt job that runs unattended-upgrades where it is installed and enabled (`task` `patching`). The event shows the job ran to completion: unattended-upgrades records the updates it installs, and its own errors, in its log. A job that fails is a `system.fault.detected` failed unit |
| `system.protection.activated` | systemd finishing `apparmor.service`, which loads the AppArmor profiles at boot (`protection` `mandatory_access_control`) |

Completed units are recognised only in the journal, from systemd itself: the
record must come from process 1, which journald records for each sender, so a
program logging as `systemd` cannot report another unit's run. A syslog file
carries the process ID its sender wrote, so its unit results are not evidence.
The messages are matched in the `Finished <unit> - <description>.` form that
systemd 257 logs on Debian 13; a host set to `StatusUnitFormat=description`
logs the description alone and is not recognised. Other recognised messages
are as trustworthy as the log they come from, since a local program can write
a message under any name.

KEEN grants the 2026.11 catalogue in its enrolment, renewal and health
replies once it accepts these event types. Until then the agent keeps to the
2026.10 catalogue every KEEN accepts: the newer messages are sent only as
lines in `all_lines` mode, with their recognised fields (such as `fault` or
`clock.condition`) as line attributes, and are otherwise counted as not
evidence. Those fields can also be used in `include_when` and `exclude_when`
filters, for example to leave out `dns.reason: degraded`.

| `evidence_mode` | Sends |
| --- | --- |
| `events` (default) | recognised events; source lines only as SHA-256 hashes and offsets |
| `events_with_lines` | recognised events with their redacted source lines |
| `all_lines` | as above, plus every other line as `log.line.collected` |

Set `evidence_mode` globally or per source. KEEN sets the most each identity
may send and enforces it; a source asking for more is reduced and reported in
health.

Account names, user IDs and Windows SIDs become HMAC-SHA256 pseudonyms before
they leave the machine. Each event type declares the fields it may carry, and
the agent drops prohibited and undeclared fields, recording each removal in
the envelope. `redact` adds RE2 patterns to the default secret redaction,
applied before the queue.

### Filters

Each source accepts `include_when` and `exclude_when` conditions on parsed
fields (`equals`, `starts_with`, `contains`, `exists`, `in_cidr`), applied
after parsing and redaction and before anything is queued. By default any
matching exclusion discards a record; `exclude_match: all` requires every
exclusion condition. Filtered records advance checkpoints, never reach KEEN
and are counted per source in health.

```yaml
sources:
  - name: nginx-access
    kind: file
    parser: nginx
    paths: [/var/log/nginx/*access*.log]
    evidence_mode: all_lines
    exclude_match: all
    exclude_when:
      - field: client.ip
        operator: in_cidr
        value: 192.0.2.0/24
      - field: status
        operator: equals
        value: "200"
```

## Delivery

Each envelope is sealed (evidence ID, chain position) and queued with its file
offset or journal cursor in one synchronised bbolt transaction under
`/var/lib/keen-agent`. Batches of up to 64 envelopes are signed, encrypted to
KEEN and sent over verified HTTPS; acknowledged envelopes leave the queue. A
crash before acknowledgement resends the same envelopes and KEEN deduplicates
them.

- An acknowledgement counts only if it is encrypted with the one-time key the
  agent put inside that request, which only KEEN could read. Anything else,
  including a `200` from a server that merely holds a valid certificate, leaves
  the envelopes queued and is reported in local status.
- Network errors, 408, 429, unverifiable responses and server errors retry
  with backoff, honouring `Retry-After`. Redirects are refused and TLS is
  always verified.
- 421 means KEEN no longer holds the encryption key the request used (KEEN
  makes a new one every 30 days); the agent fetches KEEN's current key,
  checks it against the pinned identity, and sends again.
- Other 4xx responses are refusals. Error responses are not encrypted, so a
  refusal may not be KEEN's: the agent keeps the envelopes, waits an hour,
  tries again, and reports the refusal in local status (`delivery_refused`,
  `credential_last_error`). Refusals never block the agent; a revoked or
  expired agent keeps retrying hourly until it is stopped or enrolled again.
- `queue_mb` bounds the queue; at capacity collection pauses without advancing
  checkpoints. `retention_days` (default 0, keep) permits discarding old
  envelopes; every discard is itself sent as `evidence.records.discarded`.
- Keep the state directory private and persistent: it holds the identity, the
  chain position and the queue. Never copy it to another machine.

`keen-agent -command status` shows queue size, source health, the chain
position, evidence modes and the identity's state; KEEN shows the same in its
agent inventory. `keen-agent -command key` prints the current key as
`KEY_ID=PUBLIC_KEY`, the form a reviewer pins when checking a KEEN
verification bundle with `ueu_verify_bundle.py --key`.

## Workstation posture

The Windows and macOS packages install `keen-posture`, a system service that
measures posture hourly and sends it with its own identity, and **KEEN Setup**,
which enrols it with a code. On Linux, `keen-agent` includes host and session
posture collectors. See [workstation setup](docs/workstation-setup.md),
[Linux posture](docs/posture-linux.md) and
[macOS and Windows posture](docs/posture-macos-windows.md).

## Security

The agent has no inbound listener, remote command channel, plugin loading or
template execution. Its only child processes are `/usr/bin/journalctl` with
fixed arguments and the read-only posture probes. Every request is signed with
the agent's key and accepted once; every batch carries a signed manifest of
its envelopes' hashes.

Every request, the enrolment code included, is encrypted end to end to KEEN
with HPKE (hybrid post-quantum MLKEM768-X25519, HKDF-SHA256, AES-256-GCM),
to a key signed by the KEEN identity whose fingerprint ends the enrolment
code. A reverse proxy, CDN, TLS-inspecting middlebox, or an impostor with a
valid certificate for KEEN's hostname sees only ciphertext, and cannot
acknowledge evidence away, alter a grant or replace KEEN's key. KEEN replaces
its encryption key every 30 days and erases old ones, so recorded traffic
cannot later be opened with keys taken from KEEN. This protects traffic, not
KEEN itself: whoever controls the KEEN server can read what it receives. See
[the protocol](docs/evidence-format.md#11-agent-identity-and-transport).

### Post-quantum cryptography

Encryption is post-quantum; signatures are not yet.

- **Confidentiality.** Each request's key comes from ML-KEM-768 (NIST's
  post-quantum standard, FIPS 203) and X25519 together, so reading it means
  breaking both, and bodies and KEEN's responses use AES-256-GCM. Traffic
  recorded today cannot be decrypted by a quantum computer built later
  ("harvest now, decrypt later").
- **Authentication.** KEEN's identity key, the agent's key and every request,
  batch and evidence signature are Ed25519, which a large quantum computer
  could forge. A forgery only helps an attacker active at the time; recorded
  traffic cannot be impersonated afterwards, and passing off forged evidence
  as historical still needs write access to KEEN.
- **TLS.** Since Go 1.24 the agent's TLS client also offers the hybrid
  X25519MLKEM768 key exchange; a reverse proxy whose TLS library supports it
  (for example OpenSSL 3.5 or later) adds a second post-quantum layer. The private queue is not encrypted by the agent; use
disk encryption where required. A compromised host can still sign false
evidence, so signatures establish origin and integrity, not truth.

## Development

```sh
make test                                     # Go race tests and vet
npm ci --prefix onboarding && npm test --prefix onboarding
go run ./cmd/keen-agent -command posture-host  # local posture preview
```

Releases are described in [docs/releasing.md](docs/releasing.md). `VERSION` is
the single source of the release version.
