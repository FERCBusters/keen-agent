# KEEN Agent

KEEN Agent sends signed evidence to [KEEN](https://keen.cloud): recognised
activity from server logs and, on workstations, measured security settings.
Each item is a Universal Evidence Utility (UEU) envelope: a typed record named
by an event type from an event catalogue, with pseudonymous subjects in place
of account names, chained to the agent's previous evidence and signed with the
agent's own Ed25519 key. KEEN checks every signature, envelope and chain
position, stores the evidence with its provenance and applies the
organisation's framework mapping rules.

- **Servers** (Linux): package changes, SSH and console authentications,
  sudo and audited privileged commands, denied system calls and OSSEC alerts,
  recognised in selected logs. Each source chooses whether to send recognised
  events only, events with their redacted source lines, or every line.
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
never leaves the machine. The agent renews its key before it expires. For
autoscaling fleets, use an enrollment profile's bootstrap key instead
(`enrollment.bootstrap_key_file`; see [examples/autoscale.yaml](examples/autoscale.yaml)):
each machine enrols itself with its own key.

The packaged service runs as the unprivileged `keen-agent` user with a hardened
systemd unit. Packages install `/usr/bin/keen-agent`, the unit and
`/etc/keen-agent/config.yaml`; first installation never starts the service,
upgrades keep configuration, identity and queue, and removal keeps them for
deliberate cleanup.

## Configure

[examples/config.yaml](examples/config.yaml) documents every setting. Unknown
keys and parsers are rejected; the configuration must not be writable by group
or others; source paths are restricted to `/var/log`, and symlinks and
non-regular files are refused.

| Parser | Recognised events |
| --- | --- |
| `dpkg`, `apt`, `dnf` | `software.package.changed` |
| `syslog` | `user.authenticated` (SSH), `privileged.action.completed` (sudo) |
| `auditd` | `user.authenticated`, `privileged.action.completed`, `access.denied` |
| `ossec` | `security.alert.generated` ([docs/ossec.md](docs/ossec.md)) |
| `raw`, `json`, `nginx`, `php` | lines only (`all_lines` mode) |

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
`/var/lib/keen-agent`. Batches of up to 64 envelopes are signed and sent over
verified HTTPS; acknowledged envelopes leave the queue. A crash before
acknowledgement resends the same envelopes and KEEN deduplicates them.

- Network errors, 408, 429 and server errors retry with backoff, honouring
  `Retry-After`. Redirects are refused and TLS is always verified.
- Other 4xx responses pause delivery; envelopes stay queued and health reports
  the pause.
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
its envelopes' hashes. The private queue is not encrypted by the agent; use
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
