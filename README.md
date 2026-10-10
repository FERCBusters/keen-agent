# KEEN Agent

KEEN Agent is a standalone Linux Go service that collects selected host logs and sends OTLP/HTTP JSON to KEEN. It enriches records with patching, HTTP, PHP and Linux Audit context. KEEN stores the events and their redacted artifacts, then applies the existing framework mapping rules.

## How to install KEEN Agent

### APT repository

```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://mig5.net/static/mig5.asc | sudo gpg --dearmor -o /usr/share/keyrings/mig5.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mig5.gpg] https://apt.mig5.net $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mig5.list
sudo apt update
sudo apt install keen-agent
```

### RPM repository

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

## Install the KEEN receiver on the KEEN server

In KEEN, open **Admin → Integrations → Manage agents**, register one identity per server, and save the one-time credential. Choose its expiry (1–365 days, default 90). The server stores only a SHA-256 hash of the randomly generated 256-bit credential. Outbound API integration credentials continue to use their existing encryption mechanism.

The standard reverse proxy endpoint is `https://keen.example.org/api/v1/otlp/logs`. Direct API deployments use `/v1/otlp/logs`. Ensure TLS terminates at a trusted reverse proxy.

## Build and install the agent on a Linux server

Use a maintained Go toolchain supporting Go 1.25 or newer. Dependencies are pinned in `go.mod` and `go.sum`.

```sh
cd keen-agent
make build
sudo useradd --system --home-dir /var/lib/keen-agent --shell /usr/sbin/nologin keen-agent
sudo install -m 0755 dist/keen-agent /usr/local/bin/keen-agent
sudo install -d -o root -g keen-agent -m 0750 /etc/keen-agent
sudo install -o root -g keen-agent -m 0640 examples/config.yaml /etc/keen-agent/config.yaml
sudo install -o root -g keen-agent -m 0640 /dev/null /etc/keen-agent/token
sudoedit /etc/keen-agent/config.yaml
sudoedit /etc/keen-agent/token
sudo install -m 0644 packaging/keen-agent.service /etc/systemd/system/keen-agent.service
```

Paste the issued credential into the token file as a single line. Adjust the endpoint and enable only sources that exist on the server. Do not put credentials in command-line arguments, YAML or shell history. On systems without `useradd`, create the equivalent system account through the operating system's account manager. Skip account creation if it already exists.

Grant the service account read access to selected logs. For journald, where the group exists:

```sh
sudo usermod -aG systemd-journal keen-agent
```

For files, use a dedicated log-reader group or narrowly scoped ACLs. Auditd commonly restricts both `/var/log/audit` traversal and the log file itself: configure its `log_group` and directory permissions according to local policy. Ensure logrotate/auditd rotation creates replacement files with the same read access. Avoid granting write access, `CAP_AUDIT_CONTROL`, or `CAP_DAC_READ_SEARCH`. The shipped service runs without capabilities; it does not need root when these permissions are configured.

```sh
sudo -u keen-agent /usr/local/bin/keen-agent -command check
sudo systemctl daemon-reload
sudo systemctl enable --now keen-agent
sudo journalctl -u keen-agent -f
sudo -u keen-agent /usr/local/bin/keen-agent -command status
```

`check` validates configuration, file permissions and CA loading. Collection permissions and connectivity are verified during normal operation and appear in source health. `status` reads the latest local report while the service is running. The service uses `/var/lib/keen-agent` with mode 0700 and reports health to KEEN approximately once a minute. Large or slow collections can delay reports. Restart after changing configuration or replacing a blocked/expired credential.

The systemd unit limits privileges, memory, process count and writable paths. Keep `state_dir` at its default unless you also update the unit's `StateDirectory` and `ReadWritePaths`. Test the unit against your distribution's security policy (including SELinux/AppArmor).

## Configuration and log semantics

See `examples/config.yaml` for the complete configuration and commented source examples. Unknown YAML keys and unknown parsers are rejected. Configuration must be non-writable by group/others; credential files must also deny all access to others. Source paths are restricted to `/var/log`; symlinks in any path component and non-regular files are refused. Keep log directories and configuration owned by trusted administrators.

| Parser | Enrichment |
| --- | --- |
| `raw` | Original redacted text, collection time and source |
| `syslog` | RFC 5424/ISO timestamps; RFC 3164 host-local timestamp with year inference |
| `json` | Bounded top-level JSON fields; malformed JSON retained with a parse marker |
| `nginx` | Common access-log request path (without query), HTTP status; 5xx outcome |
| `php` | PHP fatal/parse error outcome; optional multiline grouping |
| `dpkg` | Timestamp, install/upgrade/remove/purge/status, package and available versions |
| `apt` | History transaction grouped from Start-Date to End-Date, package lists and requester |
| `dnf` | Recognized Installed/Upgraded/Removed/Erased/Downgraded messages; raw RPM/DNF messages retained |
| `auditd` | Group by audit timestamp/serial, record type, auid, syscall fields and success/failure |

Parsing is intentionally conservative. An unrecognized format remains evidence as redacted text. Dpkg and legacy syslog times use the agent host's timezone. Auditd records are grouped across reads and restarts, with interleaved IDs supported; an EOE record closes a group. Groups also close after three seconds without a new record or at the size limit and carry `group_completion=timeout_or_size`. Late records can therefore form another event. Raw grouped records preserve fields that repeat across audit record types; enrichment uses the first occurrence. Hex-encoded audit EXECVE/PROCTITLE values remain encoded. This release does not decode syscall numbers against architecture tables.

`multiline_start` groups file records until the next matching line or idle/size boundary. Journald uses its native message boundaries and durable cursors; auditd grouping and multiline options apply to file sources. A journal source's initial read uses `initial_lookback`. A newly discovered file starts at byte zero. Select paths carefully to avoid importing an unintended archive.

## Delivery, rotation and retention

Events receive a random UUID before being durably queued. The event and its file offset/journal cursor are committed in one bbolt transaction with disk synchronization enabled. Pending multiline/audit groups are also persisted. After a successful receiver response, the acknowledged batch is removed. A crash before acknowledgement resends the same UUIDs; KEEN deduplicates by registered identity plus UUID and rejects conflicting content.

This provides at-least-once delivery for records durably collected, with server-side deduplication while their KEEN events remain retained. Source deletion, log rotation during a long outage, disk failure, explicit queue expiry or deleting KEEN evidence can affect these guarantees. Clearing the state directory or registering a new identity breaks continuity. Never copy one agent's state/credential to another server.

- Network errors, 408, 429 and server errors retry with exponential backoff and jitter, honoring Retry-After up to one hour. Redirects are refused and TLS certificates/hostnames are verified; there is no insecure TLS switch.
- Permanent client errors (including 400, 401, 403, 409, 413 and 415) pause delivery. Records remain queued, collection continues until capacity, and health reports show the pause. Fix the problem and restart the service. A partial-success response with rejected records also pauses delivery for review; the KEEN receiver itself uses whole-batch acceptance.
- `queue_mb` bounds serialized queued payload and checkpoint bytes. Pending groups/checkpoints are additionally capped at a quarter of that budget or 16 MiB, whichever is smaller. At capacity, collection pauses without advancing the affected checkpoint. Database allocation adds overhead. bbolt reuses freed pages and retains its allocated high-water size; allow disk headroom above the payload limit. It is not a hard filesystem quota.
- `retention_days: 0` retains unsent records indefinitely. A positive value permits removal of records older than that many days **since queueing**. Removal increments the dropped/gap counter. Choose this only when the operational policy permits lost evidence.
- File identity uses device/inode plus a prefix fingerprint. Configure both the live filename and uncompressed rotated files. Rename rotation is supported when the rotated file remains matched. Copy-truncate is detected when its size/prefix changes and increments the gap counter; a truncate-and-regrow race with an identical prefix cannot be reliably detected by polling.
- Compressed archives are not replayed. Set an uncompressed retention window longer than expected outages. A missing/vacuumed journal cursor reports an error; resolve journal retention or explicitly start a new source name with a chosen lookback, accepting possible replay.
- Lines over 60,000 bytes are consumed without unbounded allocation and counted as dropped. Incomplete lines wait for a newline. Source paths are capped at 256 matched files, each source at 32 pending groups, and retained checkpoints at 4,096. Reaching a checkpoint limit pauses new-file collection; inspect state/rotation policy before planning a fresh state directory and replay.
- Delivery sends up to 32 records per batch, roughly one batch per second when collection is quick. Filtering high-volume access logs is advisable. Monitor queue growth and choose filters and retention appropriate to the expected event volume.

The status file and agent UI show queue bytes, record count, dropped/gap count, source errors, credential expiry and last contact. “Connected” means recent authenticated contact; inspect source status and queue growth to assess collection health. A quiet generic OTLP collector may have no recent contact because it does not send KEEN heartbeats.

## Evidence and framework mapping

The server assigns `source=keen-agent` and binds `system` to the administrator-registered name. Client-supplied host names remain descriptive attributes and cannot replace that identity. Normalized payload includes `source` (configured log source), `action`, `outcome`, `actor`, `raw`, `fields` and the stable event ID. The artifact contains this normalized, redacted record; raw pointers include agent ID, event ID, receive time and the canonical received-record digest.

Use **Admin → Evidence definitions** to create rules against these fields, selecting the framework and controls appropriate to your organization. Useful criteria include `source=keen-agent`, `action=package.upgrade`, `action=auditd.SYSCALL` or `action=http.request` with `outcome=failure`. Parsed fields remain visible in the normalized payload for review; the current rule editor matches its listed event fields and summary patterns. Validate them using KEEN's existing rule editor and test tools; rules are not automatically installed for an assumed framework version.

A recorded update demonstrates an observed maintenance action. A compliance claim about patch timeliness additionally needs asset scope, applicable requirements, deadlines and measurements. Host logs and heartbeats are claims from a credentialed collector; a compromised host can falsify them. Preserve independent corroboration where required.

## Security and privacy

The agent has no inbound listener, remote command channel, plugin loading, template execution or shell-based parser. Its only child process is `/usr/bin/journalctl` with fixed arguments and validated unit names. Parsing uses bounded inputs and Go regular expressions. Install the binary, configuration, CA files, log directories and token under trusted ownership.

Default redaction covers common password/token assignments, bearer tokens and authentication/cookie headers. `redact` adds RE2 expressions, applied before the spool. KEEN applies its existing redaction and optional privacy masking again before evidence storage. These patterns cannot guarantee removal of every secret or personal datum: review actual source formats, minimize selected logs and add organization-specific rules. The private spool is **not encrypted** by the agent; use host disk encryption if required. Inbound agent tokens are hashed in Postgres, and the agent must retain its plaintext token in a protected file. KEEN's existing database/object-storage encryption policies govern received evidence.

Rotate through the UI, replace the host token atomically with its protected permissions, then restart. Revocation is permanent for the identity and takes effect after any already-running locked ingestion transaction completes. It preserves historical evidence. A token only authenticates log submission and heartbeat updates; it cannot read evidence, edit controls or administer KEEN.

## OTLP interoperability

The receiver implements the **logs signal over OTLP/HTTP JSON**, at `/v1/otlp/logs` (or `/api/v1/otlp/logs` through the UI proxy). Protobuf, gRPC, traces and metrics are not implemented in this release. Standard collectors must select JSON and override their logs endpoint. KEEN-specific enrichment is optional; see `examples/alloy.alloy`.

KEEN Agent emits these optional log attributes:

| Attribute | Meaning |
| --- | --- |
| `keen.event.id` | Stable UUID; assigned once before queueing |
| `keen.source` | Configured log source name |
| `keen.action`, `keen.outcome`, `keen.actor` | Parsed activity |
| `keen.summary` | Bounded summary |
| `keen.field.*` | Additional parsed context |

Generic records use `action=log.record`, `source=otlp` within their normalized payload, and a deterministic UUID derived from the authenticated identity and canonical record content. This deduplicates identical retries; identical records with the same timestamp/content also collapse. Supply a stable `keen.event.id` when distinct identical records must be preserved. Avoid changing resource/scope metadata during replay. The actual KEEN event source remains `keen-agent` for both senders.

Receiver limits: 64 records/request; 1 MiB compressed and decompressed body; gzip or identity encoding; raw body 65,536 characters; 128 normalized fields, each value up to 4,096 characters and aggregate serialized fields up to 32 KiB. Timestamps must be timezone-aware via OTLP epoch nanoseconds, between year 2000 and five minutes into the future. Attribute nesting is limited to eight levels. Client enrichments beginning `resource.` or `otel.` are reserved. Rate limits are 60 log requests/minute per identity and 120/minute per observed client IP, plus separate heartbeat limits. Shared NAT/proxy deployments must account for the aggregate limit. The receiver fails closed if its rate-limit store is unavailable.

A successful response is `{}` after the complete batch commits. UUID conflicts return 409; invalid batches return 400; oversized requests 413; unsupported encodings 415. Server errors leave the transaction uncommitted for retry. An object-store write followed by database rollback can leave an unreferenced, redacted object. Each persistence attempt uses a fresh artifact key, so retries also work with write-once local storage and hosted S3 conditional writes. Configure operational cleanup for unreferenced objects in accordance with your retention policy; database rollback never deletes retained evidence objects.

## Development and checks

```sh
make test
make release  # Linux amd64 and arm64 binaries, with SHA256SUMS
```

## Debian and Fedora packages

Build all four native package variants (Docker with BuildKit required):

```sh
./packaging/build-packages.sh
# Or select specific targets:
./packaging/build-packages.sh debian13 fedora44
```

Outputs are in `dist/packages/<target>/`. Builders use Debian 12/13 or Fedora
43/44 and checksum-verified Go 1.27.1. Builds are native amd64 or arm64;
CGO is disabled, so the executable has no glibc dependency. Tests and vet run
inside each build. Packages contain source license notices.

Install with `sudo apt install ./keen-agent_*.deb` or
`sudo dnf install ./keen-agent-*.rpm`. The package creates `keen-agent`, adds it
to existing `systemd-journal`, `adm` and `www-data` groups, and installs defaults
in `/etc/keen-agent`. Fedora does not normally have www-data; no such group is
invented. Grant additional read access for your chosen logs where required.
Membership of www-data grants access to other group-readable web files too.

Set the endpoint/sources in `/etc/keen-agent/config.yaml` and paste the issued
credential into `/etc/keen-agent/token`, then:

```sh
sudo -u keen-agent /usr/bin/keen-agent -command check
sudo systemctl enable --now keen-agent
```

First install never starts/enables the service. Upgrades preserve configuration,
credentials and queue; manually restart after upgrading to load the new binary.
Removal stops/disables the service and retains credentials, queue and account
for deliberate operator cleanup. Debian purge also retains token and state.
Packages install `/usr/bin/keen-agent`; when migrating from a manual installation,
remove the old `/etc/systemd/system/keen-agent.service` override after reviewing
local changes, run `systemctl daemon-reload`, and remove the obsolete
`/usr/local/bin/keen-agent` so it does not shadow the packaged command.


### client IP and structured collection filters

Nginx common/combined access logs expose `client.ip` from the first token
(the logged remote address), supporting IPv4 and IPv6. Custom nginx formats must
place that address first to use this parser. Forwarded headers are not inspected.
If nginx real-IP processing replaces remote_addr, its trusted-proxy configuration
is responsible for that value. This is a logged address, not proof of identity.

```yaml
sources:
  - name: nginx-access
    kind: file
    parser: nginx
    paths: [/var/log/nginx/*access*.log]
    exclude_when:
      - field: client.ip
        operator: in_cidr
        value: 192.0.2.0/24
      - field: status
        operator: equals
        value: "200"
```

Filters address literal keys in the parsed `fields` object, including keys with
dots such as `log.file.path`. Operators: equals, starts_with, contains, exists,
in_cidr. IPv4 and IPv6 CIDRs are supported; families remain distinct (an
IPv4-mapped IPv6 address uses IPv6 CIDRs). Values are case-sensitive strings;
quote numeric status codes. Up to 32 conditions per list are accepted.

An optional `include_when` list requires ANY condition to match. By default, ANY matching
`exclude_when` condition then discards the event (set exclude_match: all for AND). Exclusions win. Missing fields
never match, including exists. Existing raw include/exclude regex filters also
apply before parsing. Structured filters run after parsing and redaction, before
queuing. File offsets/journal cursors and per-source filtered counters advance
atomically with the queue transaction. Filtered records never reach KEEN and are
not automatically recoverable by changing filters. Existing queued records remain.

`filtered_by_source` in status/heartbeats counts structured-filter exclusions,
including records omitted by include_when. It persists across restarts and is
separate from rejected/gap counters. Raw regex exclusions are not in this count.
Deploy the accompanying platform update first to accept the new heartbeat field.


To require every exclusion condition to match, add `exclude_match: all` to that
source. The default `exclude_match: any` uses OR. With all (AND), a missing field
prevents exclusion; an empty list excludes nothing. include_when remains OR.

```yaml
    exclude_match: all
    exclude_when:
      - field: client.ip
        operator: in_cidr
        value: 192.0.2.0/24
      - field: status
        operator: equals
        value: "200"
```

This excludes only status 200 requests from that network. Other statuses from
that network, and status 200 requests from other networks, remain eligible.

## OSSEC JSON alerts

Use `parser: ossec` to collect JSON alerts on an OSSEC manager, with structured rule, host, IP and file-integrity fields.
See [OSSEC collection and evidence mapping](docs/ossec.md) for configuration, permissions, filtering and rotation.

You probably need to add `keen-agent` user to the `ossec` group to be able to reach the logs.
