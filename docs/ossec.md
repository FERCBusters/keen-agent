# OSSEC JSON evidence

Run KEEN Agent on the OSSEC manager to collect its JSON alert stream. Enable
`<jsonout_output>yes</jsonout_output>` inside the existing `<global>` section of
`/var/ossec/etc/ossec.conf`, then restart OSSEC using your normal service procedure.
OSSEC writes one JSON object per line in `/var/ossec/logs/alerts/alerts.json`.

Add this source to your existing `/etc/keen-agent/config.yaml`:

```yaml
sources:
  - name: ossec
    kind: file
    parser: ossec
    paths:
      - /var/ossec/logs/alerts/alerts.json
      # Also discover uncompressed dated files across an active-file rotation.
      - /var/ossec/logs/alerts/*/*/ossec-alerts-*.json
```

Keep your existing endpoint, token, state directory, redaction and other sources.
Check the actual dated filenames on your installation before enabling the second
pattern. Multiple paths to the same inode in one named source share a checkpoint.
Files start at byte zero on first collection, so this may import existing history.
Only uncompressed files are read. Keep an uncompressed window longer than expected
agent outages; already-compressed historical files are outside this collector's
scope. Up to 256 matching files per source are allowed. A complete record larger
than the existing 60,000-byte limit is skipped and increments `rejected`; monitor
that counter for large file-integrity diffs. Incomplete trailing lines wait for
completion. Invalid JSON is retained as raw evidence with `parse_status=invalid_json`.

## Permissions

The service continues running as `keen-agent`, with its existing systemd sandbox
and no capabilities. Grant traversal on `/var/ossec` and `/var/ossec/logs`, and
read/traversal access to the selected alert logs and directories. Use narrow ACLs
or your existing log-reader policy; OSSEC configuration and agent keys are outside
the added readable path policy. Confirm permission inheritance and file modes after
OSSEC rotates a log, since a restrictive creation mode can mask inherited ACLs.

For an ACL-based installation, an operator can use:

```sh
sudo setfacl -m u:keen-agent:--x /var/ossec /var/ossec/logs
sudo find /var/ossec/logs/alerts -type d -exec setfacl -m u:keen-agent:r-x,d:u:keen-agent:r-x {} +
sudo find /var/ossec/logs/alerts -type f -name '*.json' -exec setfacl -m u:keen-agent:r-- {} +
sudo -u keen-agent head -c 1 /var/ossec/logs/alerts/alerts.json >/dev/null
sudo keen-agent -command check
sudo systemctl restart keen-agent
sudo keen-agent -command status
```

Install your distribution's ACL utilities if needed. Repeat the read-access check
after rotation. SELinux policy, where enforced, must also permit the selected reads.
The configuration check validates settings; source health verifies actual collection.

OSSEC commonly uses an active-file symlink. The collector accepts `alerts.json`
pointing beneath the same alert directory, then opens its target using the existing
descriptor-based path walk. Escaping targets, additional symlink hops and symlinked
parent directories are refused. Other parsers retain their existing no-symlink policy.
Custom OSSEC installations may place copied alert files beneath `/var/log`; the
additional allowed root for `parser: ossec` is specifically `/var/ossec/logs/alerts`.

## Evidence fields

The parser supports older OSSEC fields and the nested alert schema. Plain string
values are exposed directly, so mapping conditions do not need extra JSON quotes.

| Event field | Meaning |
| --- | --- |
| `fields.parser` | `ossec` |
| `fields.ossec.rule.id` | `rule.id`, or legacy `rule.sidid` / `rule.sid` |
| `fields.ossec.rule.level` | Original OSSEC level |
| `fields.ossec.rule.description` | `rule.description` or `rule.comment`; also the event summary |
| `fields.ossec.rule.groups` | Sorted JSON array of groups, e.g. `["sshd","syslog"]` |
| `fields.ossec.rule.firedtimes` | Upstream occurrence count, when present |
| `fields.ossec.alert.id` | Original alert ID; KEEN Agent retains its own stable delivery UUID |
| `fields.host.name`, `fields.host.ip` | Monitored host, taken from agent/legacy host fields |
| `fields.ossec.agent.id` | Upstream OSSEC agent ID |
| `fields.ossec.manager.name` | OSSEC manager name, when supplied |
| `fields.source.ip`, `fields.client.ip` | Validated source IP; the same address in both fields |
| `fields.destination.ip` | Validated destination IP |
| `fields.source.port`, `fields.destination.port` | Reported ports |
| `fields.user.name` / `actor` | Reported user |
| `fields.process.name` | Reported program |
| `fields.ossec.decoder.name` | Decoder name |
| `fields.ossec.location` | Original log location in the alert |
| `fields.log.file.path` | JSON alert file collected by KEEN Agent |
| `fields.file.path` | File-integrity target from `syscheck` or legacy `SyscheckFile` |
| `fields.ossec.syscheck.*` | Reported event, before/after MD5/SHA1/SHA256, size, permissions, UID/GID |
| `fields.ossec.data.*` | Bounded scalar leaves from custom nested `data` fields |

Legacy epoch-millisecond `TimeStamp` takes precedence; otherwise the parser accepts
ISO timestamps (including numeric offsets without a colon) and OSSEC's older
`YYYY Mon DD HH:MM:SS` form. Zone-less timestamps use the collector host's local
timezone. Missing/invalid timestamps retain collection time and set
`timestamp_status=collection_time_fallback`. The original vendor severity is retained;
KEEN severity scales levels 0–15 to 0–10, with level 16 capped at 10.

Explicit rule groups determine normalised actions:

| Classification | Action | Outcome |
| --- | --- | --- |
| Authentication failure groups | `auth.login` | `failure` |
| Authentication success group | `auth.login` | `success` |
| Syscheck/file-integrity alert | `file.integrity.alert` | `info` |
| Explicit syscheck `added` / `modified` / `deleted` | `file.created` / `file.changed` / `file.deleted` | `info` |
| Rootcheck | `host.integrity.alert` | `info` |
| Other valid alert JSON | `ossec.alert` | `info` |

The full JSON remains the raw evidence, subject to configured redaction. When
redaction is configured, JSON string escapes are decoded before matching and the
sanitized object is serialized again. Malformed JSON receives ordinary raw-text
redaction. Detection alerts do not establish whether active response ran or succeeded;
collect actual response records separately when that evidence is required.

## Filtering before delivery

The existing `include_when`, `exclude_when` and `exclude_match` options apply to
these fields. For example, exclude one noisy rule only for a specific subnet:

```yaml
    exclude_match: all
    exclude_when:
      - field: source.ip
        operator: in_cidr
        value: 192.0.2.0/24
      - field: ossec.rule.id
        operator: equals
        value: '5701'
```

`all` means AND; the default `any` means OR. Agent filter names omit the `fields.`
prefix. Filtering is applied after parsing/redaction; excluded evidence never
reaches KEEN. Keep important failures when they are needed to demonstrate monitoring.

## Mapping in KEEN

No KEEN server patch or OSSEC API credential is required. Delivery uses the existing
agent identity and OTLP endpoint. Open an ingested event and choose **Create mapping
from this event**. Keep `fields.parser = ossec`, then select relevant rule IDs,
groups, host, IP, file path, action or outcome. The mapping builder can use custom
structured-field keys even when a key is not offered as a preset.

Examples: authentication failure rules can support access monitoring; syscheck rules
can support integrity monitoring; rootcheck alerts can support host-security controls.
For a group match, use a contains condition including the JSON quotes, such as
`"syscheck"`. Choose framework controls appropriate to your audit purpose.

Reference schemas:
- https://www.ossec.net/docs/docs/formats/json.html
- https://www.ossec.net/docs/docs/manual/output/json-alert-log-output.html
