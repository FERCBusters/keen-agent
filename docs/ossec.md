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

Keep your existing endpoint, enrolment, state directory, redaction and other sources.
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

## Evidence

Each alert with a rule ID becomes a `security.alert.generated` envelope with
these attributes:

| Attribute | Meaning |
| --- | --- |
| `product` | `ossec` |
| `rule_id` | `rule.id`, or legacy `rule.sidid` / `rule.sid` |
| `level` | original OSSEC level (integer) |
| `description` | `rule.description` or `rule.comment` (classified security-sensitive) |
| `groups` | the rule groups, e.g. `["sshd", "syslog"]` |
| `category` | the parser's classification, below |

| Classification | `category` |
| --- | --- |
| Authentication failure or success groups | `auth.login` |
| Syscheck/file-integrity alert | `file.integrity.alert` |
| Explicit syscheck `added` / `modified` / `deleted` | `file.created` / `file.changed` / `file.deleted` |
| Rootcheck | `host.integrity.alert` |
| Other alerts | `ossec.alert` |

KEEN's severity scales OSSEC levels 0–15 to 0–10. The reported user, source and
destination addresses and agent names are left out of the envelope; with
`evidence_mode: events_with_lines` (or `all_lines`) the redacted alert JSON is
included as the envelope's payload, and in `events` mode only its SHA-256 and
file offset are sent. Detection alerts do not establish whether active response
ran or succeeded; collect actual response records separately when that evidence
is required.

The parser supports older OSSEC fields and the nested alert schema. Legacy
epoch-millisecond `TimeStamp` takes precedence; otherwise it accepts ISO
timestamps (including numeric offsets without a colon) and OSSEC's older
`YYYY Mon DD HH:MM:SS` form. Zone-less timestamps use the collector host's
local timezone; missing or invalid timestamps fall back to the collection time.

## Parsed fields for filtering

Filters run on the parser's fields before anything becomes evidence, so they
can use more detail than the envelope carries:

| Field | Meaning |
| --- | --- |
| `ossec.rule.id`, `ossec.rule.level`, `ossec.rule.description`, `ossec.rule.groups` | rule identity, level, description, groups |
| `ossec.alert.id` | original alert ID |
| `host.name`, `host.ip`, `ossec.agent.id`, `ossec.manager.name` | monitored host and OSSEC agent |
| `source.ip`, `client.ip`, `destination.ip`, `source.port`, `destination.port` | validated addresses and ports |
| `user.name`, `process.name`, `ossec.decoder.name`, `ossec.location` | reported user, program, decoder and log location |
| `file.path`, `ossec.syscheck.*` | file-integrity target and reported hashes, size and ownership |
| `ossec.data.*` | bounded scalar leaves from custom nested `data` fields |

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

No KEEN server change or OSSEC API credential is required. Open an ingested
alert and choose **Create mapping from this event**: match
`action = security.alert.generated` and structured fields such as
`ueu.attributes.rule_id`, `ueu.attributes.groups` or `ueu.attributes.category`.

Examples: authentication failure rules can support access monitoring; syscheck
rules can support integrity monitoring; rootcheck alerts can support
host-security controls. Choose framework controls appropriate to your audit
purpose.

Reference schemas:
- https://www.ossec.net/docs/docs/formats/json.html
- https://www.ossec.net/docs/docs/manual/output/json-alert-log-output.html
