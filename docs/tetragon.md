# Tetragon JSON evidence

[Tetragon](https://tetragon.io) observes processes, files, network connections
and kernel activity with eBPF and reports what its tracing policies match.
Run KEEN Agent on the same host to collect Tetragon's JSON export file. Each
line of that file is one event.

Write the export beneath `/var/log`, and make it readable by a group:

```sh
tetragon --export-filename /var/log/tetragon/tetragon.log --export-file-perm 640
```

In a container, bind-mount the host's `/var/log/tetragon` to the same path
and pass the same flags. With Tetragon's configuration directory, put each
value in its own file instead: `/etc/tetragon/tetragon.conf.d/export-filename`
and `/etc/tetragon/tetragon.conf.d/export-file-perm`. Tetragon creates the
file with mode 600 by default, which masks the access granted below.

An export allow-list keeps the file to the events worth keeping as evidence,
for example every event from a tracing policy and the starts of a few
programs:

```json
{"event_set": ["PROCESS_KPROBE", "PROCESS_TRACEPOINT", "PROCESS_UPROBE", "PROCESS_LSM"]}
{"event_set": ["PROCESS_EXEC"], "binary_regex": ["^(/usr)?/s?bin/(sudo|su|pkexec|doas|nc|ncat|socat|nmap|tcpdump|strace|gdb|insmod|rmmod|useradd|userdel|usermod|passwd|visudo|crontab)$"]}
{"event_set": ["PROCESS_EXEC"], "binary_regex": ["^(/usr)?/bin/(ba|da|z|k)?sh$"], "parent_binary_regex": ["/(nginx|php-fpm[0-9.]*|postgres|forgejo|uvicorn|gunicorn|java|httpd|apache2)$"]}
```

Add this source to your existing `/etc/keen-agent/config.yaml`:

```yaml
sources:
  - name: tetragon
    kind: file
    parser: tetragon
    paths:
      - /var/log/tetragon/tetragon.log
      # Rotated files, so collection continues across a rotation.
      - /var/log/tetragon/tetragon-*.log
```

Keep your existing endpoint, enrolment, state directory, redaction and other
sources. Files start at byte zero on first collection, so this may import
existing history. Only uncompressed files are read: leave
`--export-file-compress` off, or keep enough uncompressed files
(`--export-file-max-backups`) to cover an agent outage. A complete record
larger than the existing 60,000-byte limit is skipped and increments
`rejected`. Incomplete trailing lines wait for completion. Invalid JSON is
retained as raw evidence with `parse_status=invalid_json`.

## Permissions

The service runs as `keen-agent` with no capabilities. Grant it read access
to the export directory and the files Tetragon creates there:

```sh
sudo setfacl -m u:keen-agent:r-x,d:u:keen-agent:r-- /var/log/tetragon
sudo setfacl -m u:keen-agent:r-- /var/log/tetragon/*.log
sudo -u keen-agent head -c 1 /var/log/tetragon/tetragon.log >/dev/null
sudo keen-agent -command check
sudo systemctl restart keen-agent
sudo keen-agent -command status
```

Repeat the read check after Tetragon rotates the file. SELinux policy, where
enforced, must also permit the reads.

## Evidence

Tetragon has no severity of its own. Each alert carries a `level` from 0 to
10, set by what the policy observed (below) and adjustable per policy.

### Policy alerts

Every event from a tracing policy (`process_kprobe`, `process_tracepoint`,
`process_lsm`, `process_uprobe`) becomes a `security.alert.generated`
envelope:

| Attribute | Meaning |
| --- | --- |
| `product` | `tetragon` |
| `rule_id` | the policy's name, e.g. `anomaly-secret-reads` (the hook, when the policy is unnamed) |
| `level` | 0 to 10 |
| `description` | what happened, e.g. `cat read /etc/shadow`, after the policy's `message` when it sets one (classified security-sensitive) |
| `groups` | the event kind, the hook, the policy action (e.g. `action:post`) and the policy's `tags` |
| `category` | from the hook, below |

| Hook | `category` | Default `level` |
| --- | --- | --- |
| `security_file_permission`, `security_file_open`, `fd_install` and LSM `file_open` reading | `file.read` | 8 |
| the same hooks writing or appending, and truncation, rename and unlink hooks | `file.write` | 8 |
| file hooks without an access mask or open flags | `file.access` | 6 |
| `security_bprm_check` and LSM `bprm_check_security` | `process.exec` | 8 |
| `tcp_connect`, `security_socket_connect` and LSM `socket_connect` | `network.connect` | 8 |
| `do_init_module`, `security_kernel_read_file` | `kernel.module.load` | 6 |
| `free_module` | `kernel.module.unload` | 4 |
| `bpf_check`, `security_bpf_prog_load` | `kernel.bpf.load` | 6 |
| any other hook | `tetragon.alert` | 5 |

The category comes from the hook, so it stays correct when a policy is
renamed. Give a policy `tags` to map on your own vocabulary as well.

### Program starts

`process_exec` events that pass the export allow-list are classified by the
program and the account it runs as:

| Start | Envelope |
| --- | --- |
| `sudo`, `su`, `pkexec`, `doas` or `run0` running as root under a non-root parent | `privileged.action.completed`: `mechanism` (e.g. `sudo`), `executable` (the program `sudo`, `doas` or `pkexec` ran, when it is a plain program name), `audit_type` `process_exec`, outcome `success` |
| the same programs under a root parent (sudo's own child, the `su` it starts) | nothing: the escalation was already recorded |
| a shell started by a network service (`nginx`, `php-fpm`, `postgres`, `forgejo`, `uvicorn`, `gunicorn`, `java`, `redis-server`, `valkey-server`, `httpd`, `apache2`) | `security.alert.generated`, `rule_id` `process_exec`, `category` `process.exec.service_shell`, level 9 |
| any other start | `security.alert.generated`, `rule_id` `process_exec`, `category` `process.exec.watched`, level 3; `groups` name the program and `parent:<program>`, and `setuid` when it gained root |

`process_exit` and other events are not evidence. With `evidence_mode:
all_lines` they are sent as `log.line.collected`.

### Accounts and privacy

The login uid (`auid`), which Linux keeps through `sudo` and `su`, becomes
the envelope's pseudonymous subject, so a root shell's actions stay linked
to the account that opened it. Without a login uid, the subject is the
invoking account for a privilege change and the process's own account for an
alert. Uids themselves are not sent.

Command arguments, working directories, addresses and container names are
left out of the envelope. Account directories are replaced in paths and
descriptions: `/home/alice/.ssh/id_ed25519` becomes
`/home/~/.ssh/id_ed25519`, as do `/var/home/<account>` and
`/run/user/<uid>`. With `evidence_mode: events_with_lines` (or `all_lines`)
the redacted event JSON is included as the envelope's payload; in `events`
mode only its SHA-256 and file offset are sent. Redaction applies to the
decoded JSON strings, as for OSSEC alerts.

## Levels

Override the level of a policy's alerts by name, or of watched program
starts with `process_exec`:

```yaml
    tetragon_levels:
      anomaly-secret-reads: 10
      process_exec: 2
```

Names follow Tetragon's policy names (lower-case letters, digits, `.`, `_`
and `-`); levels are 0 to 10; at most 64 entries.

## Parsed fields for filtering

Filters run on the parser's fields before anything becomes evidence:

| Field | Meaning |
| --- | --- |
| `tetragon.event`, `tetragon.policy.name`, `tetragon.function`, `tetragon.action`, `tetragon.message` | event kind, policy, hook (`subsys/event` for tracepoints, the symbol for uprobes), action and message |
| `tetragon.rule`, `tetragon.level`, `tetragon.description`, `tetragon.groups` | the alert as it will be sent |
| `tetragon.exec.kind` | `privilege`, `privilege_child`, `service_shell` or `watched` |
| `process.name`, `process.executable`, `process.pid`, `process.user.id` | the process (account directories replaced) |
| `process.parent.name`, `process.parent.executable`, `process.parent.pid`, `process.parent.user.id` | its parent |
| `tetragon.process.auid`, `tetragon.process.exec_id`, `container.id`, `tetragon.node.name` | login uid, Tetragon's execution ID, Docker container and node |
| `file.path`, `tetragon.file.mask`, `tetragon.file.flags` | the file a hook reported, and how it was accessed |
| `tetragon.module.name`, `tetragon.bpf.program_name`, `tetragon.bpf.program_type` | kernel module and BPF program |
| `destination.ip`, `destination.port` | the connection a socket hook reported |

For example, drop secret reads by a backup job:

```yaml
    exclude_match: all
    exclude_when:
      - field: tetragon.policy.name
        operator: equals
        value: anomaly-secret-reads
      - field: process.name
        operator: equals
        value: restic
```

## Mapping in KEEN

No KEEN server change or Tetragon API access is required. Open an ingested
alert and choose **Create mapping from this event**: match
`action = security.alert.generated` with `ueu.attributes.product = tetragon`
and `ueu.attributes.rule_id`, `category` or `groups`.

For ISO/IEC 27001:2022, for example:

| Evidence | Annex A controls |
| --- | --- |
| secret reads (`/etc/shadow`, SSH keys) | 5.17 Authentication information, 8.3 Information access restriction, 8.16 Monitoring activities |
| writes to account, sudo, cron, systemd or SSH configuration | 8.9 Configuration management, 5.18 Access rights, 8.16 |
| programs run from temporary directories | 8.7 Protection against malware, 8.16 |
| kernel module and BPF program loads | 8.7, 8.19 Installation of software on operational systems |
| shells opening network connections, shells started by services | 8.20 Networks security, 8.16 |
| `privileged.action.completed` from component `tetragon` | 8.2 Privileged access rights |
| starts of `strace`, `gdb`, `tcpdump` or `setcap` | 8.18 Use of privileged utility programs |

Every collected event also supports 8.15 Logging. Choose framework controls
appropriate to your audit purpose.

Reference:
- https://tetragon.io/docs/concepts/events/
- https://tetragon.io/docs/reference/daemon-configuration/
- https://tetragon.io/docs/concepts/tracing-policy/
