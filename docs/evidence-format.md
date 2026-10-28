# KEEN's evidence format: the UEU profile `0.1-keen`

KEEN Agent sends evidence as Universal Evidence Utility (UEU) envelopes. This
document specifies KEEN's profile of the draft UEU specification: the envelope,
event catalogues, canonical form, hashing, chaining, batch signatures, the
OTLP binding, and the agent identity protocol (enrolment, renewal and request
signatures). KEEN's receiver implements the same rules, and
`internal/ueu/testdata/vectors.json` pins byte-exact examples that both
implementations must reproduce.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Terms

- **Producer**: the component that creates and signs envelopes. For KEEN Agent,
  one enrolled agent identity.
- **Envelope**: one evidence record: something observed (a measured state) or
  something that happened (an event).
- **Event type**: a dotted name such as `endpoint.screen_lock.observed`, defined
  by an event catalogue.
- **Catalogue**: an implementor's vocabulary of event types and their fields.
- **Stream**: the sequence of envelopes one producer chains together.
- **Batch**: the envelopes sent in one request, listed in a signed manifest.

## 2. Envelope

An envelope is a JSON object with exactly these members (`?` marks optional
members). Unknown members are invalid.

| Member | Type and constraints |
| --- | --- |
| `ueu_spec_version` | `"0.1-keen"` |
| `evidence_id` | UUIDv7 (RFC 9562), lower-case canonical form |
| `event_type` | `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$`, defined by the catalogue |
| `catalogue` | `{"id": …, "version": …}` naming the catalogue that defines the type |
| `event_time` | when the state was observed or the event happened (section 5) |
| `evidence_time` | when the producer sealed the envelope (section 5) |
| `source` | `{"application_id", "application_version", "component", "instance_id"}`: the producing software, its sub-component (collector or provider, at most 256 bytes) and the producer instance (the agent ID) |
| `asset` | `{"asset_type", "platform", "identifier"}`: what the evidence describes, for KEEN Agent `server` or `workstation`, `linux`, `windows` or `darwin`, and the agent ID |
| `event` | `{"action", "object_type", "outcome", "reason_code"}`; `outcome` is one of `observed`, `unknown`, `success`, `failure`, `info`; `object_type` matches the catalogue |
| `context?` | correlation identifiers only: `transaction_id`, `trace_id`, `span_id`, `correlation_id`, `session_id`, `workflow` (strings of at most 128 characters from `[A-Za-z0-9_.:@/+=-]`), `parent_evidence_id` and `related_evidence_ids` (evidence IDs, at most 16) |
| `subject?` | `{"identifier_type": "pairwise" \| "public", "identifier": "hmac-sha256:<64 hex>"}` (section 6) |
| `observation?` | for observation types: `{"method", "scope", "valid_for_seconds", "facts"}`; `outcome` MUST be `observed` |
| `attributes?` | for event types: typed fields (section 3) |
| `evidence` | `{"payload_included": bool, "payload"?, "payload_hash"?, "supporting_record_reference"?, "collection_mode"?}` |
| `privacy` | `{"profile": "keen-default-1", "personal_data_included": false, "transformations": [...]}` |
| `mappings` | producer-suggested framework mappings; KEEN Agent sends `[]` |
| `integrity` | `{"canonicalisation": "RFC8785", "hash_algorithm": "SHA-256", "stream", "sequence", "previous_evidence_hash"}` (section 7) |

An envelope carries exactly one of `observation` and `attributes`, matching its
type's class.

`evidence.payload` is the source record (a redacted log line, at most 60,000
bytes) and is present exactly when `payload_included` is true.
`evidence.payload_hash` is `sha256:<hex>` of the source record and is sent
whenever there is one, so a reviewer holding the original log can match it
without the line being sent. `supporting_record_reference` locates the source
record on the producer (`file:<path>@<offset>` or `journal:<cursor>`, at most
512 bytes). `collection_mode` records the evidence mode the producer applied
(section 10).

`privacy.personal_data_included` is `false` for envelopes without a payload:
their structured fields carry no personal data, which is replaced at source by
pseudonymous subjects. An included payload is a redacted source record that can
still name people, addresses or hosts, so an envelope with a payload sets it to
`true`; a receiver MUST reject `true` without a payload. `privacy.transformations` records what the
producer changed, from this vocabulary only (at most 64 entries):

- `subject-pseudonymised`: a local account identifier became `subject`;
- `removed:<field>:<reason>`: a field was left out, with `<reason>` one of
  `prohibited`, `undeclared`, `invalid_name`, `invalid_<type>` or
  `too_many_fields`; a field whose name is itself invalid is recorded as
  `unnamed`, and `removed:further_fields:truncated` ends a list that reached
  its limit.

A serialised envelope MUST NOT exceed 64 KiB.

## 3. Catalogues

A catalogue names its event types and, for each, its class, the fields it may
carry and the fields it must never carry. UEU recommends catalogues and leaves
the vocabulary to implementors; envelopes name the catalogue they follow.
KEEN's catalogue is `internal/ueu/catalogue/keen-2026.10.json`
(`{"id": "keen", "version": "2026.10"}`), shipped identically in KEEN.

Each event type declares:

| Property | Meaning |
| --- | --- |
| `class` | `observation` (a measured state) or `event` (something that happened) |
| `object_type` | what the envelope is about; repeated in `event.object_type` |
| `summary` | a display template; `{component}`, `{scope}`, `{reason_code}`, `{outcome}`, `{action}`, `{attributes.X}` and `{facts.X}` are replaced |
| `facts` or `attributes` | declared fields with a `type` and an optional `classification` |
| `additional_facts` / `additional_attributes` | `reject` (default) or `scalar_string`: undeclared fields are refused, or allowed as strings |
| `prohibited` | field names that MUST NOT appear |
| `subject` | `forbidden`, `optional` or `required` |
| `payload` | `forbidden`, `optional` or `required` |

Field types and their JSON forms:

| Type | JSON | Limits |
| --- | --- | --- |
| `boolean` | `true` / `false` | |
| `integer` | integer | within ±(2^53 − 1) |
| `string` | string | at most 1,024 bytes |
| `timestamp` | RFC 3339 string | at most 64 characters |
| `string_list` | array of strings | at most 64 items of at most 256 bytes |

An envelope carries at most 48 facts or attributes, with names matching
`^[a-z][a-z0-9_.]{0,63}$`.

Classifications are `evidence_metadata` (measured settings, states, counts and
times), `operational` (names of software, services and configuration needed to
interpret the evidence) and `security_sensitive` (detail sent only where a type
allows it). The classifications `personal_data` and `authentication_secret`
exist in the vocabulary only to be refused: a catalogue that declares a field
with either is invalid.

Facts are measurements or absent: a collector that cannot measure a setting
omits the fact (and an observation that measured nothing is not sent; the
coverage record reports it instead, section 8). Values are never guessed or
defaulted.

## 4. Canonical form

The canonical form of an envelope, manifest or signed statement is its RFC
8785 (JSON Canonicalization Scheme) serialisation, restricted as follows:

- numbers MUST be integers within ±(2^53 − 1), so no floating-point formatting
  arises;
- nesting MUST NOT exceed 32 levels;
- strings MUST be valid Unicode (no lone surrogates);
- object member names MUST be unique.

Members are ordered by their UTF-16 code units; strings escape `"`, `\`,
`\b`, `\f`, `\n`, `\r`, `\t` and other characters below U+0020 as `\u00xx`
with lower-case hexadecimal, and emit every other character as UTF-8.

A receiver MUST reject an envelope whose received text differs from the
canonical form of its parsed value, so the bytes stored are the bytes hashed.

## 5. Identifiers and times

`evidence_id` is a UUIDv7 generated when the envelope is built; its time
prefix orders identifiers by creation. Times use the form
`YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC, milliseconds). A receiver MAY reject
`event_time` before 2000 or more than five minutes ahead of its clock, so a
producer records an event dated more than a minute ahead of its own clock at
the time it collected it.

## 6. Subjects

Local account identifiers (Unix user names and IDs, Windows SIDs) never leave
the device. The producer replaces them with

    identifier = "hmac-sha256:" + hex(HMAC-SHA256(key, "keen-ueu-subject-v1" || 0x00 || kind || 0x00 || value))

where `kind` names the identifier type (`unix_uid`, `unix_user`,
`windows_sid`). The key determines the subject type:

- **pairwise**: a 32-byte key generated on the device and never sent. The
  same account on two devices yields unrelated pseudonyms.
- **public**: a 32-byte key KEEN issues to every agent configured for public
  subjects. The same account yields the same pseudonym on each such device.

KEEN chooses the type per agent identity or enrollment profile and tells the
agent at enrolment and renewal.

## 7. Integrity

The **evidence hash** is `sha256:` followed by the hexadecimal SHA-256 of the
envelope's canonical form.

Each producer chains its envelopes in one stream: `integrity.stream` is the
producer instance (the agent ID), `integrity.sequence` counts from 1 and
`integrity.previous_evidence_hash` is the evidence hash of the stream's
previous envelope (`null` for sequence 1 only). The producer assigns the
sequence and seals the envelope in the same durable transaction that queues
it, so a crash cannot reuse or skip a position.

A receiver compares each envelope with the last one it accepted from that
stream and records one of: `started` (first sequence), `continuous` (next
sequence, matching previous hash), `broken` (next sequence, different previous
hash), `gap` (later sequence), `restarted` (sequence 1 after others) or
`out_of_order` (earlier sequence).

## 8. Records about collection

Producers account for their own collection with two event types:

- `evidence.collection.completed`: sent after each posture run, listing the
  checks attempted, observed and unavailable and the probes that could not
  run. A receiver can therefore distinguish "not measured" from "measured and
  failing".
- `evidence.records.discarded`: sent when queued evidence is discarded (queue
  expiry under `retention_days`, or an explicit purge), with the reason, the
  count and the first and last sequence numbers discarded. It accounts for the
  resulting gap in the chain.

## 9. Batches and the OTLP binding

A batch is sent as one OTLP/HTTP JSON logs request (`application/json`) with
one resource. Each log record carries one envelope:

- `body`: `{"stringValue": <the envelope's canonical text>}`;
- `timeUnixNano`: the event time;
- `severityNumber`: 13 (WARN) for `failure`, otherwise 9 (INFO);
- attributes `event.name` (the event type), `ueu.spec_version` and
  `ueu.evidence_id`.

Resource attributes: `service.name`, `service.version`,
`ueu.producer.instance_id` and, for a signed batch, `ueu.batch.manifest`,
`ueu.batch.signature` and `ueu.batch.key_id`.

The **manifest** is the canonical form of

```json
{"context": "keen-ueu-batch-v1",
 "evidence": [{"evidence_hash": "sha256:…", "evidence_id": "…"}, …],
 "issued_at": "…",
 "key_id": "…",
 "producer": "<agent id>"}
```

listing every envelope in the batch, in record order. The signature is
Ed25519 over the manifest's bytes, encoded as unpadded base64url. The
signature therefore covers every envelope through its hash; OTLP attributes
outside the manifest and the bodies are hints only.

A receiver:

- rejects the whole request if a manifest is present but malformed, does not
  list exactly the batch's envelopes, or carries a signature that fails with
  the named key when it holds that key;
- accepts a batch without a manifest as `unsigned`, and a batch signed with a
  key it does not hold as `unknown_key`, recording that on each envelope;
- records `verified` (or `revoked_key` for a key since revoked) otherwise.

## 10. Evidence modes

Each server log source chooses what becomes evidence:

| Mode | Sent |
| --- | --- |
| `events` | recognised events; source lines as `payload_hash` and reference only |
| `events_with_lines` | recognised events with `payload` included |
| `all_lines` | as above, plus every other line as `log.line.collected` (payload required) |

KEEN sets the most each identity may send (its evidence mode ceiling) and
tells the agent at enrolment and renewal. The agent reduces a source asking
for more and reports that in health. KEEN also enforces the ceiling on
receipt: above it, an included payload is removed and recorded in the custody
record, and `log.line.collected` envelopes are not stored (their chain
positions are still recorded).

## 11. Agent identity

### Keys

Each agent holds one Ed25519 key pair, generated on the device and kept in its
private state (`identity.json`, mode 0600, or a SYSTEM-only file on Windows).
KEEN stores only public keys. A key's identifier is

    key_id = <agent id> + ":" + first 16 hex digits of SHA-256(raw 32-byte public key)

Public keys are sent as unpadded base64url of the raw 32 bytes.

### Enrolment

`POST /v1/agents/enroll` with `Authorization: Bearer <credential>`, where the
credential is a single-use enrolment code (`kc_<agent id>.<43 base64url>`,
valid for 24 hours) issued for a registered identity, or an enrollment
profile's bootstrap key (`ke_<profile id>.<43 base64url>`). Body:

```json
{"public_key": "…", "proof": "…", "name": "…", "nonce": "…"}
```

`name` and `nonce` (32 random bytes, unpadded base64url, saved privately
before the first attempt) are required for profile enrolment and absent for
codes. `proof` is an Ed25519 signature by the new key over the canonical form
of

```json
{"context": "keen-agent-enroll-v1",
 "credential_sha256": "<hex SHA-256 of the credential>",
 "public_key": "…"}
```

which proves possession of the key and binds it to that credential. A retry
with the same code (or the same profile, name, nonce) and the same key returns
the same binding; another key is refused. The response (the **grant**):

```json
{"agent": {"id", "name", "agent_type", "enrollment_profile_id", "expires_at", "enabled"},
 "key_id": "…",
 "subject": {"type": "pairwise"} | {"type": "public", "key": "<32 bytes, base64url>"},
 "evidence_mode_ceiling": "events" | "events_with_lines" | "all_lines",
 "catalogue": {"id": "keen", "version": "2026.10"}}
```

The agent checks that `key_id` names the key it holds before saving the grant.
A new enrolment with a fresh code retires the identity's previous key.

### Request signatures

Every other agent request is signed with RFC 9421 HTTP Message Signatures:

    Content-Type: application/json
    Content-Digest: sha-256=:<base64 SHA-256 of the body>:
    Keen-Agent-Operation: otlp-logs | heartbeat | renew
    Signature-Input: keen=("@method" "keen-agent-operation" "content-digest" "content-type");created=<unix seconds>;keyid="<key id>";nonce="<16 random bytes, base64url>";alg="ed25519"
    Signature: keen=:<base64 Ed25519 signature>:

over the signature base

    "@method": POST
    "keen-agent-operation": <operation>
    "content-digest": <Content-Digest value>
    "content-type": application/json
    "@signature-params": <Signature-Input value after "keen=">

KEEN accepts a signature only within five minutes of `created`, only once per
nonce, only for the endpoint matching its operation, and only with the
identity's active key; it compares the body with `Content-Digest` after
reading it.

### Renewal

Before the key expires (at the later of seven days before expiry and four
fifths of its lifetime), the agent generates a new key pair and a fresh nonce,
saves both privately, and sends a request signed with the current key
(operation `renew`) to `POST /v1/agents/renew`:

```json
{"public_key": "<new key>", "nonce": "…", "proof": "…"}
```

with `proof` by the new key over the canonical form of

```json
{"context": "keen-agent-renew-v1", "agent_id": "…", "previous_key_id": "…", "public_key": "…"}
```

KEEN binds the new key, retires the old one and returns a grant. For 24 hours
the retired key and the same nonce can repeat the request after a lost
response and receive the same grant.

## 12. Receiver results and errors

KEEN stores each accepted envelope with a provenance record: the evidence
hash, batch verification, chain status, catalogue validation (`valid`, or
`catalogue_unknown` for a catalogue KEEN does not hold, which is accepted with
structural checks) and a custody record. KEEN redacts stored text with its
usual rules but keeps typed booleans, integers and timestamps whatever their
names; when anything changes, the custody record lists each changed path and
the reason and keeps the original evidence hash.

Rejections carry these codes:

| Code | Meaning |
| --- | --- |
| `UEU_CANONICALISATION_FAILED` | the body is not the canonical form of valid JSON in this profile |
| `UEU_SPEC_VERSION_UNSUPPORTED` | not `0.1-keen` |
| `UEU_SCHEMA_VALIDATION_FAILED` | structure, types, limits or class do not match |
| `UEU_EVENT_TYPE_UNKNOWN` | the type is not in its (known) catalogue |
| `UEU_PROHIBITED_FIELD_DETECTED` | a prohibited field, or a subject or payload the type forbids |
| `UEU_PRIVACY_POLICY_FAILED` | `personal_data_included` is true without an included payload |
| `UEU_EVIDENCE_VERIFICATION_FAILED` | the manifest or its signature does not verify |

## 13. Test vectors

`internal/ueu/testdata/vectors.json` holds, for the Ed25519 seed `0x42` × 32
and the subject key `0x07` × 32: the public key and key ID, a sealed
observation envelope (canonical text and evidence hash), a signed manifest, a
subject pseudonym with its inputs, and a signed heartbeat request (body,
digest, signature input, base and signature). `go test ./internal/ueu`
reproduces them; KEEN's `services/api/tests/test_ueu_evidence.py` checks its
own implementation against the same file.
