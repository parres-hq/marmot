# Push notifications

Status: draft for internal review.

Push notifications let a sender give a recipient a delivery hint outside the normal group-message fetch path.

Push notification support is optional. A group MUST still work when no client supports push notifications.

## Surfaces

- App payload: token gossip event kinds `447`, `448`, and `449`, carried inside ordinary encrypted group messages (see
  "Token gossip event shapes").
- Transport: Nostr push notification rumor kind `446` for the current Nostr binding. Unlike the kinds above, `446` is
  not an inner group payload: it is the rumor inside a separately gift-wrapped trigger addressed to the notification
  server's inbox (see "Notification trigger").
- Group state: no group-state transition.
- Account transport: trigger publish targets are gossiped relay hints, with the server account's inbox relays from the
  Nostr binding as fallback (see "Notification trigger").

No persistent group app component is required for push notifications v1.

## Behavior

A push notification hint MAY tell a recipient that new encrypted group content is available. It MUST NOT carry message
plaintext, media plaintext, MLS secrets, exporter output, or group-state-changing bytes.

Receiving or missing a push notification does not affect group state. The recipient still fetches and processes the
normal Marmot transport messages.

## Notification servers

A notification server is identified by its Nostr public key. That key and an optional relay hint travel inside token
gossip records (see "Token gossip event shapes"); they are per-token data, not group state.

A notification server is an ordinary Nostr account. Its inbox relays are the Nostr binding's account inbox relays
([../transports/nostr.md](../transports/nostr.md)); this feature does not define a server-specific relay-list event
kind.

Each application provides its own notification server's public key, for example as a build-time default. This is
structural, not provisional: Apple and Google require application-level credentials to trigger native push, so a
notification server can only wake the application whose platform push credentials it holds. A server's public key is
therefore tied to the application it serves, and this feature defines no protocol-level server discovery.

## Token encryption

When a device enables native push, it encrypts its platform token to the notification server's Nostr public key.

The current MIP-era encrypted token format is:

```text
TokenPlaintext = platform[1] || token_length[2] || device_token[token_length] || random_padding
EncryptedToken = ephemeral_pubkey[32] || nonce[12] || ciphertext[1040]
```

`TokenPlaintext` is exactly 1024 bytes. `EncryptedToken` is exactly 1084 bytes.

- `platform` is one byte: `0x01` for APNs or `0x02` for FCM. No other value is valid.
- `token_length` is a 2-byte big-endian unsigned integer: the length of `device_token` in bytes, between 1 and 1021
  inclusive.
- `device_token` is the raw platform token bytes.
- `random_padding` is random bytes filling `TokenPlaintext` to exactly 1024 bytes.

The encryption key is derived with secp256k1 ECDH and HKDF-SHA256:

```text
shared_x       = secp256k1_ecdh(ephemeral_privkey, server_pubkey)
prk            = HKDF-SHA256-Extract(salt = "mip05-v1", IKM = shared_x)
encryption_key = HKDF-SHA256-Expand(prk, info = "mip05-token-encryption", 32)
```

The HKDF hash is SHA-256 in both steps. `shared_x` is input keying material passed through Extract with the 8-byte
ASCII salt `mip05-v1`; it is not used as a precomputed PRK. The Expand info is the 22-byte ASCII string
`mip05-token-encryption` with no length prefix, and the output is a 32-byte key.

`server_pubkey` is a 32-byte x-only secp256k1 key. ECDH lifts it to the curve point with even Y, following the BIP-340
convention. `shared_x` is the 32-byte big-endian X coordinate of the resulting shared point, with no Y parity byte and
no hashing before HKDF. `ephemeral_privkey` is a fresh secp256k1 scalar; its x-only public key is the
`ephemeral_pubkey[32]` carried in `EncryptedToken`.

The token is encrypted with ChaCha20-Poly1305, a random 12-byte nonce, and empty AAD. `ciphertext[1040]` is the combined
AEAD output: the 1024-byte ciphertext of `TokenPlaintext` followed by the 16-byte Poly1305 authentication tag as a
suffix (1024 + 16 = 1040). A recipient splits off the trailing 16 bytes as the tag and authenticates before decrypting.

Native platform tokens are required; iOS clients use APNs directly and MUST NOT use FCM as an iOS proxy.

## Token gossip event shapes

Token distribution uses Marmot app events carried inside ordinary group messages:

- kind `447`: token request and self-token update;
- kind `448`: token list response;
- kind `449`: token removal.

These are unsigned Marmot app payloads like all inner app events; the envelope shape is owned by
[../foundation/application-messages.md](../foundation/application-messages.md). This section defines their `content`.

The `content` of each kind is a JSON object carrying a version member `v` that MUST be the string `mip05-v1`. A
recipient MUST reject a payload with any other `v` value, and ignores unknown members. Senders also tag each gossip
event with `["v", "mip05-v1"]`; the content member is the validated value.

### Token entries (kinds 447 and 448)

Kinds `447` and `448` share one content shape:

```json
{
  "v": "mip05-v1",
  "tokens": [
    {
      "member_id_hex": "<64 lowercase hex characters>",
      "leaf_index": 3,
      "platform": "apns",
      "token_fingerprint": "sha256:<24 hex characters>",
      "server_pubkey_hex": "<64 lowercase hex characters>",
      "relay_hint": "wss://relay.example.com",
      "encrypted_token": "<standard base64 of one 1084-byte EncryptedToken>"
    }
  ]
}
```

- `tokens` is an array of token entries. A missing `tokens` member is read as an empty array.
- `member_id_hex` is the owning member's account public key as 32-byte lowercase hex.
- `leaf_index` is the owning device's MLS leaf index as an unsigned-integer JSON number.
- `platform` is the string `apns` or `fcm`.
- `token_fingerprint` is the string `sha256:` followed by the first 24 lowercase hex characters of
  `SHA-256(platform_byte || device_token)`, where `platform_byte` is the one-byte platform value from "Token
  encryption". It names a token in gossip and removals without revealing token bytes.
- `server_pubkey_hex` is the notification server's Nostr public key as 32-byte lowercase hex.
- `relay_hint` is an optional relay URL where the server accepts notification triggers. It is omitted when not set,
  and a recipient treats an empty or whitespace-only value as absent.
- `encrypted_token` is one 1084-byte `EncryptedToken` as standard base64 with padding.

A recipient MUST reject an entry whose `member_id_hex` or `server_pubkey_hex` is not 32-byte lowercase hex, whose
`token_fingerprint` is not `sha256:` followed by exactly 24 hex characters, whose `platform` is unknown, or whose
`encrypted_token` does not decode to exactly 1084 bytes.

### Request and update (kind 447)

A kind `447` event with a non-empty `tokens` array is a self-update: the sender announces its own current token
record, normally as exactly one entry. A kind `447` event whose `tokens` array is empty is a token request: it carries
no records and asks other members to share theirs.

A recipient processes both forms with the same rule — apply every listed entry — so an empty request changes no state.

### List response (kind 448)

A kind `448` event is a response listing the responder's current view of the group's active token records, one entry
per record, including its own. A recipient applies the same entry rule as for kind `447`.

### Removal (kind 449)

```json
{
  "v": "mip05-v1",
  "removals": [
    {
      "member_id_hex": "<64 lowercase hex characters>",
      "leaf_index": 3,
      "platform": "apns",
      "token_fingerprint": "sha256:<24 hex characters>",
      "server_pubkey_hex": "<64 lowercase hex characters>"
    }
  ]
}
```

- `removals` is an array of removal entries. A missing `removals` member is read as an empty array.
- The five members identify the token record being removed and use the encodings defined for token entries. A removal
  entry MUST carry `leaf_index` so it targets exactly one device's record and cannot revoke a sibling leaf's active
  token for the same account, platform, and server.

A recipient deletes the stored token record matching all five values.

### Record state

A device keeps one push registration at a time, so a leaf has at most one active token record. Clients store one token
record per member id, leaf index, platform, and server public key in a group: an incoming entry that matches a stored
record on those four values replaces it — including its fingerprint, relay hint, and encrypted token — and any
other entry inserts a new record. Entries are applied in array order, so a later entry replaces an earlier match.

Token records are local push state, never group state. The rules below order and revoke them so that two members'
clients can converge on the same token set without any of it affecting group validity. None of this ordering touches
MLS state, commit selection, or message validity, and a client MUST NOT reject, delay, or reorder a valid group
message because of a token record's age, absence, or supersession.

#### Record key and ordering primitive

The record key is the tuple `(member_id_hex, leaf_index, platform, server_pubkey_hex)`. At most one active record
exists per key per group. `leaf_index` is part of the key because one Marmot account can participate from multiple MLS
leaves (see [multi-device.md](multi-device.md)); omitting it would collapse sibling devices, letting one leaf's list
entry or removal overwrite or suppress another leaf's active token.

Every kind `447`, `448`, and `449` event carries the unsigned Marmot app-event members from
[../foundation/application-messages.md](../foundation/application-messages.md), including an inner `created_at` and a
content-derived app-event `id`. The ordering primitive for a record key is the pair `(created_at, app-event id)`,
compared as the integer `created_at` first and the lowercase-hex app-event `id` as the lexicographic tie-breaker. The
`created_at` half is the same sender-clock, latest-wins basis that kind `1009` edits use; the app-event `id`
tie-breaker is added here so that records with an equal `created_at` still converge deterministically. It inherits the
trust already placed in the MLS-authenticated sender and is deliberately advisory. A client MUST NOT substitute
transport arrival order, outer transport event ids, relay metadata, or local receive time for this primitive.

A client stamps each stored record with the `(created_at, app-event id)` of the event that last wrote it. Apply an
incoming entry or removal to a record key only when its event's ordering primitive is strictly greater than the stored
stamp for that key; otherwise ignore it as stale. Within a single event the array-order rule above still holds, so the
last matching entry in one event's array wins and shares that event's stamp.

#### Removal and tombstones

A kind `449` removal does not merely delete the matching record: it writes a tombstone for the record key stamped with
the removal event's `(created_at, app-event id)`. A tombstone suppresses any later-arriving but earlier-stamped kind
`447`/`448` entry for that key, so a token list assembled before the removal cannot resurrect a revoked token. A
subsequent kind `447`/`448` entry whose stamp is strictly greater than the tombstone re-establishes an active record
for the key and clears the tombstone.

A tombstone is durable: it persists until a strictly-greater-stamped kind `447`/`448` entry clears it (as above) or
the owning member is removed from the group (see member cleanup below). A client MUST NOT garbage-collect a tombstone
merely because it looks old by wall clock or sender `created_at`: record stamps are sender-supplied and uncorrelated
with MLS epoch, so a later-arriving but earlier-stamped kind `448` could otherwise resurrect a revoked token. A client
MAY drop a tombstone only once the MLS application message that would carry any competing token record can no longer be
accepted — that is, once the carrying epoch falls outside the retained app-payload window defined by
`app_payload_past_epoch_limit` in [../protocol-core/retained-history.md](../protocol-core/retained-history.md). Beyond
that window the application message is rejected outright (`BeyondAnchor`), so no surviving kind `447`/`448` can deliver
a competing record for the key and dropping the tombstone cannot resurrect a revoked token.

#### Race handling

- **Removal versus a stale list response.** A kind `449` and a kind `448` that both reference the same record key are
  resolved by their ordering primitives, not by arrival order. The higher-stamped event wins; a lower-stamped list
  entry is dropped even if it arrives later.
- **Removal versus a stale trigger.** A kind `446` trigger whose target token record has been removed or superseded is
  ignored as a stale trigger (see "Replay and freshness"). The trigger never deletes or mutates a record.
- **Concurrent self-updates.** Two kind `447` self-updates for the same key from re-registration are ordered by their
  primitives; the higher-stamped record is the active one. Equal `created_at` is broken by app-event id, so clients
  converge.
- **Equal stamps.** Two distinct events cannot share an app-event id under the canonical id rule, so the tie-breaker is
  always decisive. An exact-duplicate event (same id) is idempotent: applying it again is a no-op.

When a member is removed from the group, clients delete every stored token record and tombstone for that member as part
of local cleanup. No kind `449` event is required for that cleanup.

## Notification trigger

When a sender wants to wake recipients, it publishes a NIP-59 gift-wrapped event addressed to the notification server:

```text
kind 1059 gift wrap
  kind 13 seal
    unsigned kind 446 Marmot notification rumor
```

The kind `446` rumor contains:

- `content`: one standard-base64 string with one or more concatenated 1084-byte `EncryptedToken` values;
- a `["v", "mip05-v1"]` tag, and no other tag;
- `pubkey`: a fresh ephemeral key.

The content field follows the Nostr transport byte-encoding rule: standard base64 with padding and no `encoding` tag.

The seal is signed by the same ephemeral key used as the rumor `pubkey`. The gift wrap uses a separate ephemeral key
and is addressed to the notification server.

The sender publishes the gift wrap to the relay hints carried in the stored token records for that server. When no
stored record carries a relay hint, the sender publishes to the server account's inbox relays from the Nostr binding
([../transports/nostr.md](../transports/nostr.md)).

### Replay and freshness

A kind `446` trigger is a delivery hint, not group data. Replaying, dropping, duplicating, or reordering triggers MUST
NOT affect group state and MUST NOT make any valid group message invalid. All handling below is local push hygiene.

A notification server SHOULD deduplicate incoming triggers. The dedup key is the kind `446` rumor's content hash —
`SHA-256` over the decoded trigger content (the concatenated `EncryptedToken` bytes), not the outer gift-wrap event id,
which a replayer can change freely by re-wrapping. A server that has already acted on a content hash within its
retention window SHOULD ignore a later trigger with the same hash rather than wake the recipient again. Because the
outer wrap uses a fresh ephemeral key per publish, the server MUST NOT rely on the outer event id for dedup.

A server MUST treat a trigger whose target token record it can no longer match — because the token was removed,
superseded by a newer record, or never registered — as a stale trigger and ignore it. A stale or replayed trigger never
mutates token state; only kind `447`/`448`/`449` group events do, under "Record state".

A client that receives a redundant or stale wake performs a silent fetch and returns to sleep (see "Decoys and
batching"); duplicate wakes are expected and are never surfaced as errors.

### Server retention

Trigger material is ephemeral. A notification server retains a decoded trigger and its content-hash dedup entry only as
long as needed to deliver the wake and suppress immediate replays — a short bound measured in minutes, not a durable
log. A server MUST NOT retain decrypted device tokens beyond the active push registration it needs them for, and MUST
NOT persist trigger plaintext, group identifiers, or recipient linkage derived from a trigger. A server holds no group
state and learns nothing about group membership or message content from a trigger; the only material it needs is the
platform token it decrypts to dispatch the native push.

## Decoys and batching

Clients SHOULD batch notifications for a short period and include decoy tokens when possible. Decoys are valid encrypted
tokens from other groups or the sender's own token, not random bytes. Random bytes are distinguishable because they fail
curve or AEAD validation.

Silent wakes that lead to no new messages are expected. Clients SHOULD fetch, find nothing, and return to sleep without
showing user-facing errors.

## Validation

A client MUST treat malformed push notification data as advisory failure. It MUST NOT reject valid group messages
because a related push hint was missing, delayed, duplicated, or malformed.

### Advisory push hygiene versus protocol-invalid group data

Push notifications draw a sharp line between two failure classes:

- **Advisory push hygiene.** Everything in this document — a malformed or unsupported token entry, a removal that
  matches no record, a stale or replayed kind `446` trigger, a token list that loses an ordering race, a missing relay
  hint, a failed token decrypt at the server — is advisory. The correct response is to drop the offending datum and
  continue. None of it rejects a group message, mutates group state, or changes which commit wins. A single bad entry
  in a kind `447`/`448`/`449` event is dropped on its own; the rest of the array still applies and the carrying group
  message remains valid.
- **Protocol-invalid group data.** The only protocol-invalid conditions are the ones the owning foundation/transport
  docs already define for the carrying surface: an inner app payload whose canonical app-event `id` does not match its
  bytes, a forbidden `sig` member, or a duplicate object key (see
  [../foundation/application-messages.md](../foundation/application-messages.md)). Those are decided by the app-payload
  decoder, not by this feature, and they are not specific to push. This feature adds no new way for push content to
  invalidate a group message.

Put plainly: kind `447`/`448`/`449` are ordinary unsigned Marmot app events, so they share the app payload's
validity rules; their push-specific `content` checks below only decide whether an individual token entry or removal is
applied, never whether the group message is valid.

A recipient applies the per-field rejection rules in "Token entries" and "Removal" at the entry granularity: reject the
individual entry, keep processing the rest, and never let an entry failure propagate to group-message validity.

Notification servers MUST reject or ignore malformed notification triggers, including:

- missing or unsupported `v` tags;
- invalid base64 content;
- decoded content whose length is not a multiple of 1084 bytes;
- token chunks with invalid ephemeral keys, failed ECDH/HKDF, failed AEAD authentication, invalid platform bytes, or
  invalid token lengths.

## Migration notes

MIP-05 is still Draft in the merged MIP set. This feature SHOULD stay optional and MUST NOT change group state.

This document supersedes the MIP-05 draft event shapes where they differ. The MIP-05 draft carried token gossip in
`token` tags with empty content, left the sender's leaf implicit, defined no removal entries, and required an
`["encoding", "base64"]` tag on the kind `446` rumor. The shapes above — JSON content with explicit member ids, leaf
indexes, fingerprints, and removal entries, and a kind `446` rumor whose only tag is `v` — are the interop surface.
