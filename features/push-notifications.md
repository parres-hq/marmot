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

The encrypted token format is:

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
prk            = HKDF-SHA256-Extract(salt = "marmot-push-token-v1", IKM = shared_x)
encryption_key = HKDF-SHA256-Expand(prk, info = "marmot-push-token-encryption", 32)
```

The HKDF hash is SHA-256 in both steps. `shared_x` is input keying material passed through Extract with the 20-byte
ASCII salt `marmot-push-token-v1`; it is not used as a precomputed PRK. The Expand info is the 28-byte ASCII string
`marmot-push-token-encryption` with no length prefix, and the output is a 32-byte key.

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

The `content` of each kind is a JSON object carrying a version member `v` that MUST be the string `marmot-push-v1`. A
recipient MUST reject a payload with any other `v` value, and ignores unknown members. Senders also tag each gossip
event with `["v", "marmot-push-v1"]`; the content member is the validated value.

### Token entries (kinds 447 and 448)

Kinds `447` and `448` share one content shape:

```json
{
  "v": "marmot-push-v1",
  "tokens": [
    {
      "member_id_hex": "<64 lowercase hex characters>",
      "leaf_index": 3,
      "platform": "apns",
      "token_fingerprint": "sha256:<24 hex characters>",
      "server_pubkey_hex": "<64 lowercase hex characters>",
      "relay_hint": "wss://relay.example.com",
      "encrypted_token": "<standard base64 of one 1084-byte EncryptedToken>",
      "owner_ts": 1735680000000,
      "owner_sig": "<128 lowercase hex characters>"
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
- `owner_ts` is the owning member's claimed Unix time in milliseconds as an unsigned-integer JSON number. It is the
  owner-signed ordering stamp for this record (see "Owner authentication" and "Record key and ordering primitive"); a
  recipient MUST NOT substitute the carrying event's `created_at` for it.
- `owner_sig` is the owner's BIP-340 Schnorr signature over the record, as 64-byte (128 lowercase hex character)
  signature bytes (see "Owner authentication"). It binds every other field to `member_id_hex`, so the record stays
  verifiable no matter which member relays it.

A recipient MUST reject an entry whose `member_id_hex` or `server_pubkey_hex` is not 32-byte lowercase hex, whose
`token_fingerprint` is not `sha256:` followed by exactly 24 hex characters, whose `platform` is unknown, whose
`encrypted_token` does not decode to exactly 1084 bytes, whose `owner_sig` is not 64-byte lowercase hex, or whose
`owner_sig` does not verify under "Owner authentication".

### Owner authentication

Each token entry and each removal entry is self-authenticated by the member that owns it, independent of the member
that carries it. This lets one member relay another member's records (see "List response") so a group converges on the
full token set without requiring every owner to be online, while preventing a relaying member from forging, repointing,
or rolling back another member's routing.

An owner signs the canonical byte string

```text
SignedRecord = domain_tag
            || group_id_len[2]            big-endian u16
            || group_id[group_id_len]     the carrying group's MLS group id
            || member_id[32]
            || leaf_index[4]              big-endian u32
            || platform_byte[1]
            || server_pubkey[32]
            || token_fingerprint[12]      the 12 bytes the sha256: prefix encodes
            || owner_ts[8]                big-endian u64, milliseconds
            || relay_hint_len[2]          big-endian u16, 0 when absent
            || relay_hint[relay_hint_len] UTF-8 bytes of the relay hint, empty when absent
            || encrypted_token[1084]      removal entries omit this field
```

`domain_tag` is the 27-byte ASCII string `marmot-push-token-record-v1` for token entries (kinds `447`/`448`) and the
28-byte ASCII string `marmot-push-token-removal-v1` for removal entries (kind `449`); a removal omits the trailing
`encrypted_token`. `group_id` is the raw MLS group id of the carrying group and is length-prefixed because the MLS group
id is variable-length. `member_id` and `server_pubkey` are the raw 32-byte values the corresponding hex fields encode
(both are Nostr x-only public keys). The signature is a BIP-340 Schnorr signature over `SHA-256(SignedRecord)`, produced
with the secret key for `member_id_hex` and carried as `owner_sig`.

A recipient verifies `owner_sig` against `member_id_hex` over the same canonical bytes, reconstructing `group_id` from
the carrying group message. An entry whose signature does not verify is dropped as advisory-invalid and never mutates
`group_push_tokens`. Because the signature binds `group_id`, `server_pubkey_hex`, `relay_hint`, `encrypted_token`, and
`owner_ts`, a relaying member cannot move the record to another group, repoint it at a different notification server or
relay, swap the token, or restamp it. The carrying event stays an ordinary unsigned Marmot app payload (it MUST NOT
carry a `sig` member, see "Validation"); `owner_sig` lives inside each record, not on the event.

A record's authority comes only from `owner_sig` and current group membership, not from the carrying event's sender. A
recipient applies a verified entry regardless of whether `message.sender` equals `member_id_hex`, but MUST still drop
any entry — verified or not — whose `member_id_hex` is not a current group member.

### Request and update (kind 447)

A kind `447` event with a non-empty `tokens` array is a self-update: the sender announces its own current token
record, normally as exactly one entry. A kind `447` event whose `tokens` array is empty is a token request: it carries
no records and asks other members to share theirs.

A recipient applies each listed entry that passes "Owner authentication" and names a current member, and ignores the
rest, so an empty request changes no state. A self-update normally signs over `message.sender`'s own `member_id_hex`,
but the apply decision is the signature check, not a sender-equality check.

### List response (kind 448)

A kind `448` event is a response listing the responder's current view of the group's active token records, one entry
per record, including records the responder learned from other members. Each entry carries the original owner's
`owner_sig` and `owner_ts`, so a recipient applies it under the same "Owner authentication" rule as kind `447`: any
entry whose owner signature verifies and whose `member_id_hex` is a current member is applied, even when the responder
is not its owner. Entries that fail verification or name a non-member are dropped. To relay another member's record, a
responder MUST reproduce that member's `owner_sig` and `owner_ts` unchanged; it cannot mint records for members whose
signatures it does not hold.

### Removal (kind 449)

```json
{
  "v": "marmot-push-v1",
  "removals": [
    {
      "member_id_hex": "<64 lowercase hex characters>",
      "leaf_index": 3,
      "platform": "apns",
      "token_fingerprint": "sha256:<24 hex characters>",
      "server_pubkey_hex": "<64 lowercase hex characters>",
      "owner_ts": 1735680000000,
      "owner_sig": "<128 lowercase hex characters>"
    }
  ]
}
```

- `removals` is an array of removal entries. A missing `removals` member is read as an empty array.
- The first five members identify the token record being removed and use the encodings defined for token entries. A
  removal entry MUST carry `leaf_index` so it targets exactly one device's record and cannot revoke a sibling leaf's
  active token for the same account, platform, and server.
- `owner_ts` and `owner_sig` are the owner-signed ordering stamp and signature, using the removal `domain_tag` and the
  removal `SignedRecord` form (no `encrypted_token`) from "Owner authentication".

A recipient deletes the stored token record for the removal's record key (`member_id_hex`, `leaf_index`, `platform`,
`server_pubkey_hex`) only when the removal passes "Owner authentication", `member_id_hex` is a current member, and the
removal wins the record key's ordering primitive (see "Record key and ordering primitive"). A removal that fails
verification, names a non-member, or loses the ordering race is dropped as advisory-invalid.

The `token_fingerprint` is part of the owner-signed `SignedRecord`, so it is authenticated and states which token
instance the owner intends to revoke, but it is **not** part of the record key and does not gate the delete: the
`(owner_ts, record digest)` stamp is the single arbiter of which write to a record key wins. This is deliberate. A
removal only deletes a record older than itself (it must win the ordering race), so the realistic re-registration race —
an old token, its removal, and a newer token with a different fingerprint on the same key — converges correctly on the
newest record by stamp alone, and a relayed stale removal can never revoke a newer token because it loses the race. A
fingerprint-gated delete would not improve this and would weaken tombstones (a fingerprint-scoped tombstone could not
suppress a differently-fingerprinted stale record from resurrecting the key).

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

Each entry carries its owner's `owner_ts` and `owner_sig` (see "Owner authentication"). The ordering primitive for a
record key is the pair `(owner_ts, record digest)`, compared as the integer `owner_ts` first and the lowercase-hex
`SHA-256(SignedRecord)` as the tie-breaker. The `owner_ts` half is an owner-supplied, latest-wins clock; the digest
tie-breaker makes two distinct records with an equal `owner_ts` converge deterministically. The primitive lives inside
the owner-signed bytes, so it inherits the trust of `owner_sig` rather than the carrying event's sender, and it stays
deliberately advisory. A client MUST NOT substitute the carrying event's `created_at`, transport arrival order, outer
transport event ids, relay metadata, or local receive time for this primitive. Using `owner_ts` rather than the
carrying `created_at` is what makes the primitive relay-safe: a member relaying another member's record in a kind `448`
cannot advance or rewind that record's position, because it cannot re-sign `owner_ts`.

A client stamps each stored record with the `(owner_ts, record digest)` of the entry that last wrote it. Apply an
incoming entry or removal to a record key only when its ordering primitive is strictly greater than the stored stamp
for that key; otherwise ignore it as stale. Within a single event the array-order rule above still holds, but ordering
is decided per entry by its own primitive, so a lower-stamped entry never overwrites a higher-stamped one even when it
appears later in the array.

#### Removal and tombstones

A kind `449` removal does not merely delete the matching record: it writes a tombstone for the record key stamped with
the removal entry's `(owner_ts, record digest)`. A tombstone suppresses any later-arriving but earlier-stamped kind
`447`/`448` entry for that key, so a token list assembled before the removal cannot resurrect a revoked token. A
subsequent kind `447`/`448` entry whose stamp is strictly greater than the tombstone re-establishes an active record
for the key and clears the tombstone.

A tombstone is durable: it persists until a strictly-greater-stamped kind `447`/`448` entry clears it (as above) or
the owning member is removed from the group (see member cleanup below). It MUST NOT be garbage-collected on any
wall-clock, `owner_ts`, or MLS-epoch basis. Owner authentication makes records relay-portable: any current member can
re-emit another member's still-valid `owner_sig`/`owner_ts` record inside a fresh, in-window kind `448` at any later
epoch. So a tombstone (and, equivalently, the stored ordering stamp for a live record) is the only durable high-water
mark that stops a relayed but stale signed record from resurrecting a revoked or superseded token, and it cannot be
bounded by the retained app-payload window: unlike a record that could only ever arrive in its original carrying epoch,
a relayed record's carrying epoch is unbounded. The per-key stamp and tombstone therefore persist for the owning
member's whole lifetime in the group, and are cleared only when that member leaves (see member cleanup below).

#### Race handling

- **Removal versus a stale list response.** A kind `449` and a kind `448` that both reference the same record key are
  resolved by their ordering primitives, not by arrival order. The higher-stamped event wins; a lower-stamped list
  entry is dropped even if it arrives later.
- **Removal versus a stale trigger.** A kind `446` trigger whose target token record has been removed or superseded is
  ignored as a stale trigger (see "Replay and freshness"). The trigger never deletes or mutates a record.
- **Concurrent self-updates.** Two kind `447` self-updates for the same key from re-registration are ordered by their
  primitives; the higher-stamped record is the active one. Equal `owner_ts` is broken by the record digest, so clients
  converge.
- **Equal stamps.** Two records that differ in any signed field have distinct digests, so the tie-breaker is decisive.
  Two entries with the same `owner_ts` and the same digest are the same signed record: applying it again is idempotent,
  whether it arrives as a fresh self-update or relayed in a kind `448`.

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
- a `["v", "marmot-push-v1"]` tag, and no other tag;
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

- **Advisory push hygiene.** Everything in this document — a malformed or unsupported token entry, an entry whose
  `owner_sig` fails to verify or names a non-member, a removal that matches no record, a stale or replayed kind `446`
  trigger, a token list that loses an ordering race, a missing relay hint, a failed token decrypt at the server — is
  advisory. The correct response is to drop the offending datum and continue. None of it rejects a group message,
  mutates group state, or changes which commit wins. A single bad entry in a kind `447`/`448`/`449` event is dropped on
  its own; the rest of the array still applies and the carrying group message remains valid. In particular, an
  `owner_sig` that fails verification fails the entry, never the carrying group message.
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

## Status and interop surface

Push notifications are an optional feature. A group MUST keep working when no member supports them, and nothing in this
document changes group state.

The `marmot-push-v1` shapes above are the interop surface: JSON content with explicit member ids, leaf indexes,
fingerprints, owner-signed token and removal entries, and a kind `446` rumor whose only tag is `v`. Earlier exploratory
drafts that carried token gossip in `token` tags with empty content, left the sender's leaf implicit, defined no
removal entries, or required an `["encoding", "base64"]` tag on the kind `446` rumor are not interoperable with this
version and predate the owner-authentication and per-record ordering rules; clients MUST reject any `v` other than
`marmot-push-v1`.
