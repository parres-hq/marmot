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
      "platform": "apns",
      "token_fingerprint": "sha256:<24 hex characters>",
      "server_pubkey_hex": "<64 lowercase hex characters>"
    }
  ]
}
```

- `removals` is an array of removal entries. A missing `removals` member is read as an empty array.
- The four members identify the token record being removed and use the encodings defined for token entries.

A recipient deletes the stored token record matching all four values.

### Record state

A device keeps one push registration at a time, so a leaf has at most one active token record. Clients store one token
record per member id, platform, and server public key in a group: an incoming entry that matches a stored record on
those three values replaces it — including its leaf index, fingerprint, relay hint, and encrypted token — and any
other entry inserts a new record. Entries are applied in array order, so a later entry replaces an earlier match.

When a member is removed from the group, clients delete every stored token record for that member as part of local
cleanup. No kind `449` event is required for that cleanup.

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

## Decoys and batching

Clients SHOULD batch notifications for a short period and include decoy tokens when possible. Decoys are valid encrypted
tokens from other groups or the sender's own token, not random bytes. Random bytes are distinguishable because they fail
curve or AEAD validation.

Silent wakes that lead to no new messages are expected. Clients SHOULD fetch, find nothing, and return to sleep without
showing user-facing errors.

## Validation

A client MUST treat malformed push notification data as advisory failure. It MUST NOT reject valid group messages
because a related push hint was missing, delayed, duplicated, or malformed.

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
