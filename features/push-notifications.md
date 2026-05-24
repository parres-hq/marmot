# Push notifications

Status: draft for internal review.

Push notifications let a sender give a recipient a delivery hint outside the normal group-message fetch path.

Push notification support is optional. A group must still work when no client supports push notifications.

## Surfaces

- App payload: token gossip event kinds `447`, `448`, and `449`.
- Transport: Nostr push notification rumor kind `446` for the current Nostr binding.
- State machine: no group-state transition.
- Account transport: notification server relay discovery through kind `10050`.

No persistent group app component is required for push notifications v1.

## Behavior

A push notification hint may tell a recipient that new encrypted group content is available. It MUST NOT carry message
plaintext, media plaintext, MLS secrets, exporter output, or group-state-changing bytes.

Receiving or missing a push notification does not affect group state. The recipient still fetches and processes the
normal Marmot transport messages.

## Token encryption

When a device enables native push, it encrypts its platform token to the notification server's Nostr public key.

The current MIP-era encrypted token format is:

```text
TokenPlaintext = platform[1] || token_length[2] || device_token[token_length] || random_padding
EncryptedToken = ephemeral_pubkey[32] || nonce[12] || ciphertext[1040]
```

`TokenPlaintext` is exactly 1024 bytes. `EncryptedToken` is exactly 1084 bytes.

The encryption key is derived with secp256k1 ECDH and HKDF:

```text
shared_x       = secp256k1_ecdh(ephemeral_privkey, server_pubkey)
prk            = HKDF-Extract(salt = "mip05-v1", IKM = shared_x)
encryption_key = HKDF-Expand(prk, "mip05-token-encryption", 32)
```

The token is encrypted with ChaCha20-Poly1305, a random 12-byte nonce, and empty AAD.

`platform` is `0x01` for APNs or `0x02` for FCM. Native platform tokens are required; iOS clients use APNs directly and
must not use FCM as an iOS proxy.

## Token gossip

Token distribution uses Marmot app events carried inside ordinary group messages:

- kind `447`: token request and self-token update;
- kind `448`: token list response;
- kind `449`: token removal.

These inner app events are unsigned, like other Marmot app payloads.

Clients index tokens by MLS leaf. A leaf has at most one active push token record, and that record carries the
notification server public key and relay hint. When a member is removed, clients delete tokens for the removed leaves as
part of local cleanup.

## Notification trigger

When a sender wants to wake recipients, it publishes a NIP-59 gift-wrapped event to the notification server's inbox
relays:

```text
kind 1059 gift wrap
  kind 13 seal
    unsigned kind 446 Marmot notification rumor
```

The kind `446` rumor contains:

- `content`: one standard-base64 string with one or more concatenated 1084-byte `EncryptedToken` values;
- `v`: `mip05-v1`;
- `pubkey`: a fresh ephemeral key.

The content field follows the Nostr transport byte-encoding rule: standard base64 with padding and no `encoding` tag.

The seal is signed by the same ephemeral key used as the rumor `pubkey`. The gift wrap uses a separate ephemeral key
and is addressed to the notification server.

The notification server advertises its inbox relays with a signed kind `10050` event containing one `relay` tag per
inbox relay.

## Decoys and batching

Clients should batch notifications for a short period and include decoy tokens when possible. Decoys are valid encrypted
tokens from other groups or the sender's own token, not random bytes. Random bytes are distinguishable because they fail
curve or AEAD validation.

Silent wakes that lead to no new messages are expected. Clients should fetch, find nothing, and return to sleep without
showing user-facing errors.

## Validation

A client MUST treat malformed push notification data as advisory failure. It must not reject valid group messages
because a related push hint was missing, delayed, duplicated, or malformed.

Notification servers MUST reject or ignore malformed notification triggers, including:

- missing or unsupported `v` tags;
- invalid base64 content;
- decoded content whose length is not a multiple of 1084 bytes;
- token chunks with invalid ephemeral keys, failed ECDH/HKDF, failed AEAD authentication, invalid platform bytes, or
  invalid token lengths.

## Migration notes

MIP-05 is still Draft in the merged MIP set. This feature should stay optional and must not change group state.
