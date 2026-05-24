# Nostr transport

Status: draft for internal review.

This document defines the first Marmot transport binding: MLS bytes carried over Nostr relays.

Nostr also appears in Marmot identity and app payloads. Those are separate foundation rules:

- Marmot account identity is a Nostr public key.
- Marmot app payloads use an unsigned Nostr event shape inside MLS.

This transport document covers only the outer relay-facing Nostr events used to publish, fetch, and route MLS bytes.

## Required group state

A Nostr-routed group requires the `marmot.transport.nostr.routing.v1` app component.

That component owns:

- `nostr_group_id`, the 32-byte transport group id;
- the canonical relay list for group messages.

The Nostr transport uses those values. It does not derive them from account ids, MLS group ids, KeyPackage ids, relay
URLs, or Nostr event ids.

## Group message delivery

Nostr group messages use Nostr kind `445`.

A kind `445` event MUST include an `h` tag whose value is the lowercase hex encoding of the group's `nostr_group_id`.

The event `pubkey` MUST be a fresh ephemeral Nostr public key generated for that event. The kind `445` event MUST be
signed by the matching ephemeral key. The ephemeral key MUST NOT be the sender's Marmot account identity, and it MUST
NOT be reused across events.

The event content carries one encrypted MLS message:

```text
group_event_key = MLS-Exporter("marmot", "group-event", 32)
nonce           = random(12)
aad             = ""
ciphertext      = ChaCha20-Poly1305.encrypt(group_event_key, nonce, mls_message_bytes, aad)
event.content   = base64(nonce || ciphertext)
```

The base64 encoding is standard base64 with padding.

The `ciphertext` value is the full AEAD output and includes the authentication tag. The 12-byte nonce is prepended to
the ciphertext before base64 encoding. The AAD is the empty byte string and is not serialized into the event.

Receivers MUST reject kind `445` content that is not valid base64 or that decodes to fewer than 28 bytes. The minimum is
12 nonce bytes plus the 16-byte ChaCha20-Poly1305 tag.

Kind `445` Nostr event ids, relay timestamps, relay arrival order, and subscription order are transport evidence. They
must not choose group state.

## Welcome delivery

Nostr welcomes use NIP-59 gift wraps.

The outer relay event is kind `1059`. It contains a kind `13` NIP-59 seal. The seal contains an unsigned kind `444`
Marmot welcome rumor.

The gift-wrap recipient is the invitee's Nostr public key.

The inner kind `444` rumor MUST include:

- `content`: serialized MLSMessage bytes whose wire format is `mls_welcome`, encoded as base64;
- `encoding` tag: `["encoding", "base64"]`;
- `e` tag: the Nostr event id of the KeyPackage event used for the invite;
- `relays` tag: relay URLs where the new member should fetch group messages.

The inner kind `444` rumor MUST NOT have a `sig` field. The kind `13` seal and kind `1059` gift wrap are signed by
NIP-59.

A receiver MUST reject a welcome that is not addressed to its own account identity.

A receiver MUST reject a kind `444` rumor whose `encoding` tag is missing or names any encoding other than `base64`.

## KeyPackage publication

Nostr KeyPackages use kind `30443`.

The event content is the serialized MLS KeyPackage bytes encoded as base64. The event is authored by the account
identity that owns the KeyPackage. The event MUST be signed as a normal Nostr event.

The current tag set is:

- `d`: random non-empty KeyPackage slot id, currently a random 32-byte hex value;
- `mls_protocol_version`: `1.0`;
- `i`: lowercase hex KeyPackageRef;
- `mls_ciphersuite`: MLS ciphersuite id;
- `mls_extensions`: supported MLS extension ids;
- `mls_proposals`: supported MLS proposal ids;
- `encoding`: `base64`;
- `relays`: relay URLs where the account can receive KeyPackage-related traffic.

The `i` tag is the KeyPackageRef, not the account identity. Receivers SHOULD verify it against the decoded KeyPackage.

The `mls_extensions` tags MUST include `0xf2f1` for `marmot.account-identity-proof.v1`. Receivers MUST still validate
the decoded KeyPackage LeafNode proof; the tag is only an advertisement and fetch filter.

KeyPackage publication is account transport. It helps other users find fresh KeyPackages. It does not create group
state.

KeyPackage relay discovery uses kind `10051` events. A kind `10051` event lists relays with `relay` tags and an empty
content field.

Legacy kind `443` KeyPackages may exist during migration windows. Implementations that still support that migration may
query both kinds, but valid kind `30443` events are preferred. New publications should use kind `30443`.

## Subscriptions and fetch rules

A Nostr transport client subscribes to:

- account inbox gift wraps: kind `1059`, `p` tag equal to the local account pubkey;
- group messages: kind `445`, `h` tag equal to the group's `nostr_group_id`;
- KeyPackage relay lists: kind `10051`, author equal to the account being queried;
- KeyPackage events: kind `30443`, using the account lookup rules defined by
  [../foundation/key-packages.md](../foundation/key-packages.md).

Clients SHOULD use a `since` value when resubscribing if they have a retained transport timestamp. The timestamp is a
fetch hint only.

## Publish targets and acknowledgements

Group messages are published to the relay list in `marmot.transport.nostr.routing.v1`, after applying any local safety
policy.

Welcome messages are published to the recipient's inbox relay set.

KeyPackage events are published to the account's KeyPackage relay set.

The transport may report endpoint-level acceptances and failures. Publish acknowledgement is not group consensus. The
protocol-core publish lifecycle defines when locally created MLS work may be applied.

## Validation before peeling

A Nostr transport client MUST validate the outer event enough to classify it before passing bytes to the MLS peeler:

- kind `445` group messages must have an `h` tag;
- kind `1059` welcomes must be signed Nostr events and must have a `p` tag;
- kind `444` welcome rumors must have `["encoding", "base64"]` after NIP-59 unwrapping;
- kind `30443` KeyPackage events must have `["encoding", "base64"]`;
- fields that claim to be hex or base64 must decode successfully;
- unsupported Nostr kinds are ignored or reported as malformed transport input.

The peeler validates transport encryption, welcome recipient binding, and MLS bytes. Protocol core validates group
state.
