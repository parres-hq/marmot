# Nostr transport

Status: draft for internal review.

This document defines the first Marmot transport binding: MLS bytes carried over Nostr relays.

Nostr also appears in Marmot identity and app payloads. Those are separate foundation rules:

- Marmot account identity is a Nostr public key.
- Marmot app payloads use an unsigned Nostr event shape inside MLS.

This transport document covers only the outer relay-facing Nostr events used to publish, fetch, and route MLS bytes.

## Transport name and version

This binding is `marmot.transport.nostr`, version 1. There is no single on-wire version field; the binding is versioned
structurally through the event kinds, tag shapes, and the `marmot.transport.nostr.routing.v1` component below. An
interop-visible change uses the narrowest hook in [README.md](./README.md) ("Versioning") — a new envelope version, a
new Nostr kind, a new routing component id, or a new required capability — rather than a binding-wide version number.

## Required group state

A Nostr-routed group requires the `marmot.transport.nostr.routing.v1` app component.

That component owns:

- `nostr_group_id`, the 32-byte transport group id;
- the canonical relay list for group messages.

The Nostr transport uses those values. It does not derive them from account ids, MLS group ids, KeyPackage ids, relay
URLs, or Nostr event ids.

## Transport byte encoding

Fields in this binding that carry Marmot, MLS, or AEAD bytes use base64 with the standard alphabet and padding
(RFC 4648, section 4) unless the field is explicitly defined as lowercase hex. "Standard" here distinguishes this
alphabet from URL-safe base64 (RFC 4648, section 5), which this binding does not use.

This binding does not use `encoding` tags to negotiate byte encoding. A sender MUST NOT add an `encoding` tag for any
event shape in this document. A receiver MUST NOT switch decoders based on an `encoding` tag; each field is decoded by
the rule that defines that field.

## Relay URL profile

Relay URL fields and `relay`/`relays` tag values use the Nostr relay URL profile:

- the value MUST be valid UTF-8 and no more than 512 bytes;
- the URL MUST be absolute;
- the scheme MUST be `wss` or `ws`;
- the host MUST be present;
- username, password, and fragment components MUST be absent.

Producers SHOULD use `wss`, lowercase DNS hostnames, omit default ports, and avoid redundant path spelling. Receivers
compare relay URL byte strings exactly after validation. Local safety policy MAY refuse to connect or publish to a
valid relay URL, but it does not rewrite signed group state.

## Group message delivery

Nostr group messages use Nostr kind `445`.

A kind `445` event MUST include exactly one `h` tag whose value is the lowercase hex encoding of the group's
`nostr_group_id`.

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

The exporter label/context pair is registered for the Nostr kind `445` outer encryption layer only. It MUST NOT be
reused for app payloads, media, stream records, or other feature keys.

`group_event_key` is scoped to one MLS group epoch, so nonce uniqueness for a given key rests entirely on the 12-byte
random nonce. The number of kind `445` events in a single epoch is bounded by how often the group commits, which keeps
random 96-bit nonces well inside the birthday bound for this outer ChaCha20-Poly1305 layer.

The Nostr event id, event `pubkey`, tags, relay timestamp, and relay URL are not AEAD AAD for kind `445`. They are
validated as the transport envelope and then treated as transport evidence only.

Receivers MUST verify the kind `445` event id and Nostr signature before attempting to decrypt its content. That
signature proves only integrity of the ephemeral transport envelope. Marmot sender identity still comes from the MLS
message after decryption.

Receivers MUST reject kind `445` content that is not valid base64 or that decodes to fewer than 28 bytes. The minimum is
12 nonce bytes plus the 16-byte ChaCha20-Poly1305 tag.

Kind `445` Nostr event ids, relay timestamps, relay arrival order, and subscription order are transport evidence. They
MUST NOT choose group state.

## Outer decryption and epoch selection

`group_event_key` is derived from the MLS epoch's exporter secret, so it differs per group epoch. The kind `445`
envelope carries no epoch hint and uses an empty AAD, so a receiver cannot read the target epoch before decrypting.

A receiver decrypts the outer layer by trying the `group_event_key` of each retained candidate group state until one
authenticates, then hands the recovered MLS message to the peeler. The candidate set is the retained states the
convergence policy already requires: the current canonical epoch, any retained epoch inside the rollback horizon, and
any staged-but-unmerged local commit. A receiver MUST NOT widen this set using transport evidence, and trial decryption
MUST NOT by itself choose the canonical branch; it only recovers candidate MLS bytes for protocol-core convergence to
judge.

Trying the staged-but-unmerged local commit's key here is candidate construction, not application. It does not conflict
with the rule in [../protocol-core/group-state.md](../protocol-core/group-state.md) that inbound MUST NOT be applied to canonical group state during
`PendingPublish` or `Merging`: trial decryption only recovers bytes for convergence to judge, and the inbound message is
not applied while the group is in those states.

If no retained candidate key authenticates the content, the event is undecryptable transport input and is retained or
dropped under the inbound-processing rules, not applied to group state.

## Welcome delivery

Nostr welcomes use NIP-59 gift wraps.

The outer relay event is kind `1059`. It contains a kind `13` NIP-59 seal. The seal contains an unsigned kind `444`
Marmot welcome rumor.

The gift-wrap recipient is the invitee's Nostr public key.

The inner kind `444` rumor MUST include:

- `content`: serialized MLSMessage bytes whose wire format is `mls_welcome`, encoded as base64;
- `e` tag: the Nostr event id of the KeyPackage event used for the invite;
- `relays` tag: relay URLs, using the relay URL profile above, where the new member SHOULD fetch group messages.

The inner kind `444` rumor MUST NOT have a `sig` field. The kind `13` seal and kind `1059` gift wrap are signed by
NIP-59.

A receiver MUST reject a welcome that is not addressed to its own account identity.

A receiver MUST reject a kind `444` rumor whose content is not valid base64, whose `e` tag is missing or not a
32-byte hex Nostr event id, or whose `relays` tag is missing or empty.

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
- `app_components`: supported Marmot app-component ids.

The `i` tag is the KeyPackageRef, not the account identity. Receivers MUST verify it against the decoded KeyPackage.

The `mls_extensions` tags MUST include `0xf2f1` for `marmot.account-identity-proof.v1`. Receivers MUST still validate
the decoded KeyPackage LeafNode proof; the tag is only an advertisement and fetch filter.

KeyPackage publication is account transport. It helps other users find fresh KeyPackages. It does not create group
state.

KeyPackage relay discovery uses the account's kind `10002` NIP-65 relay list. KeyPackages are published to, and fetched
from, the relays in that list. There is no dedicated KeyPackage relay list, and KeyPackage kind `30443` events do not
repeat those relays.

Kind `30443` is a Nostr addressable event. Two events occupy the same slot when their `author`, `kind`, and `d` tag
value are all equal, comparing the `d` value as exact bytes. For one `(author, kind, d)` slot, clients SHOULD keep the
newest valid event by `created_at`, with lower event id as the deterministic tie-breaker when timestamps are equal.
Across different `d` slots, each valid event is a separate candidate KeyPackage. Candidate ranking then follows
[../foundation/key-packages.md](../foundation/key-packages.md).

When candidates from different `(author, kind, d)` slots are otherwise equivalent after foundation ranking, clients
SHOULD select the candidate with the lexicographically lower decoded KeyPackageRef from the `i` tag. The `i` tag is
hex-decoded before comparison.

## Subscriptions and fetch rules

A Nostr transport client subscribes to:

- account inbox gift wraps: kind `1059`, `p` tag equal to the local account pubkey;
- group messages: kind `445`, `h` tag equal to the group's `nostr_group_id`;
- NIP-65 relay lists: kind `10002`, author equal to the account being queried, to discover where that account
  publishes its KeyPackages;
- KeyPackage events: kind `30443`, using the account lookup rules defined by
  [../foundation/key-packages.md](../foundation/key-packages.md).

Clients SHOULD use a `since` value when resubscribing if they have a retained transport timestamp. The timestamp is a
fetch hint only.

## Publish targets and acknowledgements

Group messages are published to the relay list in `marmot.transport.nostr.routing.v1`, after applying any local safety
policy.

Welcome messages are published to the recipient's inbox relay set.

KeyPackage events are published to the account's NIP-65 (kind `10002`) relay set.

The transport MAY report endpoint-level acceptances and failures. Publish acknowledgement is not group consensus. The
protocol-core publish lifecycle defines when locally created MLS work MAY be applied.

## Validation before peeling

A Nostr transport client MUST validate the outer event enough to classify it before passing bytes to the MLS peeler:

- kind `445` group messages MUST be signed Nostr events with a valid id/signature, MUST have exactly one `h` tag, and
  MUST have base64 content whose decoded length is at least 28 bytes;
- kind `1059` welcomes MUST be signed Nostr events and MUST have a `p` tag;
- kind `444` welcome rumors MUST have `e` and `relays` tags after NIP-59 unwrapping;
- kind `30443` KeyPackage event content MUST be base64-encoded MLS KeyPackage bytes;
- fields that claim to be hex or base64 MUST decode successfully;
- unsupported Nostr kinds are ignored or reported as malformed transport input.

The peeler validates transport encryption, welcome recipient binding, and MLS bytes. Protocol core validates group
state.

## Duplicate and replay handling

Relays MAY redeliver the same event, and a client subscribing to several relays will receive the same group message
more than once. The Nostr event id is transport evidence and MUST NOT be used as the Marmot deduplication id: the id
used for dedup and replay is defined over the recovered Marmot or MLS bytes (see
[../foundation/wire-envelopes.md](../foundation/wire-envelopes.md), "Message ids", and
[../protocol-core/inbound-processing.md](../protocol-core/inbound-processing.md), "Message identity"). A client peels
the transport envelope, recovers the MLS message, and deduplicates on that stable id before applying state, so relay
redelivery and cross-relay duplication collapse to a single `duplicate` outcome. Relay `created_at` timestamps, relay
arrival order, and subscription order are fetch hints only and MUST NOT choose group state.

## Metadata exposed to the transport

Relays see only transport-envelope metadata, never plaintext or MLS secrets:

- kind `445` events expose the group's random `nostr_group_id` via the `h` tag (it is not derived from any member key,
  so it does not link members across groups), a fresh per-event ephemeral `pubkey` (never the sender's account identity
  and never reused), and the relay timestamp. The MLS message is encrypted under the per-epoch group-event key.
- welcomes are NIP-59 gift wraps addressed to the invitee's account public key; the inbox address is the deliberate
  account-addressing exception ([../foundation/identity.md](../foundation/identity.md)). The gift wrap and seal hide the
  sender and the inner `kind 444` rumor.
- kind `30443` KeyPackage events are authored by the account identity, because their purpose is to let others find that
  account's packages.

A client MUST NOT add tags, content, or `encoding` markers that expose account ids, group ids, message ids, payloads,
or key material beyond what each event shape above already requires. Local safety policy MAY refuse a relay URL, but it
MUST NOT rewrite signed group state to do so.
