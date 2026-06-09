# Canonical encoding

Status: draft for internal review.

When Marmot signs, hashes, stores, compares, or names protocol values by bytes, those bytes MUST have one encoding.

## Scope

This document covers Marmot-owned bytes: app component state, app component updates, Marmot extensions, and other byte
strings owned by this spec.

It does not redefine bytes owned by another protocol:

- MLS messages, KeyPackages, credentials, and MLS-defined extensions use the encoding defined by MLS.
- Nostr event ids and signatures use the Nostr canonical event serialization.
- Transport envelopes use the encoding defined by their transport document.

When a Marmot document embeds upstream bytes, it treats them as opaque bytes unless that document says it parses the
upstream type.

## Marmot binary profile

Marmot-owned binary structures use TLS Presentation Language syntax with QUIC variable-length vector prefixes unless the
owning document names another encoding.

That means:

- struct fields are serialized in the order shown;
- `uint8`, `uint16`, `uint32`, `uint64`, and similar integers are fixed-width unsigned integers in network byte order;
- `opaque name[N]` is exactly `N` bytes and has no length prefix;
- `opaque name<min..max>` is a QUIC variable-length integer length prefix followed by that many bytes;
- `Type items<V>` is a QUIC variable-length integer byte length followed by the concatenated encodings of the items;
- the decoded length MUST satisfy the bounds written in the structure;
- a decoder MUST consume the full byte string when a document says a value is decoded exactly.

`Type items<V>` denotes a list whose byte length is encoded as a QUIC variable-length integer, followed by the
concatenated encoded items. The maximum byte length is `2^62 - 1`. A decoder MUST reject the value unless the vector
body decodes to a whole number of items with no trailing bytes. Owning documents SHOULD give a tighter bound when one
applies. An unbounded `<V>` means only the QUIC variable-length integer maximum applies.

## QUIC length prefixes

A QUIC variable-length integer length prefix uses the two high bits of the first byte to say how many bytes encode the
length:

| Length value                      | Prefix size | High bits |
| --------------------------------- | ----------- | --------- |
| `0..63`                           | 1 byte      | `00`      |
| `64..16383`                       | 2 bytes     | `01`      |
| `16384..1073741823`               | 4 bytes     | `10`      |
| `1073741824..4611686018427387903` | 8 bytes     | `11`      |

The remaining bits, together with any following length bytes, carry the length in network byte order.

Canonical Marmot encoders MUST use the shortest prefix size that can hold the length. Canonical Marmot decoders MUST
reject a longer prefix for the same value.

Examples:

- an empty variable-length byte string encodes as `00`;
- a seven-byte value `09 02 62 22 37 5a 36` encodes as `07 09 02 62 22 37 5a 36`;
- a 64-byte value starts with `40 40`;
- a 16383-byte value starts with `7f ff`;
- a 16384-byte value starts with `80 00 40 00`.

## Upstream TLS and MLS bytes

Marmot uses MLS, and MLS uses TLS Presentation Language. Marmot does not rewrite MLS-owned structures into the Marmot
binary profile.

For example, an MLS KeyPackage inside Marmot is still an MLS KeyPackage. A Marmot document MAY carry the serialized
KeyPackage bytes, hash them, or bind them into a credential, but the KeyPackage's internal encoding comes from MLS.

The Marmot binary profile applies when this spec defines the structure.

## Text

Text fields are UTF-8 byte strings.

Protocol equality is byte equality. Clients MUST NOT normalize Unicode, trim whitespace, case-fold, or otherwise rewrite
text before signing, hashing, comparing, storing, or replaying it unless the owning document defines that rule.

This carve-out is what binds hex and base64 string encodings: a producer emits the case its owning document specifies
(for example, the Nostr binding in `../transports/nostr.md` requires lowercase hex), and a decoder compares the decoded
bytes, not the encoded characters.

## Sorting and duplicates

When a Marmot structure says a list is sorted, the default sort order is lexicographic order over the encoded item
bytes.

When a Marmot structure says a list is unique, duplicates are checked by exact byte equality after the owning document's
validation rules have run.

## Unknown bytes

Unknown optional data that a client is required to preserve MUST be copied byte-for-byte.

A client MUST NOT parse, normalize, sort inside, partially copy, or re-encode unknown preserved bytes.

## Nostr-shaped values

When Marmot asks for a Nostr event signature or event id, the signing input is the Nostr canonical event serialization.

Unsigned Nostr-shaped app payloads inside MLS are still encoded by the document that owns that message type. They are
not relay-publishable Nostr events.
