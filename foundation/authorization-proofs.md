# Authorization proofs

Status: adopted.

Marmot authorization proofs let a Nostr account key authorize protocol-specific bytes through a normal signed Nostr
event. This accommodates external signers that sign Nostr events but do not expose arbitrary BIP-340 signing.

The signed event is a local signing template. It is not a transport event and MUST NOT be published to relays.

This document defines the common proof envelope and validation algorithm. Each proof class owns a separate event kind
and defines the exact event fields, the authority the signer must possess, the values bound by the event, the carrier,
and any class-specific freshness or replay rules.

## Common proof envelope

Every proof class using this construction carries the following Marmot-owned bytes:

```text
struct {
  opaque signer_pubkey[32];
  uint64 created_at;
  opaque signature[64];
} MarmotAuthorizationProof;
```

The structure uses the Marmot binary profile in
[canonical-encoding.md](./canonical-encoding.md). All fields are fixed width, so the encoded proof is exactly 104 bytes:
the raw 32-byte x-only secp256k1 signer public key, an unsigned big-endian Unix timestamp in seconds, and a 64-byte
BIP-340 Schnorr signature.

The component id or other carrier version is the proof format's major version. The envelope therefore has no generic
version field.

`created_at` MUST be at least `1` and at most `9007199254740991` (`2^53 - 1`) so zero is not a valid signing timestamp
and the value is represented exactly by interoperable JSON implementations.

## Proof-class event

The owning proof-class document MUST define:

- one Nostr event kind used only for that authority class;
- the event's exact ordered tag array and exact content string;
- how every tag value is encoded;
- the protocol values from which the event is reconstructed;
- the authority the event signer must possess;
- the carrier and exact point at which the proof is validated;
- freshness and replay rules, if any.

Different authority classes MUST use different Nostr event kinds. A proof event kind MUST NOT be reused merely because
two proofs share the common envelope or happen to bind some of the same values.

Unless an owning document explicitly says otherwise, a proof event has no tags beyond the exact ordered tag array it
defines. Tag order, tag name, tag arity, tag value, content, kind, public key, and timestamp are all signed and MUST
match exactly.

The proof event id is the SHA-256 digest of the NIP-01 canonical serialization:

```text
[0, signer_pubkey_hex, created_at, kind, tags, content]
```

`signer_pubkey_hex` is the envelope's `signer_pubkey` encoded as 64 lowercase hexadecimal characters. `created_at` is
the envelope's integer value. The remaining fields come from the owning proof-class document. NIP-01 serialization and
event-id rules are pinned in [canonical-encoding.md](./canonical-encoding.md) ("Nostr-shaped values").

The envelope does not carry the event id or a copy of the event. A verifier reconstructs both from the envelope and the
owning proof context.

## Producing a proof

A producer:

1. obtains the protocol values required by the owning proof class;
2. sets `created_at` to the producer's local current Unix time in whole seconds for this signing request;
3. constructs the exact unsigned event defined by that proof class;
4. asks the Nostr account signer to sign that event;
5. validates the returned event exactly as described below; and
6. stores or transmits only the 104-byte `MarmotAuthorizationProof` in the owning carrier.

A signer SHOULD display the event kind, content, timestamp, and relevant tags to the user. A signer SHOULD warn or
require explicit confirmation when the requested timestamp is implausibly far from its local current time. That
signer-side protection helps a user understand what is being authorized; it is not a receiver-side wall-clock rule.

An external signer may return a complete signed Nostr event. Before extracting the common envelope, the producer MUST
verify that the returned `pubkey`, `created_at`, `kind`, `tags`, and `content` exactly equal the requested values, that
the returned event id equals the NIP-01 event id recomputed from those values, and that the signature verifies for that
event id and public key. The producer MUST NOT accept an external signer's substitutions, additional tags, alternate
content, or stale response.

## Validating a proof

A verifier:

1. decodes exactly one 104-byte `MarmotAuthorizationProof`, rejecting truncation or trailing bytes;
2. rejects a `signer_pubkey` that is not a valid x-only secp256k1 public key;
3. rejects a `created_at` equal to zero or greater than `2^53 - 1`;
4. reconstructs the exact proof event from the envelope and the owning proof context;
5. computes the NIP-01 event id; and
6. verifies `signature` as a BIP-340 signature of that 32-byte event id under `signer_pubkey`.

The verifier then applies the owning proof class's signer-authorization, binding, freshness, replay, and carrier rules.
A cryptographically valid envelope is not sufficient unless all of those class-specific rules also pass.

Protocol validity MUST NOT depend on comparing `created_at` with a receiver's local wall clock unless the owning proof
class explicitly defines a bounded-time rule and a deterministic evaluation point. In particular, a proof does not
expire merely because its event timestamp is old. This avoids different group members accepting or rejecting the same
MLS Commit based on clock skew or processing time.

## Versioning

Changing the common envelope, an event's kind, ordered tags, content, encoding, signed bindings, signer authority, or
validation semantics is a breaking proof-class change. The owning construction MUST allocate a new component id or
other carrier version and, when the event schema or authority class changes, a new event kind.

A newer proof class MUST NOT reinterpret or silently fall back to an older proof's carrier bytes.
