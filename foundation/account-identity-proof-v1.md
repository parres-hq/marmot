# Account identity proof v1

Status: draft for internal review.

`marmot.account-identity-proof.v1` is a Marmot custom MLS LeafNode extension that binds the Marmot account identity in
an MLS `BasicCredential` to that leaf's MLS signature public key.

This is a breaking protocol requirement. Marmot clients MUST reject member leaves and KeyPackages that do not carry a
valid proof.

## Registry

- MLS extension type: `0xf2f1`
- Name: `marmot.account-identity-proof.v1`
- Valid location: MLS LeafNode extensions, including the LeafNode inside a KeyPackage
- Version byte: `0x01`
- Signature algorithm: Nostr account-key BIP-340 Schnorr signature

## Extension payload

The extension payload is the following byte structure:

```text
uint8  version = 1
uint16 mls_ciphersuite
uint16 mls_signature_scheme
opaque account_identity[32]
uint16 mls_signature_public_key_len
opaque mls_signature_public_key[mls_signature_public_key_len]
opaque schnorr_signature[64]
```

This structure does not use the Marmot binary profile's QUIC variable-length prefixes
([canonical-encoding.md](./canonical-encoding.md)): all integers are fixed-width unsigned big-endian, every
`opaque name[N]` is exactly N bytes with no prefix, and the one length-prefixed field uses a fixed `uint16`
(`mls_signature_public_key_len`), not a QUIC varint. `account_identity` is the raw 32-byte x-only secp256k1 account
public key also carried as the MLS `BasicCredential` identity. `mls_signature_public_key` is the exact serialized MLS
leaf signature public key bytes from the same LeafNode; `mls_signature_public_key_len` MUST equal the signature public
key length for `mls_signature_scheme` (32 bytes for Ed25519 under the required ciphersuite `0x0001`), and the field
exists only as an explicit length boundary.

## Signing input

The account key signs the SHA-256 digest of this canonical byte string:

```text
ASCII "marmot.account-identity-proof.v1"
uint8  0
uint16 extension_type = 0xf2f1
uint8  version = 1
uint16 mls_ciphersuite
uint16 mls_signature_scheme
uint16 account_identity_len = 32
opaque account_identity[32]
uint16 mls_signature_public_key_len
opaque mls_signature_public_key[mls_signature_public_key_len]
```

The signature is a 64-byte BIP-340 Schnorr signature over that digest, verified with `account_identity`. The 32-byte
`SHA-256` digest above is itself the BIP-340 message: the account key signs and a verifier checks it as a prehashed
32-byte value. Marmot reuses only the account key's BIP-340 scheme here; it does NOT apply the Nostr canonical
event-id construction (`[0, pubkey, created_at, kind, tags, content]`) to build this preimage. This proof is not a Nostr
event and is never published.

The signing input is a standalone, domain-separated preimage, not the extension payload re-serialized. It length-prefixes
`account_identity` only to make that field boundary explicit; the payload and preimage both cover the same 32 account-key
bytes. `mls_signature_scheme` is still carried and verified directly, even though the ciphersuite implies it.

## Required capabilities

Every Marmot KeyPackage and group member LeafNode MUST advertise support for extension type `0xf2f1` in MLS
capabilities.

Every Marmot group MUST require extension type `0xf2f1` in MLS `RequiredCapabilities`.

## Validation

A client MUST reject a LeafNode or KeyPackage if:

- the extension is missing;
- the payload is truncated or has trailing bytes;
- `version` is not `1`;
- `mls_ciphersuite` does not match the group's ciphersuite or the KeyPackage ciphersuite being validated;
- `mls_signature_scheme` does not match the ciphersuite's MLS signature scheme;
- `account_identity` is not a valid 32-byte x-only secp256k1 public key;
- `account_identity` does not exactly match the LeafNode `BasicCredential` identity;
- `mls_signature_public_key` does not exactly match the LeafNode MLS signature public key;
- `schnorr_signature` is not a valid BIP-340 signature for the signing input digest and `account_identity`.

There is no legacy fallback. A member without a valid proof is not a Marmot member for this draft.
