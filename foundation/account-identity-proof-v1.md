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

Integers are unsigned big-endian integers. `account_identity` is the raw 32-byte x-only secp256k1 account public key
also carried as the MLS `BasicCredential` identity. `mls_signature_public_key` is the exact serialized MLS leaf
signature public key bytes from the same LeafNode.

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

The signature is a 64-byte BIP-340 Schnorr signature over that digest, verified with `account_identity`.

The signing input is a standalone, domain-separated preimage. It is not the extension payload re-serialized. It begins
with the fixed 32-byte ASCII label `marmot.account-identity-proof.v1` (no length prefix) followed by a `0x00` separator,
and it carries `account_identity` with an explicit `account_identity_len = 32` field. The extension payload instead
stores `account_identity` as a fixed `opaque account_identity[32]` with no length prefix. Both representations cover the
same 32 bytes; the `account_identity_len` field in the preimage is the constant `32` and exists only as an explicit field
boundary. `mls_signature_scheme` is carried even though it is implied by `mls_ciphersuite`, so a verifier binds and
checks it directly instead of first resolving the ciphersuite's signature scheme.

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
