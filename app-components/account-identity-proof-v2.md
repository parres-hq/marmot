# Account identity proof v2

Status: adopted.

`marmot.member.account-identity-proof.v2` proves that the Nostr account named by an MLS `BasicCredential` authorized
the MLS signature public key of that exact member leaf.

This is a required LeafNode application component and a clean break from the legacy
`marmot.account-identity-proof.v1` custom extension.

## Registry

- Component id: `0x8009`
- Name: `marmot.member.account-identity-proof.v2`
- Proof event kind: `450`
- Valid component location: the `app_data_dictionary` in an MLS LeafNode, including the LeafNode embedded in a
  KeyPackage
- Signature algorithm: Nostr account-key BIP-340 Schnorr signature over a NIP-01 event id

The component is invalid in a GroupContext, KeyPackage-level dictionary, GroupInfo, `AppEphemeral` proposal, or SafeAAD
item.

## Component data

The component data is exactly one `MarmotAuthorizationProof`:

```text
struct {
  opaque signer_pubkey[32];
  uint64 created_at;
  opaque signature[64];
} MarmotAuthorizationProof;
```

Its encoding and common validation rules are defined in
[../foundation/authorization-proofs.md](../foundation/authorization-proofs.md). The component data is exactly 104
bytes and has no component-specific wrapper or version field.

## Signing event

To create or validate the proof, construct this exact local-only Nostr event:

```text
pubkey     = lowercase-hex(proof.signer_pubkey)
created_at = proof.created_at
kind       = 450
tags       = [
  ["d", "marmot.account-identity-proof.v2"],
  ["component", "0x8009"],
  ["ciphersuite", ciphersuite_hex],
  ["signature_scheme", signature_scheme_hex],
  ["mls_signature_key", mls_signature_key_hex]
]
content    = "Authorize this MLS leaf key for my Marmot account"
```

The values are:

- `ciphersuite_hex`: the applicable MLS ciphersuite as `0x` followed by exactly four lowercase hexadecimal digits;
- `signature_scheme_hex`: that ciphersuite's MLS signature scheme as `0x` followed by exactly four lowercase
  hexadecimal digits;
- `mls_signature_key_hex`: the exact contents of the LeafNode `signature_key` opaque vector, excluding its TLS vector
  length prefix, encoded as lowercase hexadecimal with no prefix.

The applicable ciphersuite is the KeyPackage ciphersuite when validating a KeyPackage and the group's ciphersuite when
validating a group member LeafNode. The LeafNode's signature key encoding and signature scheme MUST be valid for that
ciphersuite before the event is reconstructed.

The tags MUST appear exactly once and in the order shown. The event has no other tags. The event id and signature follow
[../foundation/authorization-proofs.md](../foundation/authorization-proofs.md). This event is a signing template and
MUST NOT be published to relays.

## Production and reuse

`proof.signer_pubkey` MUST be the same 32-byte Nostr account public key carried as the LeafNode
`BasicCredential.identity`.

A producer MUST set `proof.created_at` to its local current Unix time when requesting the account signature. A proof
remains valid without a receiver-side age limit because it authorizes a long-lived key binding, not a one-time
operation.

The same proof MAY be reused only while all signed inputs remain byte-for-byte identical. In particular, a new MLS
signature public key, ciphersuite, signature scheme, or account identity requires a new proof. Reusing a proof across
KeyPackages or group leaves that contain the same signed binding does not expand its authority.

## Negotiation and presence

Every Marmot KeyPackage and every current Marmot member LeafNode MUST:

- advertise component id `0x8009` in its LeafNode `app_components` support list; and
- contain exactly one `0x8009` component data entry in that LeafNode's `app_data_dictionary`.

Every Marmot GroupContext MUST require component id `0x8009` in its `app_components` required-component list. A support
list entry does not substitute for the required proof data entry.

## Lifecycle, authorization, and removal

The component data is created as part of a new or replacement LeafNode. It is not GroupContext state and MUST NOT be
created, replaced, or removed with `AppDataUpdate`.

The proof authenticates the account-to-leaf-key binding; it does not by itself authorize the leaf to join or remain in
a group. Creating a KeyPackage follows [../foundation/key-packages.md](../foundation/key-packages.md). Adding a new
leaf still requires the membership authorization defined by the applicable join flow.

An existing member may replace this component only as part of an MLS-authenticated replacement of its own LeafNode.
The replacement leaf's `BasicCredential.identity` MUST equal the member's prior account identity. It MUST contain a
valid proof for the replacement leaf signature key and other signed inputs. A change of account identity is not a
self-update; it requires removing the old membership and separately authorizing a new membership.

Component id `0x8009` and its data MUST NOT be removed from a non-blank Marmot member leaf. The data disappears only
when the member leaf itself is removed from the tree.

## Validation

A client MUST reject a KeyPackage, proposed LeafNode, resulting group state, or received group member leaf if:

- component id `0x8009` is absent from the LeafNode's support list;
- the LeafNode has no `0x8009` component data entry or has more than one such dictionary entry;
- the component appears at an invalid location;
- the component data is not exactly one valid `MarmotAuthorizationProof`;
- `proof.signer_pubkey` is not exactly equal to the 32-byte `BasicCredential.identity`;
- the credential identity is not a valid x-only secp256k1 public key;
- the ciphersuite or signature scheme used to reconstruct the event does not match the validated MLS context;
- the signed MLS signature key is not exactly the signature key in that LeafNode;
- the event id or BIP-340 signature does not verify under `proof.signer_pubkey`.

A Marmot group is invalid if its GroupContext does not require component id `0x8009`, if a current member does not
advertise support for it, or if a current member lacks valid component data.

## Signing test vector

This fixture uses BIP-340 secret key `3` and all-zero 32-byte auxiliary randomness. The secret is test material only.

```text
signer_pubkey            = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
created_at               = 1700000000
ciphersuite              = 0x0001
signature_scheme         = 0x0807
mls_signature_key        = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

The NIP-01 canonical event serialization is:

```json
[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",1700000000,450,[["d","marmot.account-identity-proof.v2"],["component","0x8009"],["ciphersuite","0x0001"],["signature_scheme","0x0807"],["mls_signature_key","000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]],"Authorize this MLS leaf key for my Marmot account"]
```

The event id and BIP-340 signature are:

```text
event_id  = b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b
signature = c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d
```

The resulting 104-byte component data is:

```text
f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f100c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d
```

## Migration from v1

This component replaces the custom LeafNode extension type `0xf2f1`. The v1 extension is not part of the current
Marmot profile and MUST NOT be accepted as a substitute for component id `0x8009`.

There is no mixed v1/v2 fallback and this spec defines no in-place conversion of an existing v1 group. A v2 client:

- rejects a v1-only KeyPackage or LeafNode;
- publishes new KeyPackages with the `0x8009` support and data entries;
- does not require or emit extension type `0xf2f1` for a v2 group; and
- treats a group that still requires `0xf2f1` but does not require `0x8009` as a legacy group outside this profile.

A future migration flow for preserving an existing legacy group's identity may be specified separately. It MUST NOT
weaken the v2 proof or create a state in which some current member leaves use only v1.
