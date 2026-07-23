# Multi-device join authorization v1

Status: branch draft.

`marmot.authorization.multi-device-join.v1` carries an active administrator's authorization for one exact device leaf
to join one exact candidate parent state through the draft multi-device External Commit flow.

This component assigns exact bytes to the authorization proof described by
[../features/multi-device.md](../features/multi-device.md). It does not make that feature adopted: until the feature
document becomes normative, adopted membership authorization continues to reject this External Commit shape.

## Registry

- Component id: `0x800a`
- Name: `marmot.authorization.multi-device-join.v1`
- Proof event kind: `452`
- Valid carrier: one MLS `AppEphemeral` proposal in the draft multi-device `new_member_commit` External Commit
- Signature algorithm: administrator account-key BIP-340 Schnorr signature over a NIP-01 event id

This component has no persistent dictionary entry. It is invalid as component data in a GroupContext, LeafNode,
KeyPackage, or GroupInfo and is invalid as a SafeAAD item.

## AppEphemeral data

The `AppEphemeral` proposal uses component id `0x800a`. Its component-owned data is exactly one
`MarmotAuthorizationProof`:

```text
struct {
  opaque signer_pubkey[32];
  uint64 created_at;
  opaque signature[64];
} MarmotAuthorizationProof;
```

Its encoding and common validation rules are defined in
[../foundation/authorization-proofs.md](../foundation/authorization-proofs.md). The data is exactly 104 bytes and has
no component-specific wrapper or version field.

## Bound state

The proof is evaluated against:

- `candidate_parent_context`: the MLS GroupContext for the epoch to which the External Commit is applied;
- `joining_leaf`: the complete new LeafNode carried by the External Commit's UpdatePath;
- `joining_account`: the exact 32-byte `BasicCredential.identity` in `joining_leaf`;
- `mls_signature_key`: the exact contents of the `joining_leaf.signature_key` opaque vector, excluding its TLS vector
  length prefix; and
- the candidate parent group's MLS ciphersuite and corresponding signature scheme.

Compute:

```text
group_context_hash = SHA-256(TLS-serialize(candidate_parent_context))
leaf_node_hash     = SHA-256(TLS-serialize(joining_leaf))
```

The serializations are the MLS-owned TLS encodings. They are not re-encoded with the Marmot binary profile.

Because `leaf_node_hash` covers the complete joining LeafNode, it also binds the credential, capabilities, extensions,
and application-component data that the administrator reviewed. The separately displayed account and signature-key
tags below are redundant cryptographic bindings included so an external signer can present the important authorization
inputs intelligibly.

## Signing event

Construct this exact local-only Nostr event:

```text
pubkey     = lowercase-hex(proof.signer_pubkey)
created_at = proof.created_at
kind       = 452
tags       = [
  ["d", "marmot.multi-device-join-authorization.v1"],
  ["component", "0x800a"],
  ["group_id", group_id_hex],
  ["epoch", epoch_decimal],
  ["group_context_hash", group_context_hash_hex],
  ["account", joining_account_hex],
  ["ciphersuite", ciphersuite_hex],
  ["signature_scheme", signature_scheme_hex],
  ["mls_signature_key", mls_signature_key_hex],
  ["leaf_node_hash", leaf_node_hash_hex]
]
content    = "Authorize this device to join the Marmot group"
```

The tag values are:

- `group_id_hex`: the exact contents of the `candidate_parent_context.group_id` opaque vector, excluding its TLS
  vector length prefix, as lowercase hexadecimal with no prefix;
- `epoch_decimal`: `candidate_parent_context.epoch` as canonical unsigned decimal ASCII, with no leading zero except
  that zero itself is `"0"`;
- `group_context_hash_hex`: the 32-byte `group_context_hash` as 64 lowercase hexadecimal characters;
- `joining_account_hex`: the 32-byte `joining_account` as 64 lowercase hexadecimal characters;
- `ciphersuite_hex`: the group's MLS ciphersuite as `0x` followed by exactly four lowercase hexadecimal digits;
- `signature_scheme_hex`: that ciphersuite's MLS signature scheme as `0x` followed by exactly four lowercase
  hexadecimal digits;
- `mls_signature_key_hex`: the `mls_signature_key` bytes defined above as lowercase hexadecimal with no prefix; and
- `leaf_node_hash_hex`: the 32-byte `leaf_node_hash` as 64 lowercase hexadecimal characters.

The tags MUST appear exactly once and in the order shown. The event has no other tags. The event id and signature follow
[../foundation/authorization-proofs.md](../foundation/authorization-proofs.md). This event is a signing template and
MUST NOT be published to relays.

## Signer authority

`proof.signer_pubkey` MUST identify an active administrator account in the candidate parent state under
[admin-policy-v1.md](./admin-policy-v1.md). The authorization is account-scoped: any valid signer for that active
administrator account may produce it.

The joining account MUST match the credential identity of at least one existing member leaf in the candidate parent
state, as required by the draft multi-device flow. Matching an existing account does not authorize the join. A
same-account device whose account is not an active administrator cannot create this proof unless a different active
administrator signs it.

## Freshness and replay scope

A producer MUST set `proof.created_at` to its local current Unix time when requesting the administrator signature.
Receivers do not apply a wall-clock age limit.

Freshness comes from the signed candidate parent state and exact joining leaf:

- a proof is invalid for any other GroupContext, including a later epoch of the same group;
- a proof is invalid for any other joining LeafNode, even when the account and MLS signature key are unchanged;
- a proof may be replayed only against the exact same candidate parent state and exact same joining LeafNode; and
- ordinary MLS validation and Marmot convergence permit at most one conflicting Commit to become the accepted child of
  that candidate parent state.

The proof authorizes membership of the exact leaf. It does not authorize arbitrary proposals, a different commit
parent, or future membership changes.

## Negotiation and carrier rules

A group that enables the draft multi-device join flow MUST:

- require proposal type `app_ephemeral` (`0x0009`) in MLS `RequiredCapabilities`;
- require component id `0x800a` in the GroupContext `app_components` required-component list; and
- require every current member LeafNode to advertise proposal type `0x0009` and component id `0x800a`.

The GroupContext MUST NOT contain a component data entry for `0x800a`; the id in `app_components` negotiates
understanding of the commit-scoped component.

The External Commit MUST contain exactly one inline `AppEphemeral` proposal for component id `0x800a`, with exactly one
104-byte proof as its data. A standalone `AppEphemeral` proposal, an `AppEphemeral` sent by an existing member, or this
component in any Commit other than the draft multi-device `new_member_commit` is invalid.

The component does not use `AppDataUpdate`, does not become persistent GroupContext state, and contributes nothing to
MLS `FramedContent.authenticated_data`.

## Validation

In addition to ordinary MLS validation and the complete flow rules in
[../features/multi-device.md](../features/multi-device.md), a client MUST reject the proposed External Commit if:

- proposal type `0x0009` or component id `0x800a` was not negotiated as required above;
- the `0x800a` `AppEphemeral` is missing, duplicated, standalone, or used in the wrong Commit shape;
- the component data is not exactly one valid `MarmotAuthorizationProof`;
- `proof.signer_pubkey` is not an active administrator account in the candidate parent state;
- the joining account does not match an existing member account in that state;
- the joining LeafNode lacks a valid `marmot.member.account-identity-proof.v2`;
- the group id, epoch, GroupContext hash, account identity, ciphersuite, signature scheme, MLS signature key, or LeafNode
  hash does not match the validated MLS inputs; or
- the event id or BIP-340 signature does not verify under `proof.signer_pubkey`.

## Signing test vector

This fixture uses administrator BIP-340 secret key `3` and all-zero 32-byte auxiliary randomness. The secret is test
material only. The two hashes are fixed already-computed inputs for testing the event and envelope construction.

```text
signer_pubkey       = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
created_at          = 1700000060
group_id            = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
epoch               = 7
group_context_hash  = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
joining_account     = 2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
ciphersuite         = 0x0001
signature_scheme    = 0x0807
mls_signature_key   = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
leaf_node_hash      = 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
```

The NIP-01 canonical event serialization is:

```json
[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",1700000060,452,[["d","marmot.multi-device-join-authorization.v1"],["component","0x800a"],["group_id","000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"],["epoch","7"],["group_context_hash","202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"],["account","2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"],["ciphersuite","0x0001"],["signature_scheme","0x0807"],["mls_signature_key","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"],["leaf_node_hash","606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"]],"Authorize this device to join the Marmot group"]
```

The event id and BIP-340 signature are:

```text
event_id  = aa6c83eefe4f96d2e28135c93ff32412d64aeb79096a545f8e8cad4af31187f2
signature = e8fad066f7eea0271fecd1808728004b09bde30e59af63d3bf8d07413e65382a8e55e3247d5cdfc3b4fc5c5c8fc02b02a0a4b5eff44fe2c42641c11b57cd5dc8
```

The resulting 104-byte `AppEphemeral` data is:

```text
f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f13ce8fad066f7eea0271fecd1808728004b09bde30e59af63d3bf8d07413e65382a8e55e3247d5cdfc3b4fc5c5c8fc02b02a0a4b5eff44fe2c42641c11b57cd5dc8
```

## Draft migration

Earlier branch-draft text proposed carrying this proof in raw `authenticated_data` and left its component id and event
kind unassigned. That shape was never normative.

Component id `0x800a`, event kind `452`, and the `AppEphemeral` carrier replace that placeholder design. Implementations
of the draft MUST reject a kind `450` multi-device authorization, raw authenticated-data proof, SafeAAD proof item, or
any proof using the earlier unassigned shape.
