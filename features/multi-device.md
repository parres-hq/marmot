# Multi-device

Status: draft for internal review.

Multi-device support lets one Marmot account participate in a group from more than one MLS leaf.

Marmot account identity is still the Nostr public key. Devices are separate MLS clients bound to that account identity.

This feature is based on MIP-06 branch draft work. It is not part of the merged canonical MIP set yet.

## Surfaces

- Foundation identity and credentials.
- MLS External Commit.
- MLS extension `marmot_multi_device` (`0xF2F0`) as the group-level signaling gate.
- Optional LeafNode extension `encrypted_device_name` (`0xF2EF`).
- MLS authenticated data for the Nostr identity proof.
- Exporter label: `"marmot-mip06-join-psk-v1"`.
- Future custom proposal candidate: `IdentityRemove`.

## Behavior

A new device joins an existing account's group as a new MLS leaf. It uses the same Nostr credential identity as the
account's existing leaves, but it has fresh MLS key material and independent local MLS state.

History synchronization is out of scope. A newly added device cannot decrypt epochs before it joined.

## Signaling gate

External Commit behavior for multi-device support is active only when all signaling requirements are met:

- `GroupContext.extensions` contains a valid `marmot_multi_device` extension (`0xF2F0`);
- `GroupContext.required_capabilities` requires `0xF2F0`;
- every current non-blank leaf advertises `0xF2F0` in `LeafNode.capabilities.extensions`.

If any of those checks fail, a client rejects a `new_member_commit` External Commit instead of applying the multi-device
authorization carve-out.

## External Commit authorization

A multi-device External Commit is valid only when:

- the signaling gate is active;
- the joining LeafNode credential identity matches at least one existing group member's credential identity;
- the Commit contains the required `ExternalInit` proposal;
- the Commit contains exactly one MIP-06 External PSK proposal;
- the Commit contains no unrelated proposals;
- `FramedContent.authenticated_data` contains a valid Nostr identity proof;
- ordinary MLS External Commit validation succeeds.

The Nostr identity proof is a signature over a canonical local-only Nostr event of kind `450`. The proof event is not
published to relays. The challenge binds the account credential identity, the new MLS signature key, and the current
GroupContext.

For all non-MIP-06 Commits, `FramedContent.authenticated_data` stays empty unless another Marmot feature defines a
non-empty value.

## Join PSK

The External Commit includes an External PSK bound to the current GroupContext.

```text
join_psk_id = TLS-serialize(MarmotMultiDeviceJoinPskId(
  label = ASCII("marmot-mip06-join-psk-v1"),
  group_context_hash = SHA-256(TLS-serialize(GroupContext)),
))

join_psk = MLS-Exporter("marmot-mip06-join-psk-v1", join_psk_id, KDF.Nh)
```

Existing members recompute the same PSK from current group state before processing the External Commit. If the new
device used stale state, confirmation-tag validation fails.

## Pairing payload

An existing device transfers current-epoch join material to the new device over an authenticated out-of-band pairing
channel.

The MIP-06 draft payload carries, per group:

- `group_event_key`: the exact 32-byte current-epoch key used for Nostr kind `445` outer encryption;
- `join_psk`: the current-epoch multi-device join PSK;
- `group_info`: TLS-serialized MLS GroupInfo with `external_pub`, `ratchet_tree`, `marmot_group_data`, and
  `marmot_multi_device` signaling.

The payload is encrypted with X25519, HKDF-SHA256, and ChaCha20-Poly1305. Pairing uses fresh ephemeral X25519 keys and
rejects all-zero shared secrets.

Group entries are epoch-specific. A failed stale-epoch join must be retried with fresh current-epoch material.

## Device labels

`encrypted_device_name` is an optional LeafNode extension for an encrypted device label. It is display metadata. It must
not be used as identity or authorization input.

The current branch draft encrypts the device name with NIP-44 to the user's own Nostr identity. Other users should not
be able to read it.

## Removing an account identity

Removing one device leaf is ordinary member removal. Removing a whole account identity across all of its device leaves
needs identity-scoped behavior.

`IdentityRemove` is the likely Marmot custom proposal for that behavior. It has not been assigned in this draft.

## Validation

A multi-device join is invalid if:

- the group has not negotiated support for the multi-device gate;
- the identity proof is missing or invalid;
- the proof does not bind to the joining account identity;
- the external PSK id or PSK value is wrong for the current group context;
- the Commit includes any proposal beyond the required ExternalInit and MIP-06 External PSK;
- the External Commit fails normal MLS validation.

## Migration notes

MIP-06 should become this feature doc plus exact identity-proof bytes, PSK derivation bytes, pairing payload bytes,
capability rules, and legacy extension migration rules.
