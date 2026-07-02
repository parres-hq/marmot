# Multi-device

Status: draft for internal review.

Byte-level definitions in this document are placeholders and not yet finalized. They MUST NOT be implemented for
interop yet. SHA-256 is the hash function throughout this document; named key derivations use HKDF-SHA256.

Multi-device support lets one Marmot account participate in a group from more than one MLS leaf.

Marmot account identity is still the Nostr public key. Devices are separate MLS clients bound to that account identity.

This feature is still a draft. Its wire bytes are not yet normative and are subject to change before they become part
of the interop surface.

## Surfaces

- Foundation identity and credentials.
- MLS External Commit.
- MLS extension `marmot.multi-device.v1` (`0xf2f0`) as the group-level signaling gate.
- Optional LeafNode extension `marmot.encrypted-device-name.v1` (`0xf2ef`).
- MLS authenticated data for the Nostr identity proof.
- Exporter: `MLS-Exporter("marmot", join_psk_id, KDF.Nh)`.
- Future custom proposal candidate: `IdentityRemove`.

## Behavior

A new device joins an existing account's group as a new MLS leaf. It uses the same Nostr credential identity as the
account's existing leaves, but it has fresh MLS key material and independent local MLS state.

History synchronization is out of scope. A newly added device cannot decrypt epochs before it joined.

## Signaling gate

External Commit behavior for multi-device support is active only when all signaling requirements are met:

- `GroupContext.extensions` contains a valid `marmot.multi-device.v1` extension (`0xf2f0`);
- `GroupContext.required_capabilities` requires `0xf2f0`;
- every current non-blank leaf advertises `0xf2f0` in `LeafNode.capabilities.extensions`.

If any of those checks fail, a client rejects a `new_member_commit` External Commit instead of applying the multi-device
authorization carve-out.

## External Commit authorization

A multi-device External Commit is valid only when:

- the signaling gate is active;
- the joining LeafNode credential identity matches at least one existing group member's credential identity;
- the Commit contains the required `ExternalInit` proposal;
- the Commit contains exactly one MLS PreSharedKey proposal carrying the Marmot multi-device External PSK id;
- the Commit contains no unrelated proposals;
- `FramedContent.authenticated_data` contains a valid Nostr identity proof;
- ordinary MLS External Commit validation succeeds.

The Nostr identity proof is a signature over a canonical local-only Nostr event of kind `450`. The proof event is not
published to relays. The challenge binds the account credential identity, the new MLS signature key, and the current
GroupContext.

Placeholder: the exact kind `450` challenge bytes — field layout, tag contents, and signing input — are not yet
finalized and not yet normative.

For all Commits outside this multi-device join flow, `FramedContent.authenticated_data` stays empty unless another
Marmot feature defines a non-empty value.

## Join PSK

The External Commit includes an External PSK bound to the current GroupContext.

```text
struct {
  opaque label<V>;
  opaque group_context_hash[32];
} MarmotMultiDeviceJoinPskId;

label              = ASCII("marmot.multi-device.join-psk.v1")
group_context_hash = SHA-256(TLS-serialize(GroupContext))

join_psk_id = MarmotMultiDeviceJoinPskId serialized in the Marmot binary profile
join_psk    = MLS-Exporter("marmot", join_psk_id, KDF.Nh)
```

`MarmotMultiDeviceJoinPskId` uses the Marmot binary profile
([../foundation/canonical-encoding.md](../foundation/canonical-encoding.md)): `label` carries a QUIC variable-length
integer length prefix, and `group_context_hash` is a fixed 32-byte array with no length prefix. The label is 31 bytes,
so its length prefix is the single byte `0x1f`. `GroupContext` is TLS-serialized as defined by MLS. This is the
proposed encoding and is not yet finalized.

Existing members recompute the same PSK from current group state before processing the External Commit. If the new
device used stale state, confirmation-tag validation fails.

The exporter context is the serialized `MarmotMultiDeviceJoinPskId`; its label field is the purpose and version for this
PSK. `KDF.Nh` is the output size of the MLS ciphersuite KDF's `Extract` function in bytes. Clients MUST NOT reuse this
exporter output for any other PSK, app component, media, or transport key.

## Pairing payload

An existing device transfers current-epoch join material to the new device over an authenticated out-of-band pairing
channel.

The draft pairing payload carries, per group:

- `group_event_key`: the exact 32-byte current-epoch key used for Nostr kind `445` outer encryption. Its derivation is
  owned by [../transports/nostr.md](../transports/nostr.md) (`MLS-Exporter("marmot", "group-event", 32)`); the pairing
  payload transfers the already-derived key rather than redefining it;
- `join_psk`: the current-epoch multi-device join PSK;
- `group_info`: TLS-serialized MLS GroupInfo with `external_pub`, `ratchet_tree`, `app_data_dictionary`, and any
  multi-device signaling required by the active profile.

The payload is encrypted with X25519, HKDF-SHA256, and ChaCha20-Poly1305. Pairing uses fresh ephemeral X25519 keys and
rejects all-zero shared secrets.

Placeholder: the exact pairing payload construction — ephemeral key encoding, HKDF salt and info bytes, nonce rule, and
ciphertext layout — is not yet finalized and not yet normative.

Group entries are epoch-specific. A failed stale-epoch join MUST be retried with fresh current-epoch material.

## Device labels

`marmot.encrypted-device-name.v1` is an optional LeafNode extension for an encrypted device label. It is display
metadata. It MUST NOT be used as identity or authorization input.

The current branch draft encrypts the device name with NIP-44 to the user's own Nostr identity. Other users SHOULD NOT
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
- the Commit includes any proposal beyond the required ExternalInit and Marmot multi-device External PSK;
- the External Commit fails normal MLS validation.

## Remaining work

Before this feature becomes normative it needs exact identity-proof bytes, PSK derivation bytes, pairing payload bytes,
capability rules, and legacy extension migration rules to replace the placeholders called out above.
