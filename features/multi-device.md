# Multi-device

Status: branch draft.

Byte-level definitions in this document are placeholders and not yet finalized. They MUST NOT be implemented for
interop yet. Marmot-owned hashes in this document use SHA-256, and named Marmot-owned key derivations use
HKDF-SHA256. MLS-Exporter invocations are the exception: MLS computes them with the active ciphersuite's KDF and hash,
and each invocation below states its ciphersuite-dependent or fixed output length.

Multi-device support lets one Marmot account participate in a group from more than one MLS leaf.

Marmot account identity is still the Nostr public key. Devices are separate MLS clients bound to that account identity.

This feature is still a draft. Its wire bytes are not yet normative and are subject to change before they become part
of the interop surface.

This draft does not yet create an adopted exception to v1 membership authorization. The proposed flow below carries an
active-admin authorization proof as component-owned data in an `AppEphemeral` proposal. Until that component id, proof
event kind, and exact proof bytes are defined and the flow becomes normative, an External Commit shaped this way
remains invalid under adopted v1. Matching an existing account identity and possessing the draft Join PSK are not
sufficient admin authorization. Requirement keywords in the remaining draft constrain the proposed design only.

## Surfaces

- Foundation identity and credentials.
- MLS External Commit.
- MLS extension `marmot.multi-device.v1` (`0xf2f0`) as the group-level signaling gate.
- Optional LeafNode extension `marmot.encrypted-device-name.v1` (`0xf2ef`).
- The required account identity proof on the joining LeafNode.
- MLS `AppEphemeral` proposal type `0x0009` for the active-admin join authorization proof, under a future
  multi-device authorization ComponentID.
- Exporter: `MLS-Exporter("marmot", join_psk_id, KDF.Nh)`.
- Future custom proposal candidate: `IdentityRemove`.

## Behavior

A new device joins an existing account's group as a new MLS leaf. It uses the same Nostr credential identity as the
account's existing leaves, but it has fresh MLS key material and independent local MLS state.

History synchronization is out of scope. A newly added device cannot decrypt epochs before it joined.

## Signaling gate

External Commit behavior for multi-device support is active only when all signaling requirements are met:

- `GroupContext.extensions` contains a valid `marmot.multi-device.v1` extension (`0xf2f0`);
- `GroupContext.required_capabilities` requires extension type `0xf2f0` and proposal type `app_ephemeral` (`0x0009`);
- the GroupContext `app_components` list requires the future multi-device authorization ComponentID;
- every current non-blank leaf advertises `0xf2f0` in `LeafNode.capabilities.extensions` and `0x0009` in
  `LeafNode.capabilities.proposals`, and advertises the future authorization ComponentID in its `app_components`
  entry.

In the proposed flow, failure of any signaling check makes a `new_member_commit` External Commit invalid before any
future admin-authorization check.

## External Commit authorization

The proposed multi-device External Commit is valid only when:

- the signaling gate is active;
- the joining LeafNode carries the required valid Marmot account identity proof;
- the joining LeafNode credential identity matches at least one existing group member's credential identity;
- the Commit contains the required `ExternalInit` proposal;
- the Commit contains exactly one MLS PreSharedKey proposal carrying the Marmot multi-device External PSK id;
- the Commit contains exactly one `AppEphemeral` proposal for the future multi-device authorization ComponentID;
- the Commit contains no proposal other than that `ExternalInit`, PreSharedKey, and `AppEphemeral` proposal;
- the `AppEphemeral` data contains a valid active-admin join authorization proof;
- this flow contributes no data to `FramedContent.authenticated_data`, which follows any other independently
  negotiated Marmot feature's rules and is zero-length when no such feature applies;
- ordinary MLS External Commit validation succeeds.

These checks establish three different facts:

- the joining LeafNode account identity proof establishes which account owns the new MLS leaf signature key;
- the `AppEphemeral` authorization proof establishes that an active admin authorized adding that exact leaf to this
  group from the candidate parent state;
- the Join PSK establishes that the new device received current, group-specific pairing material.

The join authorization proof is a signature over a canonical local-only Nostr event. The proof event is not published
to relays. Its signer MUST be an active admin in the candidate parent state, and its signed inputs MUST bind at least
the candidate parent GroupContext, joining account identity, and new MLS leaf signature key. A same-account device that
is not an active admin cannot authorize the membership change.

The join authorization proof is a different authority class from the joining LeafNode's account identity proof and
MUST NOT reuse that proof event kind or signing template. Placeholder: the exact authorization event kind, ComponentID,
field layout, tag contents, freshness rule, and signing input are not yet assigned or finalized.

This flow does not enable the GroupContext `safe_aad` component merely to carry its authorization proof.
`AppEphemeral` gives the proof the required one-Commit lifetime without changing the framing of
`FramedContent.authenticated_data`. If another feature independently enables SafeAAD, that feature still frames the
entire field as SafeAAD; the multi-device flow contributes no SafeAAD item.

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

Transferring `group_event_key` gives the pairing recipient the ability to remove the Nostr kind `445` outer encryption
layer for every recorded envelope from that source epoch. It does not by itself reveal MLS application plaintext, but
it does expose the inner MLS message type, bytes, and traffic grouping that the outer layer hides. This is a property of
the draft pairing design, not a requirement on the base Marmot group protocol.

Before this feature becomes normative, the pairing design must either remove the `group_event_key` transfer or define a
single-use pairing payload with a bounded validity period and deletion after successful use or expiry. Those bounds
belong to this pairing flow and MUST NOT extend the base retained-history window.

Group entries are epoch-specific. A failed stale-epoch join MUST be retried with fresh current-epoch material.

## Device labels

`marmot.encrypted-device-name.v1` is an optional LeafNode extension for an encrypted device label. It is display
metadata. It MUST NOT be used as identity or authorization input.

The current branch draft encrypts the device name with NIP-44 to the user's own Nostr identity. Under that construction,
another group member cannot decrypt the label unless it also possesses that account's private key.

## Removing an account identity

Removing one device leaf is ordinary member removal. Removing a whole account identity across all of its device leaves
needs identity-scoped behavior.

`IdentityRemove` is the likely Marmot custom proposal for that behavior. It has not been assigned in this draft.

## Validation

A multi-device join is invalid if:

- the group has not negotiated support for the multi-device gate;
- the joining LeafNode account identity proof is missing or invalid;
- the joining LeafNode credential identity does not match any existing group member's credential identity;
- the multi-device authorization `AppEphemeral` proposal is missing, duplicated, uses the wrong ComponentID, or has
  invalid data;
- the authorization proof signer is not an active admin in the candidate parent state;
- the authorization proof does not bind the candidate parent GroupContext, joining account identity, and new MLS leaf
  signature key;
- the external PSK id or PSK value is wrong for the current group context;
- the Commit includes any proposal beyond the required ExternalInit, Marmot multi-device External PSK, and
  multi-device authorization `AppEphemeral`;
- `FramedContent.authenticated_data` contains a multi-device authorization proof or violates the rules of another
  independently negotiated feature;
- the External Commit fails normal MLS validation.

## Remaining work

Before this feature becomes normative it needs an assigned multi-device authorization ComponentID and event kind, exact
admin-authorization proof bytes, PSK derivation bytes, pairing payload bytes, the pairing-key lifetime decision above,
capability rules, and legacy extension migration rules to replace the placeholders called out above.
