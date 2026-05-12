# Multi-device

Status: sketch.

Multi-device support lets one Marmot account participate in a group from more than one MLS leaf.

Marmot account identity is still the Nostr public key. Devices are separate MLS clients bound to that account identity.

## Surfaces

- Foundation identity and credentials.
- MLS External Commit.
- Legacy MLS extensions: `marmot_multi_device` and `encrypted_device_name`.
- MLS authenticated data for the Nostr identity proof.
- Exporter label: `"marmot-mip06-join-psk-v1"`.
- Future custom proposal candidate: `IdentityRemove`.

## Behavior

A new device joins an existing account's group by proving that it is authorized by the account identity and by supplying
the external PSK required for the join.

The MIP-era flow uses a Nostr identity proof in MLS authenticated data. The proof is a signed Nostr-shaped value that
binds the joining device to the account identity for this group operation.

The join PSK is derived from current group secret material using the registered multi-device exporter label. The exact
PSK id, context bytes, and output length belong in the normative version of this feature doc.

## Device labels

`encrypted_device_name` is a legacy LeafNode extension for an optional encrypted device label. It is display metadata.
It must not be used as identity or authorization input.

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
- the External Commit fails normal MLS validation.

## Migration notes

MIP-06 should become this feature doc plus exact identity-proof bytes, PSK derivation bytes, capability rules, and
legacy extension migration rules.
