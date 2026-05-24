# Identity, credentials, and capabilities

Status: draft for internal review.

Marmot account identity is a Nostr public key.

The protocol identity is the raw 32-byte x-only secp256k1 public key. Human formats such as `npub` are presentation
formats and do not appear in Marmot protocol bytes unless a document says so.

## Accounts and members

A Marmot account is identified by one Nostr public key.

An MLS leaf represents one account-device membership in one group. Multiple MLS leaves may have the same Marmot account
identity when the account has multiple devices in the group.

Group policy may talk about accounts or leaves. A rule that targets an account applies to every current leaf whose
credential identity is that account. A rule that targets a leaf applies only to that leaf.

## MLS credential identity

Marmot uses the MLS credential identity to carry the Marmot account identity.

For a Marmot member leaf:

- the credential identity is exactly 32 bytes;
- those bytes are the member account's Nostr public key;
- clients reject credentials whose identity is not a valid x-only secp256k1 public key.

The MLS signature key for a leaf is not the Marmot account identity. It proves the MLS leaf. The credential identity
says which Marmot account that leaf belongs to.

## Account identity proof

Every Marmot member LeafNode MUST carry `marmot.account-identity-proof.v1`, an MLS LeafNode extension that proves the
account named by the `BasicCredential` authorized the leaf's MLS signature public key.

Clients MUST reject a member leaf or KeyPackage if the proof is missing, malformed, does not match the credential
identity, does not match the MLS leaf signature key, or does not verify under the account identity.

The extension bytes and validation rules are defined in
[account-identity-proof-v1.md](./account-identity-proof-v1.md).

## KeyPackages

KeyPackage meaning, discovery requirements, and lifecycle are defined in [key-packages.md](./key-packages.md).

## Capability negotiation

To ensure interoperability, capability negotiation is part of the Marmot protocol.

Different clients may support different features. A group must be created with the strongest feature set that every
intended member can support, and later members must support the group's required feature set before they can join.

Marmot uses MLS capabilities for this:

- each KeyPackage advertises the MLS extensions, app components, and proposal types the client supports;
- group state records the features every current and future member must support;
- adding a member fails if the new member's KeyPackage does not cover the group's required features;
- group state cannot be mutated into a state that not all members support.

Feature docs must say which capability they require. That may be an MLS extension type, an MLS proposal type, a Marmot
app component id, or a combination named by the feature. Marmot-owned ids are registered in
[registries.md](./registries.md).

Optional features should not block basic messaging. If a feature is not supported by every member, the group can still
exist without that feature. When all current members later support it, the group may upgrade its required feature set
through the protocol-core rules for capability upgrades.

## Delivery addressing is separate

Delivery addresses are not identities.

A transport delivery address must not be derived from an account id, member id, public key, MLS group id, KeyPackage id,
message id, relay URL, or other stable identity material.

Examples of delivery addresses include a Nostr group `h` tag, an inbox, a relay list, a topic, or an endpoint set. The
owning transport document defines how those addresses are generated, updated, validated, and used.

## Application content

Marmot app payloads use an unsigned Nostr event shape inside MLS. The shared shape is defined in
[application-messages.md](./application-messages.md).

The inner event's `pubkey` is the author's Marmot account identity. MLS authenticates who sent the MLS application
message to the group, and the inner event's `pubkey` is validated against that authenticated MLS sender.
