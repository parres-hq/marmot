# KeyPackages

Status: draft for internal review.

This document defines KeyPackage meaning, discovery requirements, and lifecycle.

KeyPackages are how Marmot supports asynchronous invites. A user can publish one or more usable KeyPackages before an
inviter is online. Later, an inviter fetches one, adds that user to a group, and sends a Welcome.

## Surfaces

- Foundation identity and capability negotiation.
- MLS protocol: `BasicCredential`, KeyPackage, KeyPackageRef, capabilities, and `last_resort`.
- Transport binding for KeyPackage publication and discovery.
- Protocol-core joining flow for consuming a KeyPackage through a Welcome.
- Registries for app component ids, MLS proposal ids, and transport kinds.

This document does not define new group state. It defines account/device readiness for future group joins.

## Behavior

Each Marmot account is identified by a Nostr public key. The MLS credential identity is the raw 32-byte x-only public
key, not hex text and not an `npub`.

Each MLS leaf has its own MLS signing key. That signing key proves the leaf. It is separate from the Nostr account
identity in the credential.

A KeyPackage belongs to the account named by its credential identity.

Every Marmot KeyPackage carries `marmot.account-identity-proof.v1` in its LeafNode extensions. The proof binds the
credential identity to the KeyPackage LeafNode's MLS signature public key. A KeyPackage without a valid proof is
malformed.

When a KeyPackage is published through a transport object, the transport binding defines how the outer author or sender
is checked against the credential identity.

Only the public KeyPackage bytes are published. Private `init_key` material is never published. If implementation APIs
expose a `KeyPackageBundle` type, only the public KeyPackage bytes belong in a transport publication. Those public
KeyPackage bytes are carried inside an `MLSMessage` with `wire_format = mls_key_package` (RFC 9420 §6), so a transport
publication is unambiguously the framed `MLSMessage`, not a bare `KeyPackage` struct. The `KeyPackageRef` is computed
over the inner `KeyPackage` (RFC 9420 `MakeKeyPackageRef`), not over the `MLSMessage` envelope.

## Capability advertising

KeyPackages advertise what that client/device can support. Group creation and member addition use these capabilities to
avoid creating a group that some member cannot process.

Every Marmot KeyPackage carries `marmot.account-identity-proof.v1` in its LeafNode extensions and advertises support for
that extension type as required by [account-identity-proof-v1.md](./account-identity-proof-v1.md). The remaining
current-profile capabilities are listed by namespace in [registries.md](./registries.md): `app_data_dictionary`,
`app_components`, `last_resort`, `app_data_update`, and `self_remove`. The registry is the source of numeric ids and
namespaces; this document only requires that those capabilities appear in the appropriate MLS capability lists.

A member can join only if its KeyPackage advertises support for every MLS primitive and app component the group
requires.

## Selection and lifecycle

An inviter MAY see several current KeyPackages for one account. It MUST reject malformed or incompatible candidates
before selecting one.

The selection policy carried forward from the MIP-era documents (the prior Marmot Improvement Proposals; see
[../mip-coverage.md](../mip-coverage.md)) prefers valid non-`last_resort` candidates when available, then prefers the
freshest valid candidate. A transport binding owns any transport-specific replacement, address, and tie-breaking rules.

Before ranking candidates, an inviter MUST perform the validation listed below and any additional checks required by the
active transport binding. Candidate freshness is only a KeyPackage selection input. It MUST NOT create group state and
MUST NOT override decoded KeyPackage validity, account identity proof validity, capability compatibility, or transport
author binding.

When a transport exposes a publication timestamp or replacement rule, clients SHOULD use it to avoid consuming stale
single-use KeyPackages. If two otherwise equivalent candidates remain, clients SHOULD use a deterministic
content-derived tie-breaker defined by the transport binding.

After a client successfully processes a Welcome that consumed a published KeyPackage, it SHOULD publish a fresh
replacement according to the active transport binding.

The private `init_key` material for a consumed non-`last_resort` KeyPackage MUST be deleted after successful Welcome
processing. A `last_resort` KeyPackage keeps its `init_key` until a replacement has been safely published or the local
grace policy allows deletion.

## Failure behavior

A client MUST NOT rotate or delete the consumed KeyPackage if Welcome processing fails. The existing KeyPackage remains
available so the inviter can retry or choose another candidate.

A client MUST reject a published KeyPackage when:

- the decoded content is not a valid MLS KeyPackage;
- the credential identity is not a valid Marmot account identity;
- the account identity proof extension is missing or invalid;
- the transport author or sender does not match the credential identity under the active transport binding;
- the transport publication encoding is invalid;
- required capability tags are missing or incompatible;
- a publication carries a KeyPackageRef hint and it does not match the decoded KeyPackageRef.

Transport-specific KeyPackage publication details live in [../transports/nostr.md](../transports/nostr.md).
