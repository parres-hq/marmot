# MLS protocol

Status: draft for internal review.

Marmot currently uses MLS as its continuous group key agreement (CGKA) protocol.

Implementations MAY use any MLS library if they produce and validate the same protocol bytes.

## Required ciphersuite

All Marmot implementations MUST support MLS ciphersuite `0x0001`:

`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

Implementations MAY support additional MLS ciphersuites. A group can use only a ciphersuite supported by every current
member and by every KeyPackage used to add a new member.

## What Marmot uses from MLS

Marmot builds on:

- MLS groups and epochs;
- MLS Commits, Proposals, application-message content, and Welcomes;
- MLS KeyPackages and KeyPackage references;
- MLS `BasicCredential` for member credentials;
- the Marmot account identity proof LeafNode extension;
- MLS capability advertisement and required capabilities.

The Marmot account identity carried in credentials is defined in [identity.md](./identity.md). The LeafNode extension
that binds that identity to the MLS leaf signature key is defined in
[account-identity-proof-v1.md](./account-identity-proof-v1.md).

## Handshake wire format

Marmot handshake messages — Commits and Proposals — use a single MLS wire format within a group, so the serialized
`MLSMessage` bytes of a given commit are deterministic: every member that processes the same commit recovers the same
bytes. The first profile uses MLS `PublicMessage` for handshake content. Confidentiality comes from the transport
binding, which wraps the `MLSMessage` before it reaches relays — for the Nostr binding, the kind `445`
ChaCha20-Poly1305 envelope in [../transports/nostr.md](../transports/nostr.md) — so relays never see plaintext handshake
bytes.

Pinning one wire format matters for convergence. MLS defines a single canonical TLS serialization for an `MLSMessage`,
and Marmot does not mix `PublicMessage` and `PrivateMessage` carriage for handshake content, so the commit identity used
by convergence is well defined: the `commit_digest` / `tip_digest` (see
[../protocol-core/convergence.md](../protocol-core/convergence.md)) and the dedup `message_id` (see
[wire-envelopes.md](./wire-envelopes.md)) are each `SHA-256` over the serialized commit `MLSMessage` bytes, and two
members never derive different digests for the same authenticated commit by choosing a different carriage.

## App components and group state

New group-level feature state SHOULD use MLS app components carried in `app_data_dictionary` when the backend supports
the MLS extensions draft features Marmot needs.

The shared component model is defined in [../app-components/](../app-components/). Component ids are registered in
[registries.md](./registries.md).

## Custom extensions and proposals

Persistent group state SHOULD use app components. A custom MLS proposal type is appropriate only when the feature needs
proposal semantics that a component update cannot express.

`marmot.account-identity-proof.v1` is the required custom LeafNode extension used to authenticate Marmot account
ownership of MLS leaf signature keys. New custom extensions MUST be registered in [registries.md](./registries.md).

## Authenticated data and exporters

Marmot documents that write MLS `authenticated_data` MUST own their byte contribution and define how it composes with
other contributors.

Marmot documents that use MLS exporter secrets MUST define:

- the exporter label;
- the exporter context;
- the output length;
- the consuming feature;
- any post-export key schedule or application key context.

Exporter labels and contexts MUST be domain-separated from every other Marmot exporter use. A feature that needs a
reusable epoch secret MUST say so in its owning document and MUST derive per-use keys with a feature-owned context below
the exporter output.

Registered Marmot exporter labels are listed in [registries.md](./registries.md).

## Exporter research

Before this draft becomes normative, research whether the MLS Extensions Safe framework's exporter APIs are useful for
any Marmot secret derivation. This draft does not assign one.
