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
