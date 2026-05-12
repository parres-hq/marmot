# MLS protocol

Status: sketch.

Marmot currently uses MLS as its continuous group key agreement (CGKA) protocol.

Implementations may use any MLS library if they produce and validate the same protocol bytes.

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
- MLS capability advertisement and required capabilities.

The Marmot account identity carried in credentials is defined in [identity.md](./identity.md).

## App components and group state

New group-level feature state should use MLS app data dictionary components when the backend supports the MLS extensions
draft features Marmot needs.

The shared component model is defined in [../app-components.md](../app-components.md). Component ids are registered in
[registries.md](./registries.md).

## Custom extensions and proposals

Existing Marmot groups may still use older Marmot-specific MLS extensions such as `marmot_group_data`. The rewrite is
moving the stable spec toward smaller app components.

New persistent group state should prefer app components. A custom MLS proposal type is appropriate only when the feature
needs proposal semantics that a component update cannot express.

## Authenticated data and exporters

Marmot documents that write MLS `authenticated_data` must own their byte contribution and define how it composes with
other contributors.

Marmot documents that use MLS exporter secrets must define the label, context, output length, and consuming feature. New
exporter uses should prefer the MLS extensions Safe framework when the needed backend support exists.

Registered Marmot exporter labels are listed in [registries.md](./registries.md).

## TODO: Safe exporter migration

Before this draft becomes normative, decide how Marmot exporter-derived secrets move to the MLS Extensions Safe
framework.

The decision should cover:

- which current exporter labels stay as legacy compatibility inputs;
- which app component ids own `SafeExportSecret` calls;
- how component ids, component names, or other namespaced values are used as label or context inputs;
- migration rules for kind `445` group-event encryption, encrypted media, and multi-device join PSKs.
