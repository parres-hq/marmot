# Registries

Status: draft for internal review.

This file collects Marmot-owned ids so new documents do not accidentally reuse a value.

The owning document defines the bytes and validation rules. This registry only names the value.

## App component ids

Marmot app components use MLS private-use component ids.

| Component id | Name                                     | Document                                              |
| ------------ | ---------------------------------------- | ----------------------------------------------------- |
| `0x8001`     | `marmot.group.profile.v1`                | [doc](../app-components/group-profile-v1.md)          |
| `0x8002`     | `marmot.group.blossom.image.v1`          | [doc](../app-components/group-blossom-image-v1.md)    |
| `0x8003`     | `marmot.group.admin-policy.v1`           | [doc](../app-components/admin-policy-v1.md)           |
| `0x8004`     | `marmot.transport.nostr.routing.v1`      | [doc](../app-components/nostr-routing-v1.md)          |
| `0x8005`     | `marmot.group.message-retention.v1`      | [doc](../app-components/message-retention-v1.md)      |
| `0x8006`     | `marmot.group.agent-text-stream.quic.v1` | [doc](../app-components/agent-text-stream-quic-v1.md) |
| `0x8007`     | `marmot.group.avatar-url.v1`             | [doc](../app-components/group-avatar-url-v1.md)       |

## Upstream MLS extension draft ids

These values are pinned for the MLS extensions draft profile currently used by Marmot. If the upstream draft changes
these assignments, Marmot needs an explicit compatibility plan before changing wire behavior.

| Value    | Name                  | Upstream source                      |
| -------- | --------------------- | ------------------------------------ |
| `0x0001` | `app_components`      | MLS extensions draft `ComponentID`   |
| `0x0006` | `app_data_dictionary` | MLS extensions draft extension type  |
| `0x0008` | `app_data_update`     | MLS extensions draft proposal type   |
| `0x000a` | `self_remove`         | MLS extensions draft proposal type   |
| `0x000a` | `last_resort`         | MLS extensions draft extension type  |

`self_remove` and `last_resort` share the value `0x000a` but this is not an id collision: they are assigned in different
MLS registries — `self_remove` in the proposal-type namespace and `last_resort` in the extension-type namespace, as the
Upstream source column shows. An MLS value is only unique within its own registry.

The `app_components`, `app_data_dictionary`, `app_data_update`, and `self_remove` values match
draft-ietf-mls-extensions-09. The `last_resort` value is the extension-type assignment Marmot currently implements
through OpenMLS. Confirm `last_resort` against draft-09 before relying on it: the draft MAY track last-resort handling
in the component registry rather than as extension `0x000a`.

## Marmot custom MLS extension types

| Extension type | Name                                | Document                                                    |
| -------------- | ----------------------------------- | ----------------------------------------------------------- |
| `0xf2ef`       | `marmot.encrypted-device-name.v1`   | [doc](../features/multi-device.md)                         |
| `0xf2f0`       | `marmot.multi-device.v1`            | [doc](../features/multi-device.md)                         |
| `0xf2f1`       | `marmot.account-identity-proof.v1`  | [doc](./account-identity-proof-v1.md)                       |

## Marmot custom proposal types

No Marmot-owned custom MLS proposal type is assigned in this draft yet.

`IdentityRemove` is the first likely candidate. It MUST claim a proposal type here before becoming normative.

## Nostr event kinds used by Marmot

These event kinds are part of the current Nostr binding or MIP-era specs. Transport and feature docs own their exact
event shapes.

| Kind    | Name                                | Layer                               |
| ------- | ----------------------------------- | ----------------------------------- |
| `444`   | Marmot welcome rumor                | Nostr welcome transport             |
| `445`   | Marmot group message                | Nostr group transport               |
| `446`   | Push notification rumor             | Push notification transport         |
| `447`   | Push token request                  | Marmot app payload                  |
| `448`   | Push token list response            | Marmot app payload                  |
| `449`   | Push token removal                  | Marmot app payload                  |
| `450`   | Multi-device identity proof event   | Local signing template, not relayed |
| `1200`  | Agent text stream start             | Marmot app payload                  |
| `10050` | Push notification server relay list | Nostr account transport             |
| `30443` | Marmot KeyPackage event             | Nostr KeyPackage publication        |

The experimental agent text stream QUIC feature claims kind `1200` for durable stream start app events. Live stream
chunks are transient QUIC records. Future durable abort, media-final, or fallback preview app-event kinds MUST be added
to this registry before use.

## Exporter labels

Existing Marmot exporter uses SHOULD be treated as registered until their owning docs move or replace them.

Each entry is an `MLS-Exporter(label, context, length)` invocation: the first column is the exporter `label`, the second
is the `context`, and the third is the output length in bytes.

The `label` and `context` pair is the top-level domain separator. Owning documents define any additional key context
used below the exporter output.

| Label      | Context                    | Length   | Consumer                            |
| ---------- | -------------------------- | -------- | ----------------------------------- |
| `"marmot"` | `"group-event"`            | `32`     | kind `445` outer encryption key     |
| `"marmot"` | `"encrypted-media"`        | `32`     | MIP-04 media key input              |
| `"marmot"` | `"agent-text-stream-quic"` | `32`     | Agent text stream QUIC record crypto |
| `"marmot"` | `join_psk_id`              | `KDF.Nh` | multi-device external PSK material  |

Fixed `32`-byte outputs are used where the owning document feeds a 32-byte AEAD key or feature key schedule.
`KDF.Nh` is used for the multi-device join PSK because that output is external PSK material for the MLS ciphersuite KDF.

The multi-device join entry is versioned inside the structured `join_psk_id` context. A future incompatible join-PSK
design MUST register a new exporter label or context shape.
