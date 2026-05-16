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

## Marmot custom proposal types

No Marmot-owned custom MLS proposal type is assigned in this draft yet.

`IdentityRemove` is the first likely candidate. It must claim a proposal type here before becoming normative.

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
| `10050` | Push notification server relay list | Nostr account transport             |
| `10051` | KeyPackage relay list               | Nostr account transport             |
| `30443` | Marmot KeyPackage event             | Nostr KeyPackage publication        |

The experimental agent text stream QUIC feature does not claim a Nostr event kind in this draft. Live stream chunks are
transient QUIC records, and any future durable start, final, abort, or fallback preview app-event kinds must be added to
this registry before use.

## Exporter labels

Existing Marmot exporter uses should be treated as registered until their owning docs move or replace them.

| Label                          | Context owner         | Output                          |
| ------------------------------ | --------------------- | ------------------------------- |
| `"marmot" / "group-event"`     | Nostr group transport | kind `445` outer encryption key |
| `"marmot" / "encrypted-media"` | encrypted media       | media key material              |
| `"marmot-mip06-join-psk-v1"`   | multi-device join     | external PSK material           |
