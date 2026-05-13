# Wire envelopes

Status: draft for internal review.

Marmot separates application payloads, MLS security bytes, and transport delivery.

```text
application payload
  -> MLS message or MLS Welcome
  -> transport envelope
```

Each layer has a different job.

## Application payload

Marmot application payloads use the unsigned Nostr event shape defined in
[application-messages.md](./application-messages.md).

The inner payload is not signed as a Nostr relay event and is not published directly to relays. MLS authenticates the
sender to the group.

## MLS bytes

MLS messages and MLS Welcomes are the transport-independent security bytes.

Protocol-core docs decide which MLS bytes become canonical group state. Transport arrival order, transport timestamps,
outer transport ids, subscription order, and local receive order do not choose the canonical branch.

## Transport envelopes

A transport envelope carries MLS bytes to recipients.

For example, the Nostr transport docs define the current relay shapes, including kind `445` group delivery, kind `30443`
KeyPackage publication, and NIP-59 welcome delivery. A future transport can carry the same MLS and application bytes in
a different outer envelope.

Transport docs may define routing ids, relay lists, publish targets, fetch rules, and transport-specific validation.
They should not redefine Marmot account identity or inner app payload shape.

## Message ids

Any message id used for duplicate detection, replay, or branch selection must be defined over Marmot or MLS bytes.

A Nostr event id is transport evidence. It is not a Marmot consensus id.
