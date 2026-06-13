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

Transport docs MAY define routing ids, relay lists, publish targets, fetch rules, and transport-specific validation.
They SHOULD NOT redefine Marmot account identity or inner app payload shape.

## Message ids

A Marmot message id is used for duplicate detection, replay rejection, and for marking the losing commit in a
same-epoch race. It MUST be defined over the MLS security bytes, never over transport evidence.

The message id is:

```text
message_id = SHA-256(mls_message_bytes)
```

where `mls_message_bytes` is the recovered `MLSMessage` — the transport-independent MLS security bytes from "MLS bytes"
above, serialized as MLS defines, exactly as MLS authenticated them. It is not the transport envelope and not the inner
app payload. The id is exactly 32 bytes (the raw `SHA-256` output; there is no domain-separation prefix). A decoder
computes it over the recovered bytes without re-encoding, so two transport copies of the same MLS message yield the same
id.

This is the same `SHA-256`-over-`MLSMessage`-bytes construction used for `commit_digest` / `tip_digest` in
[../protocol-core/convergence.md](../protocol-core/convergence.md) ("Same-epoch races"): for a commit, its dedup
`message_id` is byte-for-byte its `commit_digest`. The dedup/replay use of the id is separate from its use as the
same-epoch ordering tie-breaker, but the bytes are computed identically, so an implementation needs only one hash.

A Nostr event id is transport evidence. It is not a Marmot consensus id.
