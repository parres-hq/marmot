# Application payloads

Status: draft for internal review.

Marmot app payloads use a Nostr event shape inside MLS.

This is a foundation rule. It is separate from the Nostr relay transport. A future non-Nostr transport would still carry
MLS application messages whose plaintext has this Nostr-shaped payload.

## Terminology

Use these terms consistently:

- `MLS application message`: the MLS content type that carries encrypted application bytes.
- `Marmot app payload`: the plaintext bytes inside an MLS application message.
- `Marmot app event`: the current Nostr-shaped object encoded as a Marmot app payload.
- `Delivered app payload`: a Marmot app payload that passed convergence and is safe to hand to the application.

Avoid using "application message" by itself when the sentence could mean either the MLS input or the app-facing output.

## Shape

A Marmot app event has the same fields as a Nostr event, except `sig`:

- `id`
- `pubkey`
- `created_at`
- `kind`
- `tags`
- `content`

`id` is the Nostr event id for the rest of the event shape. It is computed from the canonical Nostr event serialization
of `[0, pubkey, created_at, kind, tags, content]`. This is the same hash preimage Nostr uses before signing, even though
Marmot does not produce a Nostr signature for the inner Marmot app event.

The payload is not signed as a Nostr relay event. Relays MUST NOT be able to accept it as a standalone event. MLS
authenticates the sender as a group member, and the `pubkey` field identifies the Marmot account that authored the
message.

The missing `sig` is intentional. A client MUST NOT add a Nostr signature to the inner Marmot app event before placing
it inside MLS.

`id` is a Marmot app event id. It is separate from the MLS message id and from any outer transport event id.

## Encoding

A Marmot app payload that uses the unsigned Nostr event shape — including chat kind `9` and reaction kind `7` — is
serialized as one UTF-8 JSON object with exactly the members `id`, `pubkey`, `created_at`, `kind`, `tags`, and
`content`, and no others. Field values, tag arrays, and string content follow Nostr event conventions; the signature
member is absent.

Decoders MUST reject a payload that:

- contains a `sig` member;
- contains an unknown top-level member;
- contains duplicate object keys;
- carries transport routing tags — the matching sender-side prohibition is in
  [../protocol-core/group-messaging.md](../protocol-core/group-messaging.md) ("App payloads");
- has an `id` that does not match the canonical Nostr event id computed from the other members ("Shape" above).

If a future message kind needs binary content, canonical JSON, or another encoding rule, that rule belongs in the
message-kind document and MUST name the exact bytes carried inside MLS.

## Message kinds

The foundation only defines the shared envelope shape. It does not require every client to render every Nostr kind.

Feature or app-payload docs define which kinds are protocol-required, which kinds are optional, and how a client handles
an unsupported kind.

Unknown app-event kinds SHOULD NOT break group state. A client MAY ignore or display unsupported content unless the
owning feature document says the kind changes protocol state.

## Message edits (kind 1009)

Kind `1009` is an in-place replacement of a prior chat message's text. The edit references the original event id via a
single `e` tag; its `content` is the replacement plaintext. Edits are not chat — they MUST NOT render as a separate row
in the conversation transcript. Clients SHOULD overlay the latest replacement onto the original message body and SHOULD
indicate that the row has been edited.

```json
{
  "v": 1,
  "kind": 1009,
  "tags": [["e", "<hex event id of the edited message>"]],
  "content": "the replacement plaintext"
}
```

- The original message's projected `kind` does not change; only its rendered body is overlaid.
- The chat-list preview MUST NOT bump on an edit. An edit to a stale message must not reorder the conversation list.
- The unread count MUST NOT advance on an edit. A receiver who is caught up with the original is caught up with the
  edit.

Authorship is enforced client-side: an edit is honoured only when its authenticated author (the inner event signer)
equals the original message's author. A client receiving a kind `1009` whose signer differs from the target's signer
MUST ignore the edit. The runtime emits all kind `1009` rows it persists; the client decides display.

Multiple edits to the same target are ordered by their inner event's `created_at`. The most recent edit wins as the
overlaid body. A history surface MAY list each version with its timestamp.

A client receiving an edit whose target it has not yet ingested MAY hold the edit for a bounded window and apply it
when the target arrives, or drop it. Either choice is acceptable.

## Group system events (kind 1210)

Kind `1210` is a durable group system row: a record of an authenticated change to group state — a member added,
removed, or left; an admin granted or revoked; the group renamed; the group avatar changed. These rows are not chat.
A client MUST render them separately from kind `9` chat bubbles and MUST NOT treat their `content` as a chat body.

A kind `1210` row is **synthesized locally** from canonical group state, not sent as a message. When a client applies a
commit and the protocol surfaces a state-change notification (see
[`../protocol-core/inbound-processing.md`](../protocol-core/inbound-processing.md)), the client MAY derive the
corresponding kind `1210` row from that authenticated change. Because the row is derived from MLS-authenticated state
rather than a separately delivered message, it cannot be forged by a single member and converges across clients that
apply the same commit. A client MUST NOT depend on receiving a kind `1210` *message* over the wire to know that group
state changed; the state-change notification is authoritative. (A client or connector MAY still *send* a kind `1210`
event to post an explicit free-text notice; such a sent event is an assertion by its author, not a derived state fact.)

The `content` is JSON:

```json
{
  "v": 1,
  "system_type": "member_added",
  "text": "Member added",
  "data": { "actor": "<hex pubkey>", "subject": "<hex pubkey>" }
}
```

- `v` is the schema version (`1`).
- `system_type` names the change. Defined values: `member_added`, `member_removed`, `member_left`, `admin_added`,
  `admin_removed`, `group_renamed`, `group_avatar_changed`.
- `text` is a human-readable fallback only. Clients SHOULD render from `system_type` plus `data` so the row can be
  localized and re-resolved as display names change.
- `data` carries structured fields: `actor` (hex pubkey of the committing member, when attributable), `subject` (hex
  pubkey of the member the change concerns, for the member/admin types), and `name` (the new group name, for
  `group_renamed`).

The event SHOULD carry a `["system", system_type]` tag. A row is anchored to the epoch the change reached, so it sorts
into history at the point the change took effect.

## Relationship to transport events

The inner Marmot app event and an outer Nostr transport event are different objects.

When Marmot uses Nostr relays, the transport MAY wrap MLS bytes in signed or unsigned Nostr events such as kind `445` or
NIP-59 gift wraps. Those outer events are transport envelopes. They do not replace the inner app payload.
