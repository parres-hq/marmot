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

The payload is not signed as a Nostr relay event. Relays must not be able to accept it as a standalone event. MLS
authenticates the sender as a group member, and the `pubkey` field identifies the Marmot account that authored the
message.

The missing `sig` is intentional. A client must not add a Nostr signature to the inner Marmot app event before placing
it inside MLS.

`id` is a Marmot app event id. It is separate from the MLS message id and from any outer transport event id.

## Encoding

The owning message-kind document must define the exact app payload encoding.

For current Marmot chat-style messages, the payload should stay compatible with the unsigned Nostr event shape already
used by the MIP-era protocol: event fields, tag arrays, and string content follow Nostr event conventions, but the
signature field is absent. Decoders must reject a message whose `id` does not match the canonical Nostr event id for the
other fields.

If a future message kind needs binary content, canonical JSON, or another encoding rule, that rule belongs in the
message-kind document and must name the exact bytes carried inside MLS.

## Message kinds

The foundation only defines the shared envelope shape. It does not require every client to render every Nostr kind.

Feature or app-payload docs define which kinds are protocol-required, which kinds are optional, and how a client handles
an unsupported kind.

Unknown app-event kinds should not break group state. A client may ignore or display unsupported content unless the
owning feature document says the kind changes protocol state.

## Relationship to transport events

The inner Marmot app event and an outer Nostr transport event are different objects.

When Marmot uses Nostr relays, the transport may wrap MLS bytes in signed or unsigned Nostr events such as kind `445` or
NIP-59 gift wraps. Those outer events are transport envelopes. They do not replace the inner app payload.
