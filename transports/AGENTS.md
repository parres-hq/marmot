# AGENTS.md - spec/transports

Agent operating rules for the transport surface. Read [`README.md`](README.md) for the human orientation and the
transport-document checklist; the cross-surface map is in [`../AGENTS.md`](../AGENTS.md).

## Scope

A transport doc owns the outer envelope, delivery addressing, publish/fetch rules, transport-specific validation, and
any transport-owned app components (e.g. Nostr routing). One file per transport binding. Current bindings:
[`nostr.md`](nostr.md) (primary) and [`quic.md`](quic.md) (experimental agent-stream previews).

## Read order

1. [`README.md`](README.md) (transport-document checklist + Versioning).
2. [`../principles.md`](../principles.md) ("Keep identity, delivery addressing, and transport separate"; "Do not let
   transport behavior choose group state").
3. The transport file you are editing.

## Rules

- A transport doc MUST cover the README checklist (name/version, delivery addresses, envelopes, publish/fetch, dedup
  and replay inputs, validation-before-peeling, required capabilities, and metadata-privacy constraints).
- A transport doc MUST NOT define Marmot account identity, inner app-payload shape, MLS credential binding, group-state
  branch selection, or app-component payload bytes. It says how to find and deliver bytes, never which branch wins.
- Nostr routing and relays are signed group state owned by `marmot.transport.nostr.routing.v1`
  ([`../app-components/nostr-routing-v1.md`](../app-components/nostr-routing-v1.md)), not local hints.
- An interop-visible transport change needs an explicit hook (a new envelope version, a new kind/route/topic/frame
  type, a new app component id, or a new required capability) — git history is not a versioning mechanism.

## Verification

- Confirm the transport doc references only delivery mechanics, not group-state selection.
- Confirm Nostr kinds match those registered in [`../foundation/registries.md`](../foundation/registries.md) and that
  no removed kinds (legacy `443`, `10051`) linger.

## Pointers

- Up to the cross-surface map: [`../AGENTS.md`](../AGENTS.md).
- Branch selection and convergence: [`../protocol-core/`](../protocol-core/README.md).
- Signed routing state: [`../app-components/nostr-routing-v1.md`](../app-components/nostr-routing-v1.md).
