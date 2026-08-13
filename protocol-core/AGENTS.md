# AGENTS.md - protocol-core

Agent operating rules for the protocol-core surface. Read [`README.md`](README.md) for the human orientation; the
cross-surface map is in [`../AGENTS.md`](../AGENTS.md).

## Scope

Protocol-core owns the required group flows and group-state transitions every transport and feature relies on: group
setup, joining, messaging, member departure, the group-state lifecycle, publish-before-apply, inbound processing,
convergence, retained history, and restart behavior. It says *when* MLS-valid bytes become canonical group state.

## Read order

1. [`README.md`](README.md) (big picture + main flows), then [`group-state.md`](group-state.md).
2. The convergence spine: [`convergence.md`](convergence.md), [`publish-lifecycle.md`](publish-lifecycle.md),
   [`retained-history.md`](retained-history.md), [`durability.md`](durability.md).
3. The specific flow doc you are editing.

## Rules

- This is the most-violated boundary in the spec. NO transport specifics here: no Nostr kinds, event ids, relay URLs,
  `h` tags, or gift wraps. A transport doc says how bytes arrive; protocol-core says when they become canonical.
- Transport arrival order, transport timestamps, outer event ids, subscription order, and local receive order MUST NOT
  choose the canonical branch (see [`README.md`](README.md), "Core rule").
- NO local implementation names: no module, queue, database, or API names. Those belong in
  [`../implementation-model.md`](../implementation-model.md).
- Describe every state change completely: name the prior state, input bytes, validation, authorization, the
  deterministic update, output bytes, and the rejection result (see [`../principles.md`](../principles.md), "Describe
  state changes completely").
- Keep lifecycle-state and disposition vocabularies mapped to [`../foundation/errors.md`](../foundation/errors.md).
  Keep convergence-status names consistent between [`group-state.md`](group-state.md) and
  [`convergence.md`](convergence.md); they are status projections, not input-disposition categories.

## Verification

- When adding, renaming, or removing a spec document, update [`../layout.md`](../layout.md) and this surface's
  [`README.md`](README.md) in the same change.
- Run the leak grep from [`../AGENTS.md`](../AGENTS.md) ("Verification") scoped to this directory; confirm no
  transport address shapes or darkmatter code names leaked in.
- Confirm any disposition or outcome name you introduce maps to a category in
  [`../foundation/errors.md`](../foundation/errors.md).

## Pointers

- Up to the cross-surface map: [`../AGENTS.md`](../AGENTS.md).
- Delivery and envelopes only: [`../transports/`](../transports/README.md).
- Component byte changes: [`../app-components/`](../app-components/README.md).
- Encodings and registries: [`../foundation/`](../foundation/README.md).
