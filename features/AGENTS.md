# AGENTS.md - spec/features

Agent operating rules for the feature surface. Read [`README.md`](README.md) for the human orientation and the
feature-document checklist; the cross-surface map is in [`../AGENTS.md`](../AGENTS.md).

## Scope

Feature docs describe optional or user-visible flows that span surfaces. The flow narrative lives here; the exact bytes
live in the owning component, transport, or foundation doc. This is the surface most prone to duplication, so the first
rule below is the load-bearing one.

## Read order

1. [`README.md`](README.md) (Relationship to app components + Feature document checklist).
2. [`../mip-coverage.md`](../mip-coverage.md) for where MIP-era behavior moved.
3. The owning component/transport/foundation docs, then the feature file you are editing.

## Rules

- A feature doc MUST NOT duplicate component schemas, MLS structures, transport event shapes, or foundation rules —
  reference them. If a byte layout appears in a feature doc, it has probably drifted from its owner.
- A feature SHOULD name every surface it changes and usually own at most one app-component version.
- Mandatory protocol flows belong in [`../protocol-core/`](../protocol-core/README.md) or
  [`../foundation/`](../foundation/README.md), not here, even when they used to live in a MIP.
- Interop-visible feature versions get a name inside the spec: a component id, a proposal id, an event kind, or a new
  feature document when the high-level flow changes enough to need both versions side by side. Git history is not
  version negotiation.

## Verification

- Grep the feature doc for `struct`/component-id definitions that should live in [`../app-components/`](../app-components/README.md);
  a feature doc should reference those, not define them.
- Confirm every surface the feature names resolves to a real owning doc and every link works.

## Pointers

- Up to the cross-surface map: [`../AGENTS.md`](../AGENTS.md).
- Component bytes: [`../app-components/`](../app-components/README.md).
- Delivery: [`../transports/`](../transports/README.md).
- Convergence interaction and retained history: [`../protocol-core/`](../protocol-core/README.md).
