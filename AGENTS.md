# AGENTS.md - spec

Agent map for the Marmot v2 protocol draft.

## Scope

This directory is internal draft spec text. It is for Marmot protocol surfaces that a clean-room implementation would
need:

- principles for organizing and writing the spec;
- foundation rules for identity, message payloads, encoding, MLS, wire bytes, and registries;
- proposed spec layout by stable surface;
- protocol-core flows for group setup, joining, messaging, lifecycle, convergence, and retained history;
- MLS app component rules;
- versioned Marmot component payloads;
- transport bindings;
- feature-level flows.

It is not the place for darkmatter module names, database schemas, queue mechanics, local API shapes, or crate-specific
test plans. Put those in `implementation-model.md`, `docs/marmot-architecture/`, or crate docs.

## Read Order

1. `README.md`
2. `principles.md`
3. `foundation/README.md`
4. `protocol-core/README.md`
5. `layout.md`
6. `app-components/README.md`
7. `transports/README.md`
8. `features/README.md`
9. `mip-coverage.md`
10. `implementation-model.md` only when local implementation guidance matters.

## Rules

- Principles explain how to write the spec. Keep exact client requirements in the document for the surface they affect.
- Keep Marmot component ids in the private-use MLS range.
- Component major versions are represented by component ids. A breaking version gets a new component id and document.
- Component payloads are direct bytes for that component id. Do not add a generic Marmot envelope inside each component.
- Keep transport data in transport components. Nostr routing belongs in `marmot.transport.nostr.routing.v1`.
- Treat Nostr relays in the Nostr routing component as canonical signed routing state for Nostr-routed groups.
- Keep app components in `app-components/`. Feature docs may require and reference them.
- Transport docs own outer envelopes, delivery addressing, publish targets, fetch rules, and transport validation.
- Protocol-core docs own required group flows and group-state transitions.
- Feature docs own optional or user-visible flows and cross-reference the surfaces that implement them.
- AppDataUpdate proposals may be inline or standalone. Inline is the default when the committer is authorized;
  standalone proposals cover request flows where another member must commit.

## Verification

After editing spec text, review matches from:

```sh
rg -n \
  "the spec should|spec MUST|Spec-Defined|GroupEvent|\\bengine\\b|darkmatter" \
  spec
rg -n \
  "PendingStateRef|drain_auto_publish|confirm_published|publish_failed" \
  spec
rg -n \
  "relay hints|internal version|public registry" \
  spec
```

Matches in `implementation-model.md` may be intentional. Matches in principles, component dictionaries, or lifecycle
docs usually need review.
