# AGENTS.md - spec

Agent map for the Marmot v2 protocol draft.

## Scope

This directory is internal draft spec text for protocol surfaces a clean-room implementation would need. The canonical
directory tree, surface ownership model, and feature/component split live in `layout.md`.

Do not put darkmatter module names, database schemas, queue mechanics, local API shapes, or crate-specific test plans in
normative spec files. Put those in `implementation-model.md`, `docs/marmot-architecture/`, or crate docs.

## Read Order

1. `README.md`
2. `layout.md`
3. `principles.md`
4. The README for the surface you are changing.
5. `mip-coverage.md` only when mapping from current MIPs.
6. `implementation-model.md` only when local implementation guidance matters.

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
