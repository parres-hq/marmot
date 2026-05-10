# AGENTS.md - spec

Agent map for the Marmot protocol spec rewrite sandbox.

## Scope

This directory is experimental spec text. It is for Marmot protocol surfaces
that a clean-room implementation would need:

- protocol laws and invariants;
- proposed spec layout by stable surface;
- publish-before-apply lifecycle;
- MLS app data dictionary component rules;
- versioned Marmot component dictionaries.

It is not the place for darkmatter module names, database schemas, queue
mechanics, local API shapes, or crate-specific test plans. Put those in
`implementation-model.md`, `docs/marmot-architecture/`, or crate docs.

## Read Order

1. `README.md`
2. `laws.md`
3. `layout.md`
4. `app-components.md`
5. `app-components/README.md`
6. `publish-lifecycle.md`
7. `implementation-model.md` only when local implementation guidance matters.

## Rules

- Laws speak as part of the spec: "Marmot does X" or "clients MUST do Y".
  Avoid "the spec should define" wording.
- Keep Marmot component ids in the private-use MLS range.
- Component major versions are represented by component ids. A breaking version
  gets a new component id and document.
- Component payloads are direct data dictionaries. Do not add a generic Marmot
  envelope inside each component.
- Keep transport data in transport components. Nostr routing belongs in
  `marmot.transport.nostr.routing.v1`.
- Treat Nostr relays in the Nostr routing component as canonical signed routing
  state for Nostr-routed groups.
- AppDataUpdate proposals may be inline or standalone. Inline is the default
  when the committer is authorized; standalone proposals cover request flows
  where another member must commit.

## Verification

After editing spec text, review matches from:

```sh
rg -n "the spec should|spec MUST|Spec-Defined|GroupEvent|\\bengine\\b|darkmatter|PendingStateRef|drain_auto_publish|confirm_published|publish_failed|relay hints|internal version|public registry" spec
```

Matches in `implementation-model.md` may be intentional. Matches in laws,
component dictionaries, or lifecycle docs usually need review.
