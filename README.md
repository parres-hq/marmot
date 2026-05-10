# Marmot Spec Rewrite Sandbox

Status: experimental.

This directory is a clean space for rewriting the Marmot spec by surface and
invariant. The existing MIP documents remain the historical source while this
draft settles.

The goal is to stop making every new feature edit the same old documents. Fixed
protocol surfaces should live in fixed documents. Feature work should add or
revise small versioned app components.

## Draft Map

- [laws.md](./laws.md) - rules that should hold across the whole protocol.
- [layout.md](./layout.md) - proposed shape for the rewritten spec set.
- [app-components.md](./app-components.md) - AppDataDictionary component model
  and current Marmot component registry.
- [app-components/](./app-components/) - draft component payload schemas.
- [publish-lifecycle.md](./publish-lifecycle.md) - publish-before-apply for
  locally generated group-state changes.
- [implementation-model.md](./implementation-model.md) - non-normative local
  implementation notes.

## Working Rules

- Keep this directory easy to delete or reshape.
- Prefer short normative rules over long explanation.
- Use "MUST", "SHOULD", and "MAY" only when the sentence is meant to become
  normative.
- Put transport-specific fields in transport-specific components.
- Put group semantics in group components.
- A new feature should usually add one app component or one component version.
- A feature should not require edits across identity, wire format, transport,
  lifecycle, and storage documents unless it changes those surfaces.
- Keep implementation architecture out of normative protocol documents.
