# AGENTS.md - spec/app-components

Agent operating rules for the app-component surface. Read [`README.md`](README.md) for the full human-facing model
(component ids, negotiation, common rules, update processing, default authorization); the cross-surface map is in
[`../AGENTS.md`](../AGENTS.md).

## Scope

App components own the versioned MLS `app_data_dictionary` component bytes. One component id per file. The rules here
are mechanical and easy to get wrong, so treat this file as the checklist and the README as the model.

## Read order

1. [`README.md`](README.md) (Component IDs, Negotiation, Common Rules, Update Processing, Default Authorization).
2. [`../foundation/registries.md`](../foundation/registries.md) to claim the next free id, then
   [`../foundation/canonical-encoding.md`](../foundation/canonical-encoding.md) for the byte rules.
3. The component file you are adding or editing.

## Rules

- Component ids are private-use MLS range `0x8000..0xffff`. To add one, pick the next free id and register it in THREE
  places in the same change: [`../foundation/registries.md`](../foundation/registries.md), the README "Current
  Components" list, and the [`../layout.md`](../layout.md) tree. This trio is the most frequently missed step — for
  example `avatar-url` (`0x8007`) was once absent from the README list.
- The component id IS the major version. A breaking change gets a NEW component id and a NEW file; there is no second
  version field in the payload.
- Each component doc MUST define the full required set: component id, name, entry location, state bytes, update bytes,
  validation, proposal authorization, commit authorization, removal rule, and migration rule.
- Group-level component commits are admin-gated by default. A component may loosen this, but it MUST say so explicitly,
  against the admin set in `marmot.group.admin-policy.v1`.
- Unknown non-required component entries MUST be preserved byte-for-byte; never parse, sort inside, partially copy, or
  re-encode them.

## Verification

- After adding or renaming a component, grep that the id and file appear in
  [`../foundation/registries.md`](../foundation/registries.md), the README "Current Components" list, and
  [`../layout.md`](../layout.md).
- Confirm the file defines all ten required sections above.

## Pointers

- Up to the cross-surface map: [`../AGENTS.md`](../AGENTS.md).
- Features reference components; they do not duplicate them: [`../features/`](../features/README.md).
- Id source of truth and encodings: [`../foundation/registries.md`](../foundation/registries.md),
  [`../foundation/canonical-encoding.md`](../foundation/canonical-encoding.md).
