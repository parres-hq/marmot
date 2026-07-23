# AGENTS.md - app-components

Agent operating rules for the app-component surface. Read [`README.md`](README.md) for the full human-facing model
(component ids, negotiation, common rules, GroupContext update processing, default GroupContext authorization); the
cross-surface map is in [`../AGENTS.md`](../AGENTS.md).

## Scope

App components own the versioned MLS `app_data_dictionary` component bytes at GroupContext, LeafNode, KeyPackage, and
GroupInfo locations, plus component-owned `AppEphemeral` and SafeAAD bytes. One component id per file. The rules here
are mechanical and easy to get wrong, so treat this file as the checklist and the README as the model.

## Read order

1. [`README.md`](README.md) (Component IDs, Negotiation, Common Rules, GroupContext Update Processing, Default
   GroupContext Authorization).
2. [`../foundation/registries.md`](../foundation/registries.md) to claim the next free id, then
   [`../foundation/canonical-encoding.md`](../foundation/canonical-encoding.md) for the byte rules.
3. The component file you are adding or editing.

## Rules

- Component ids are private-use MLS range `0x8000..0xffff`. To add one, pick the next free id and register it in THREE
  places in the same change: [`../foundation/registries.md`](../foundation/registries.md), the README "Current Marmot
  Components" list, and the [`../layout.md`](../layout.md) tree. This trio is the most frequently missed step — for
  example `avatar-url` (`0x8007`) was once absent from the README list.
- The component id IS the major version. A breaking change gets a NEW component id and a NEW file; do not add a generic
  version field to the payload. A component-specific constant retained by an inherited schema is not version
  negotiation.
- Each component doc MUST define the full required set: component id, name, every valid entry location, bytes and
  validation per location, negotiation and presence requirements, lifecycle, mutation authorization, replacement or
  removal rules, and migration.
- GroupContext components additionally define state bytes, AppDataUpdate bytes, proposal authorization, commit
  authorization, and removal. LeafNode, KeyPackage, and GroupInfo components change with their containing MLS object
  and MUST NOT define AppDataUpdate as their mutation mechanism.
- Commit-scoped component data uses AppEphemeral. SafeAAD is reserved for component contributions to MLS
  `authenticated_data`; do not enable it merely to attach data to one Commit.
- Group-level component proposals and commits are admin-gated by default. A component MAY loosen this, but it MUST say
  so explicitly, against the admin set in `marmot.group.admin-policy.v1`.
- Unknown non-required component entries MUST be preserved byte-for-byte; never parse, sort inside, partially copy, or
  re-encode them.

## Verification

- After adding or renaming a component, grep that the id and file appear in
  [`../foundation/registries.md`](../foundation/registries.md), the README "Current Marmot Components" list, and
  [`../layout.md`](../layout.md).
- Confirm the file defines every location-appropriate requirement above.

## Pointers

- Up to the cross-surface map: [`../AGENTS.md`](../AGENTS.md).
- Features reference components; they do not duplicate them: [`../features/`](../features/README.md).
- Id source of truth and encodings: [`../foundation/registries.md`](../foundation/registries.md),
  [`../foundation/canonical-encoding.md`](../foundation/canonical-encoding.md).
