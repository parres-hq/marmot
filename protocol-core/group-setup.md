# Group construction and settings

Status: draft for internal review.

This document describes group creation and the signed settings every member must agree on.

A Marmot group is an MLS group plus Marmot group state. The exact byte formats for Marmot group state live in app
component docs.

## Surfaces

- Foundation MLS protocol and capability negotiation.
- Protocol-core publish lifecycle and convergence.
- App components for profile, admin policy, routing, image, and message retention state.
- The active transport binding, if the group needs transport-owned routing state.
- Canonical encoding for every component state and update payload.

## Behavior

Every Marmot group has an MLS group id. That id is private group security state and must not be published through a
transport envelope unless a future document explicitly changes that rule.

Before creating a group or adding a member, clients check that the target KeyPackages support the capabilities required
by the group. A group must not be created with features that the initial members cannot process.

Group settings are authenticated group state. A client must not treat local UI preferences, locally observed delivery
data, or cached transport data as group settings.

Group creation requires `required_capabilities`, `ratchet_tree`, `app_data_dictionary`, and the app components required
by the selected feature set.

## Creation flow

When creating a group, the creator chooses the initial required feature set, initial members, initial admin policy,
transport routing state, and optional profile settings.

If the selected transport requires signed group routing state, creation includes that transport's routing component.

If the group has a human-visible profile, creation includes `marmot.group.profile.v1`.

If the group has admin-gated settings or membership changes, creation includes `marmot.group.admin-policy.v1`.

If the group has a Blossom-backed group image, creation includes `marmot.group.blossom.image.v1`.

If the group has disappearing messages, creation includes `marmot.group.message-retention.v1`.

## Updates

Group settings change through MLS group-state updates. The client prepares the update, publishes the required bytes,
and applies the pending state only after the publish obligation succeeds.

Settings updates are admin-gated by default. A component may define a looser rule, but it must say so explicitly.

Self-update Commits and dedicated SelfRemove-only Commits do not change group settings and do not require admin
authorization.

## Admin policy

Admin authority is based on Marmot account identity, not on MLS leaf id. If an account has multiple leaves in a group,
the admin policy applies to each current leaf with that account identity.

A settings update that would leave the group with no active admin is invalid.

Admins who want to use SelfRemove must first leave the admin set through an admin-policy update. The member-departure
doc owns the detailed leave flow.

## Message retention

When message retention is enabled, the transport binding applies its own retention hint, if it has one. The timestamp or
duration is derived from the inner app payload timestamp plus the retention duration.

Retention is group state, not a sender preference. A sender-supplied expiration tag is replaced or removed according to
the active retention component.
