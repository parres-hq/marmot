# marmot.group.profile.v1

Status: draft for internal review.

## Registry

- Component id: `0x8001`
- Name: `marmot.group.profile.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional
- Replaces: `marmot_group_data.name`, `marmot_group_data.description`

## State

```text
struct {
  opaque name<0..256>;
  opaque description<0..4096>;
} MarmotGroupProfileV1;
```

`name` and `description` are UTF-8 byte strings.

Protocol equality is byte equality. Clients MUST NOT normalize Unicode before hashing, signing, comparing, or storing
the component state.

## Update

The update payload is a full replacement state:

```text
MarmotGroupProfileV1 MarmotGroupProfileUpdateV1;
```

Partial updates are not defined in v1. A caller that wants to change only one field reads the current state, changes
that field, and sends a full replacement.

## Validation

A profile state is valid if:

- both fields are valid UTF-8
- `name` is at most 256 bytes
- `description` is at most 4096 bytes

An empty `name` is valid at the protocol layer. Applications MAY render a local fallback display name when `name` is
empty.

## Authorization

Any current member may send a standalone profile update proposal.

Only a current admin may commit a profile update.

An inline profile update requires the sender to be a current admin because the proposal sender and committer are the
same member.

The admin check is evaluated against the prior epoch state.

## Removal

This component MUST NOT be removed while listed as required in the GroupContext `app_components` component.

If the component is not required, removal means the group has no signed Marmot display profile.

## Migration

Migration from `marmot_group_data` copies `name` and `description` byte-for-byte after validating UTF-8 and length
limits.
