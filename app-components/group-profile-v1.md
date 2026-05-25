# marmot.group.profile.v1

Status: draft for internal review.

## Registry

- Component id: `0x8001`
- Name: `marmot.group.profile.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional

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

## Validation

A profile state is valid if:

- both fields are valid UTF-8
- `name` is at most 256 bytes
- `description` is at most 4096 bytes

An empty `name` is valid at the protocol layer. Applications MAY render a local fallback display name when `name` is
empty.

## Authorization

Any current member MAY send a standalone profile update proposal.

Only a current admin MAY commit a profile update.

The admin check is evaluated against the prior epoch state.

## Removal

If the component is not required, removal means the group has no signed Marmot display profile.
