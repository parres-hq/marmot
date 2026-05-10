# marmot.group.message-retention.v1

Status: sketch.

## Registry

- Component id: `0x8005`
- Name: `marmot.group.message-retention.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional
- Replaces: `marmot_group_data.disappearing_message_secs`

## State

```text
struct {
  uint64 disappearing_message_secs;
} MarmotMessageRetentionV1;
```

`disappearing_message_secs = 0` means disappearing messages are disabled.

Any nonzero value is a requested application retention duration in seconds.

## Update

The update payload is a full replacement state:

```text
MarmotMessageRetentionV1 MarmotMessageRetentionUpdateV1;
```

## Validation

A retention state is valid if `disappearing_message_secs` is no greater than the
maximum defined by the application profile.

This component governs application plaintext retention. It MUST NOT force
deletion of MLS state, retained anchors, pending message records, publish
obligations, or other protocol data before the protocol retention rules allow
that data to be discarded.

## Authorization

Any current member may send a standalone message-retention proposal.

Only a current admin may commit a message-retention update.

An inline message-retention update requires the sender to be a current admin
because the proposal sender and committer are the same member.

## Removal

Removal is allowed if this component is not listed as required in the
GroupContext `app_components` component.

Removal is equivalent to `disappearing_message_secs = 0`.

## Migration

Migration from `marmot_group_data` reads `disappearing_message_secs` as an
optional 8-byte big-endian integer. Empty means `0`.
