# marmot.group.message-retention.v1

Status: draft for internal review.

## Registry

- Component id: `0x8005`
- Name: `marmot.group.message-retention.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional

## State

```text
struct {
  uint64 disappearing_message_secs;
} MarmotMessageRetentionV1;
```

`disappearing_message_secs = 0` means disappearing messages are disabled.

Any nonzero value is a requested application retention duration in seconds.

The retention duration is signed group state, but the transport-level expiry timestamp is computed from the sender's
app-payload `created_at` plus this duration (see [../protocol-core/group-setup.md](../protocol-core/group-setup.md) and
the active transport binding). The duration is authenticated; the base timestamp is the sender's own `created_at`, so a
sender that backdates or forward-dates `created_at` shifts when its own message expires. Disappearing-message expiry is
therefore advisory and inherits the trust already placed in the MLS-authenticated sender. It is not a deletion guarantee
enforced against a hostile sender.

## Update

The update payload is a full replacement state:

```text
MarmotMessageRetentionV1 MarmotMessageRetentionUpdateV1;
```

## Validation

A retention state is valid if `disappearing_message_secs` is no greater than the maximum defined by the application
profile.

This component governs application plaintext retention. It MUST NOT force deletion of MLS state, retained anchors,
pending message records, publish obligations, or other protocol data before the protocol retention rules allow that data
to be discarded.

## Authorization

Any current member MAY send a standalone message-retention proposal.

Only a current admin MAY commit a message-retention update.

## Removal

Removal is equivalent to `disappearing_message_secs = 0`.
