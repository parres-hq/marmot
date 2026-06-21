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
the active transport binding; for the Nostr binding that is "Message expiration" in
[../transports/nostr.md](../transports/nostr.md)). Transport expiry applies to application messages only: group-state
history — commits and proposals — never carries a transport expiry hint, so retention does not affect group-state
catch-up. The duration is authenticated; the base timestamp is the sender's
own `created_at`, so a sender that backdates or forward-dates `created_at` shifts when its own message expires.
Disappearing-message expiry is therefore advisory and inherits the trust already placed in the MLS-authenticated
sender. It is not a deletion guarantee enforced against a hostile sender.

## Update

The update payload is a full replacement state:

```text
MarmotMessageRetentionV1 MarmotMessageRetentionUpdateV1;
```

## Validation

Any `disappearing_message_secs` value in the `uint64` range is a valid retention state. v1 defines no protocol-level
maximum. An application MAY refuse to enable a duration its UI considers unreasonable, but that local cap is not signed
group state and MUST NOT invalidate otherwise-valid retention state received from the group.

This component governs application plaintext retention. It MUST NOT force deletion of MLS state, retained anchors,
pending message records, publish obligations, or other protocol data before the protocol retention rules allow that data
to be discarded.

## Authorization

Only an active admin MAY send a standalone message-retention proposal.

Only an active admin MAY commit a message-retention update.

## Removal

Removal is equivalent to `disappearing_message_secs = 0`.

## Migration

This component carries the `disappearing_message_secs` field from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
