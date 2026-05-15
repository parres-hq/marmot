# marmot.group.agent-text-stream.quic.v1

Status: experimental draft.

## Registry

- Component id: `0x8006`
- Name: `marmot.group.agent-text-stream.quic.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required for groups that use QUIC agent text streams
- Owning feature: [agent-text-streams-quic.md](../features/agent-text-streams-quic.md)

## State

This component records the group-level policy for raw QUIC agent text streams.

It does not store stream transcripts, endpoint candidates, relay URLs, or app-event kinds. Live stream records stay
transient, and final content is carried by normal Marmot app payloads.

```text
uint8 MarmotAgentTextStreamQuicRoleMaskV1;

const uint8 receive = 0x01;
const uint8 send    = 0x02;
const uint8 fanout  = 0x04;

struct {
  uint8 required_member_roles;
  uint8 allowed_member_roles;
  uint32 max_plaintext_frame_len;
  uint32 replay_ttl_secs;
  uint16 padding_bucket_bytes;
} MarmotAgentTextStreamQuicV1;
```

`required_member_roles` is the set of role capabilities every member must advertise before joining the group.

`allowed_member_roles` is the set of role capabilities a member may advertise in this group.

For the first user-to-agent profile:

- `required_member_roles` includes `receive`;
- `allowed_member_roles` includes `receive` and `send`;
- `fanout` is allowed only when the group wants members or relays to advertise forwarding support.

`max_plaintext_frame_len` caps the plaintext bytes in one stream frame before record encryption.

`replay_ttl_secs` is the maximum time a group-approved relay may retain encrypted stream records for short replay.
`0` means no retained replay.

`padding_bucket_bytes` is the maximum padding bucket size for stream records. `0` means no feature-level padding
requirement. A first profile should keep this low; this feature is not trying to hide token cadence at high bandwidth
cost.

This component does not store QUIC endpoints or relay URLs. Endpoint discovery, relay discovery, relay authentication,
and direct-path probing belong in the raw QUIC transport binding. Per-stream candidates are carried by the start payload.

## Update

The update payload is a full replacement state:

```text
MarmotAgentTextStreamQuicV1 MarmotAgentTextStreamQuicUpdateV1;
```

## Validation

A state is valid if:

- `required_member_roles` is not empty;
- `required_member_roles` is a subset of `allowed_member_roles`;
- every bit in both role masks is one of `receive`, `send`, or `fanout`;
- `max_plaintext_frame_len` is nonzero and no greater than the application profile maximum;
- `replay_ttl_secs` is no greater than the application profile maximum;
- `padding_bucket_bytes` is no greater than the application profile maximum.

This component is for raw QUIC. WebTransport, HTTP/3, and WebSocket profiles require another component or a later
component version.

## Authorization

Any current member may send a standalone agent text stream QUIC update proposal.

Only a current admin may commit an update.

An inline update requires the sender to be a current admin because the proposal sender and committer are the same member.

## Removal

This component MUST NOT be removed while it is listed as required in the GroupContext `app_components` component.

If removed from a group that no longer requires it, live QUIC text streams are disabled for that group. Existing durable
Marmot messages remain valid.

## Migration

There is no MIP-era component to migrate from.
