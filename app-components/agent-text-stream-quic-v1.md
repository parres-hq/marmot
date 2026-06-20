# marmot.group.agent-text-stream.quic.v1

Status: experimental draft for internal review.

## Registry

- Component id: `0x8006`
- Name: `marmot.group.agent-text-stream.quic.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required for groups that are agent-stream-ready under the raw QUIC profile
- Owning feature: [agent-text-streams-quic.md](../features/agent-text-streams-quic.md)

## State

This component records the group-level policy for the raw QUIC live-preview path of agent text streams.

Embedding the transport name (`quic`) in the component id and name is a deliberate exception to the usual layering: the
bytes this component owns are generic group policy (role masks and frame/replay/padding caps), but the role capabilities
and live-stream behavior it gates are specific to the raw QUIC binding, so a non-QUIC stream profile (WebTransport,
HTTP/3, WebSocket) gets its own component id and file rather than reusing this one.

It does not store stream transcripts, endpoint candidates, relay URLs, or app-event kinds. Live stream records stay
transient, and final content is carried by normal Marmot app payloads. A group can require this component so every member
understands the stream start/final-message contract without requiring every member to open QUIC connections.

Stream record keys use the reusable `MLS-Exporter("marmot", "agent-text-stream-quic", 32)` secret defined by the feature
document because send, watch, retry, and resume paths MAY need the same epoch secret more than once.

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

Each role-mask bit names one member role capability. A member advertises a role by listing that capability's MLS
extension type in its LeafNode capabilities; the extension type ids are registered in
[../foundation/registries.md](../foundation/registries.md).

| Bit    | Role      | Role capability                                    | Extension type |
| ------ | --------- | -------------------------------------------------- | -------------- |
| `0x01` | `receive` | `marmot.feature.agent_text_stream_quic.receive.v1` | `0xf2d1`       |
| `0x02` | `send`    | `marmot.feature.agent_text_stream_quic.send.v1`    | `0xf2d2`       |
| `0x04` | `fanout`  | `marmot.feature.agent_text_stream_quic.fanout.v1`  | `0xf2d4`       |

`receive` means the member understands this component and the MLS-delivered start/final stream anchors. A `receive`
member can ignore raw QUIC endpoint candidates and wait for the final kind `9` message; it is still a valid participant.
`receive` does not mean the member can open raw QUIC streams or render live deltas.

`send` means the member can originate raw QUIC preview records for this profile and publish the matching durable
start/final messages. `fanout` means the member or helper can forward stream records for others, for example through a
broker.

`required_member_roles` is the set of role capabilities every member MUST advertise before joining the group. It is
enforced at every membership change:

- a client MUST NOT invite a member whose KeyPackage does not advertise every role capability named by
  `required_member_roles`;
- a joiner that does not support every role capability named by `required_member_roles` MUST NOT join the group.

`allowed_member_roles` is the set of role capabilities a member MAY advertise in this group.

For the first user-to-agent profile:

- `required_member_roles` includes `receive` so every member can process agent-stream start/final semantics;
- `allowed_member_roles` includes `receive` and `send`;
- `send` and `fanout` are advertised only by members or helpers that implement the live raw QUIC data plane;
- `fanout` is allowed only when the group wants members or relays to advertise forwarding support.

`max_plaintext_frame_len` caps the plaintext bytes in one stream frame before record encryption.

`replay_ttl_secs` is the maximum time a group-approved relay MAY retain encrypted stream records for short replay.
`0` means no retained replay.

`padding_bucket_bytes` is reserved in v1. No padding mechanism is defined, and senders MUST NOT emit padding. The field
stays in the byte layout as a forward-compatibility reservation, so already-deployed state remains valid; a future
version that defines a padding construction will state how padded bytes relate to the transcript hash. Until then a
producer SHOULD write `0`, and a decoder accepts any value within the application profile maximum without acting on it.

The first application profile uses these maximums:

- `max_plaintext_frame_len <= 65519`, so a maximum-length frame's ciphertext (`plaintext_len + 16` AEAD tag bytes)
  fits the record's `ciphertext<0..2^16-1>` field bound;
- `replay_ttl_secs <= 300`;
- `padding_bucket_bytes <= 4096`.

This component does not store QUIC endpoints or relay URLs. Endpoint discovery, relay discovery, relay authentication,
and direct-path probing belong in the raw QUIC transport binding ([../transports/quic.md](../transports/quic.md)).
Per-stream candidates are carried by the start payload.

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

This component is for the raw QUIC live-preview profile. WebTransport, HTTP/3, and WebSocket live-preview profiles
require another component or a later component version. The durable final kind `9` message remains ordinary Marmot chat
content regardless of the live-preview transport.

## Authorization

Any current member MAY send a standalone agent text stream QUIC update proposal.

Only an active admin MAY commit an update.

## Removal

If removed from a group that no longer requires it, live QUIC text streams are disabled for that group. Existing durable
Marmot messages and final kind `9` stream messages remain valid.

## Migration

There is no MIP-era component to migrate from.
