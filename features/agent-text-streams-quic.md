# Agent text streams over QUIC

Status: experimental brainstorming draft.

This document sketches a Marmot feature for live agent and LLM text streams inside an existing group. It is intentionally
roomy. The goal is to capture the design space before turning any part of it into protocol text.

The working idea:

- MLS remains the group membership, authentication, epoch, and key agreement layer.
- A group that uses this feature requires support at group creation.
- The group carries shared stream configuration in
  [`marmot.group.agent-text-stream.quic.v1`](../app-components/agent-text-stream-quic-v1.md).
- Marmot application messages remain the durable group history.
- QUIC carries short-lived encrypted stream records for live text deltas.
- The final transcript, or a reference to it, lands back in the group as a normal Marmot app payload.

This is for text-first agent output: assistant tokens, tool logs, planning notes, command output previews, and similar
incremental data. Images, files, and rich media should normally stay in the encrypted media feature and be referenced from
the stream or final transcript.

## Core invariant

This feature is an ephemeral live-output channel above MLS. It must not move group membership, durable history, or final
message semantics into QUIC.

The MLS-delivered start app payload authorizes and names one preview stream. QUIC records are renderable only because
they match that MLS anchor. The MLS-delivered final app payload ends the preview and becomes the durable answer.

A client that stores conversation history, indexes content, triggers normal message notifications, or runs automation
uses the final delivered app payload. Preview frames need an explicit provisional marker until they are verified or
replaced.

This draft does not allocate Nostr event kinds for stream chunks. Future app payload kinds for start, final, abort, or
fallback preview updates must be registered in [registries.md](../foundation/registries.md) before use.

## Why this exists

MLS application messages are discrete messages. A client can send one MLS application message per chunk, but that makes
the group history carry transient UI data and gives the MLS layer work it does not need.

Agent output wants different behavior:

- the UI should start showing text quickly;
- multiple streams may run at the same time;
- one stalled stream should not block other group work;
- users should be able to cancel a stream without closing the group;
- offline members should still receive a normal durable result later;
- a relay or fanout server should not see plaintext.

QUIC gives the transport shape this wants: one connection, many independent ordered streams, stream reset, stream-level
flow control, and better mobile path behavior than a single TCP connection. Marmot still needs its own end-to-end record
encryption on top because QUIC TLS protects only the hop between two QUIC endpoints.

## User-visible shape

A member starts an agent response in a group. Other online members see text appear as the agent produces it. They may see
tool output, citations, status labels, or partial structured data as separate child streams if the client supports them.

When the response finishes, the sender posts a normal Marmot app payload containing the final answer, a transcript hash,
or a media/blob reference. That final payload is the durable group message. Stream chunks are a live preview unless the
feature later defines a retained-stream mode.

If a recipient is offline, they miss the live stream and read the final group message when they sync.

If the stream is cancelled, the sender posts a final abort or replacement message if the cancellation should be visible
in group history. Local UI can also drop an unanchored stream without writing anything durable.

## Surfaces

This feature touches several surfaces:

- Foundation: Marmot app payload shape for stream start, finish, abort, and optional control events.
- MLS protocol: exporter-derived stream secrets, epoch pinning, and future Safe exporter migration.
- Protocol core: convergence treatment of start and final app payloads.
- App component: [`marmot.group.agent-text-stream.quic.v1`](../app-components/agent-text-stream-quic-v1.md) group
  configuration.
- Transport: QUIC stream session setup, relay or fanout behavior, routing, retry, stream reset, and diagnostics.
- Feature: live text semantics, chunk record types, transcript anchoring, cancellation, and fallback behavior.
- Encrypted media: images and files referenced during or after a stream.

Exact QUIC transport bytes should live in a future QUIC transport document. Exact app event payloads should live in the
message-kind document or feature section that owns them.

## Non-goals

- Do not make MLS itself a byte-stream protocol.
- Do not require every text delta to become durable group history.
- Do not send images as inline stream chunks unless a later media-specific mode needs it.
- Do not treat QUIC transport encryption as Marmot end-to-end encryption.
- Do not require Nostr relays to understand or forward QUIC stream chunks.

## Capability and group requirement

The feature capability is split by role:

```text
marmot.feature.agent_text_stream_quic.receive.v1
marmot.feature.agent_text_stream_quic.send.v1
marmot.feature.agent_text_stream_quic.fanout.v1
```

KeyPackages advertise support for this feature the same way they advertise other Marmot capabilities. They also
advertise support for the app component id used by the group configuration.

Groups that use live agent text streams require `marmot.group.agent-text-stream.quic.v1` in GroupContext
`app_components`. A member that cannot understand the component and the required role capabilities cannot join that
group.

For the first user-to-agent profile:

- every member supports `receive`;
- the agent member supports `send`;
- `fanout` is optional and may be provided by an agent process, a desktop device, or a relay service.

Agent identities advertise these role capabilities like any other Marmot member. There is no special capability channel
for agents in this draft.

This draft focuses on raw QUIC. WebTransport over HTTP/3 and WebSocket fallback are out of scope for the first version.

## High-level flow

### 0. Pairing and group setup

A common setup is one user-owned device talking to one user-owned agent host:

1. The desktop agent CLI creates or refreshes a Marmot KeyPackage.
2. The mobile app scans a QR code or another short pairing payload that points to that KeyPackage.
3. The mobile app creates a Marmot group for this agent session, requiring `marmot.group.agent-text-stream.quic.v1`.
4. The agent joins as a normal Marmot group member.
5. The user sends prompts as ordinary durable Marmot app payloads.
6. The agent streams live response chunks over QUIC, then posts the final response through MLS.

Each group is one agent session. A user can have several groups with the same agent host if they want separate
conversations, workspaces, or authorization boundaries.

The pairing payload is outside this feature. It can be a normal KeyPackage discovery flow, a QR wrapper around a
KeyPackage reference, or another Marmot-approved invite path.

### 1. Start message

The sender publishes a normal Marmot app payload through MLS:

```text
AgentTextStreamStartV1 {
  stream_id,
  sender_id,
  agent_id,
  group_id_hint,
  mls_epoch,
  transcript_policy,
  direct_quic_candidates,
  relay_candidates,
  crypto_suite,
  chunk_profile,
  created_at,
  optional_prompt_commitment,
  optional_parent_message_id
}
```

This message is durable. It tells the group that later QUIC stream records with `stream_id` belong to this group and
sender.

It is a stream anchor, not the final response. Clients can use it to authorize preview rendering, allocate local UI state,
and derive stream keys, but they should not treat the later QUIC chunks as group history.

The `stream_id` should be unguessable or derived from the start payload. A practical first rule is a 32-byte random
identifier generated by the sender, with the MLS-delivered start event id as the durable anchor.

`direct_quic_candidates` are short-lived endpoints for this stream attempt. They can include LAN addresses, public
addresses, or NAT-discovered candidates. They are not stable group state.

`relay_candidates` may point to relays from the group app component, account policy, or the sender's current runtime.
Stable relay policy belongs in the app component. Per-stream candidates belong in the start message.

### 2. QUIC session

The sender and recipients connect to a QUIC fanout service, direct peer, or group relay.

Possible deployment modes:

- Sender fanout: the sender opens a QUIC connection to each recipient or recipient relay.
- Relay fanout: the sender uploads encrypted records once; the relay forwards them to online recipients.
- Agent-host fanout: an agent service streams encrypted records to the group after receiving an MLS-authorized start.
- Hybrid fanout: Nostr or another durable transport carries start and final messages; QUIC carries only transient chunks.

Relay fanout is probably the most useful first shape. It matches how agent services tend to run, and it avoids asking a
phone to maintain many outbound streams at once.

The fanout service is not trusted with plaintext. It can see connection metadata, stream ids, record sizes, timing, and
recipient sets unless a future transport binding hides more of that.

### 2a. Relay weight

For text streams, a relay can stay small if it is only a transport helper. Three roles have different cost:

- Rendezvous service: exchanges endpoint candidates and auth material; carries no stream data; very light.
- Packet relay: forwards opaque encrypted UDP or QUIC packets when direct paths fail; cost is mostly egress bandwidth.
- Application fanout relay: terminates QUIC or WebTransport, accepts encrypted stream records, and forwards them to
  recipients; cost grows with active connections, fanout, buffering, reconnect churn, quotas, and retained replay.

A first relay should have bounded behavior:

- no plaintext access;
- short-lived stream sessions;
- small per-recipient buffers;
- hard quotas and rate limits;
- no default retained replay;
- final transcript storage through normal Marmot app payloads.

For one user's phone-to-desktop agent stream, this should be cheap to run. Large public fanout, retained replay, or media
streaming changes the operating profile.

### 3. Stream records

Each live update is a small encrypted record. The record format should be binary, length-delimited, and easy to parse
without allocating large buffers.

Candidate outer record:

```text
AgentTextStreamRecordV1 {
  version,
  stream_id,
  mls_epoch,
  sender_id,
  seq,
  record_type,
  flags,
  ciphertext,
  optional_signature
}
```

Candidate plaintext frame:

```text
TextDelta {
  utf8_delta
}

ToolDelta {
  tool_call_id,
  stream_name,
  utf8_delta
}

Status {
  code,
  display_text
}

Checkpoint {
  transcript_hash_so_far
}

Abort {
  reason_code,
  replacement_message_id
}

FinalNotice {
  final_message_id,
  transcript_hash
}
```

Text frames should be valid UTF-8 after reassembly. A sender may split across token boundaries, but it should avoid
splitting inside a UTF-8 scalar value if that makes receivers harder to implement.

Receivers should be able to render incrementally and recover if a chunk is missing. The simplest rule is that each QUIC
stream is ordered and reliable, so a missing byte range blocks that stream.

For the first version, tools, citations, status updates, and text deltas are typed frames on the main text stream. Child
streams are deferred until there is a concrete need for independent flow control between lanes.

### 3a. App-visible preview events

Stream records arrive over a separate raw QUIC connection, but they are still delivered to the app as soon as they
decrypt and pass basic sequence checks. The app needs those provisional events so it can render the agent response while
the agent is still producing it.

Preview events are not `Delivered app payload`s from
[application-messages.md](../foundation/application-messages.md). Implementations should expose them through a separate
local preview path or mark them as provisional before handing them to application code.

The app must keep the preview label clear in its own state:

- preview chunks are displayable before the final MLS message arrives;
- preview chunks are not durable group history;
- preview chunks should not trigger automation unless the application explicitly accepts preview risk;
- the final MLS app payload replaces or verifies the preview;
- a transcript-hash mismatch makes the preview unverified.

### 4. Final group message

When the agent finishes, the sender publishes a normal Marmot app payload:

```text
AgentTextStreamFinalV1 {
  stream_id,
  final_text_or_reference,
  transcript_hash,
  chunk_count,
  finished_at,
  optional_usage,
  optional_model_info,
  optional_media_refs
}
```

This final payload is the group history item and authoritative completion. The default timeline behavior is to replace
the live preview with this final message. A client may keep preview chunks only as local provisional or diagnostic state,
or use the final message to mark the preview as verified.

If the final response is large, it can use encrypted media/blob storage and put the reference in the final message.

## Key derivation sketch

The stream key should be derived from the MLS epoch in which the start message is valid.

Candidate derivation:

```text
stream_secret = MLS-Exporter(
  "marmot.agent-text-stream.v1",
  context = "v1" ||
            group_id ||
            stream_id ||
            mls_epoch ||
            sender_id ||
            start_event_id,
  32
)

record_key  = HKDF-Expand(stream_secret, "record key", 32)
nonce_base  = HKDF-Expand(stream_secret, "record nonce", 12)
signing_ctx = HKDF-Expand(stream_secret, "signing context", 32)
```

Candidate AEAD:

```text
nonce = nonce_base XOR uint96_be(seq)
aad   = version || group_id_hash || stream_id || mls_epoch || sender_id || seq || record_type || flags
ct    = AEAD_Encrypt(record_key, nonce, aad, plaintext_frame)
```

ChaCha20-Poly1305 is a good first candidate because Marmot already uses it for MIP-era encrypted media. AES-GCM is also
reasonable when a platform stack makes it easier or faster.

The exact exporter label and context need to be registered if this feature becomes real. A future version should prefer
the MLS Extensions Safe framework when the backend support exists.

## Sender authentication

The exporter secret is group shared. Every current member can derive the same `record_key`. That gives confidentiality
against outsiders, but it does not prove which group member created a chunk.

### Preview mode is the first version

Chunks are treated as untrusted live preview. The final MLS app payload is authoritative because MLS authenticates it as
an application message from the sender.

This matches the user-to-agent case: the live stream improves the UI, while the final response is the message that group
history, search, citations, and automation should trust.

An application must not treat unsigned chunks as durable instructions. A malicious current member could forge preview
chunks that later fail transcript-hash validation or disappear when the final message arrives.

### Deferred: signed chunk mode

Each record or batch is signed by the Marmot account/device identity:

```text
sig = Sign(sender_signing_key,
           "marmot agent text stream chunk v1" ||
           aad ||
           ciphertext ||
           previous_record_hash)
```

This gives live chunks sender authenticity. Signing every chunk is probably fine for text if chunks are batched every
50-250 ms. For higher-rate output, sign checkpoint frames and include a hash chain.

Signed chunks are deferred. They may be useful for groups where preview text can trigger automation before the final
message lands.

### Deferred: stream signing key mode

The start message carries a short-lived public signing key for the stream. The sender signs the start message with its
Marmot identity, then signs chunks with the stream key.

This reduces long-term key use and lets an agent process hold only a stream-limited signing key. The final MLS message
can include the stream public key and transcript hash again.

This is also deferred. It may become the right shape for hosted agent services that should not hold the user's long-term
signing key.

## Ordering, replay, and transcript hashes

Each stream has a monotonically increasing `seq`. Receivers reject duplicate sequence numbers for the same `stream_id`.

The transcript hash should commit to plaintext frame order:

```text
H_0 = hash("marmot agent text stream transcript v1" || stream_id || start_event_id)
H_n = hash(H_{n-1} || seq || record_type || plaintext_frame)
```

The final group message includes `H_final`. A receiver that saw the live stream can compare its local transcript hash to
the final message.

Open questions:

- Should missed chunks cause the live preview to become unverified, or should clients ask the relay for a short replay?
- Should replay be allowed only until the final message lands?
- Should the final message include a compact list of checkpoint hashes?
- Should clients show a warning if the final message differs from the live preview?

## Epoch changes

The first version should pin a stream to one MLS epoch.

If the group changes epoch while a stream is active:

- If the change removes a member, the sender closes the old stream and starts a new stream in the new epoch.
- If the change adds a member, the sender can keep the old stream for existing members or restart so the new member can
  join live output.
- If the change is a self-update with no membership change, the sender still closes the old stream and starts a new one
  if it needs to keep streaming.

The conservative first rule: any accepted Commit that changes the sender's current epoch closes active streams. The
sender may start a replacement stream in the new epoch and link it to the previous `stream_id`.

This keeps forward secrecy and post-compromise recovery aligned with MLS membership. It may produce short UI gaps during
active group administration, which seems acceptable for a first pass.

## QUIC mapping

The transport binding can use one QUIC connection per account session and many QUIC streams within it.

Candidate stream layout:

- One bidirectional control stream per connection for auth, subscriptions, keepalive, and server notices.
- One unidirectional send stream per live agent response.
- Optional datagrams for presence, typing indicators, or low-value heartbeat data.

For text deltas, use reliable ordered QUIC streams. QUIC datagrams are tempting, but text output usually wants ordering
and reliable delivery inside the live preview.

A sender can reset a QUIC stream on cancellation, but it should also send an `Abort` frame or a final MLS abort message
when the cancellation matters to other members.

## WebTransport and HTTP/3

The first version does not target WebTransport or HTTP/3.

Raw QUIC is the intended transport for native mobile devices, desktop agents, and desktop clients. Browser support can
be a later feature or a separate compatibility transport.

Deferred browser questions:

- Should a later browser profile reuse the same encrypted record format over WebTransport?
- Should WebSocket fallback send only coarser draft-answer updates through ordinary Marmot app messages?
- Which parts of browser compatibility belong in a transport binding instead of this feature doc?

## QUIC transport binding boundary

The feature doc owns stream semantics: start payload, preview frames, final transcript anchoring, epoch behavior, and
which data is durable.

A future raw QUIC transport binding should own:

- endpoint candidate formats;
- direct path discovery;
- relay discovery;
- relay authentication, if any;
- relay/fanout session setup;
- reconnect behavior;
- transport-visible diagnostics;
- wire framing below `AgentTextStreamRecordV1`.

If a relay requires account authentication, that authentication is only for relay access. It does not make preview chunks
authoritative, and it does not replace MLS membership or the final MLS app payload.

## Relationship to Nostr

Nostr can still carry the durable start and final app messages through the normal Marmot MLS path.

The QUIC stream chunks do not need to be Nostr events. They are transient transport records. Making every chunk a Nostr
event would put pressure on relays, leak more timing metadata into relay history, and blur the difference between live
preview and durable group state.

This feature should not claim low-numbered MIP-era notification or multi-device values for stream traffic. If another
MIP has already claimed a kind that is not yet listed in the registry, that claim wins; this feature should not use
`450` or `451` for QUIC stream chunks, start/final payloads, or fallback previews.

Possible Nostr-related side ideas:

- Define QUIC relay endpoint discovery in the raw QUIC transport binding if Nostr is used for rendezvous.
- Use Nostr events only for rendezvous, not for chunk delivery.
- Allow a Nostr-only fallback that sends coarser preview updates as ordinary Marmot app messages.
- Let relays advertise QUIC fanout support separately from ordinary Nostr relay support.

## Agent identity

An agent stream may be sent by:

- a normal user device running an agent locally;
- a bot account that is a Marmot group member;

The first version treats the agent as a normal Marmot group member. It has a KeyPackage, joins the group, advertises the
same capabilities as any other member, receives prompts as normal app payloads, streams previews over QUIC, and sends the
final answer as an MLS-authenticated app payload.

The UI may still label that member as an agent, bot, device, or CLI process, but that is display state. The protocol
model does not need an agent-specific membership class for the first version.

Deferred questions:

- Which agent profile fields belong in the KeyPackage, a profile event, or an app payload?
- Can a hosted agent service participate without becoming a full group member?
- How does the final transcript show which local process, model, or tool produced the output?

## Images and other media

Images should usually use the encrypted media feature:

1. The sender encrypts and uploads the image or generated artifact as a blob.
2. The stream emits a placeholder frame or media reference notice.
3. The final MLS message includes the media reference in normal app payload form.

This avoids pushing binary media through a text stream and keeps media hashing, MIME checks, previews, and storage rules
in one place.

A future fast-preview mode could stream progressive image bytes, but that should be a separate media-streaming feature.

## Retention and offline behavior

The default stream is transient.

The durable record is the final MLS app payload. A client may locally cache chunks for UI replay, but those chunks are
not canonical group history.

Possible retained-stream mode:

- The QUIC relay stores encrypted chunks for a short TTL.
- The final message includes a chunk manifest and transcript hash.
- Late online clients can fetch chunks before the TTL expires.
- Offline clients still fall back to the final message after the TTL.

This mode may be useful for long agent runs where observers join a few minutes late. It should be opt-in because it
changes storage and metadata behavior.

## Backpressure and chunk policy

Text deltas should be batched. Sending one record per token is wasteful and leaks token cadence.

Candidate policy:

- Flush at 50-250 ms intervals while text is arriving.
- Flush sooner on sentence boundary, tool-call boundary, or user-visible status change.
- Cap plaintext frame size.
- Coalesce tiny deltas.
- Pad records only when the privacy gain is worth the bandwidth.

If a receiver falls behind, the fanout service can slow that recipient, drop the live preview, or tell the sender to
reduce frequency. It should not hold unbounded buffers.

## Privacy notes

End-to-end chunk encryption hides text from the fanout service, but metadata remains:

- which accounts connect to a fanout endpoint;
- when a stream starts and stops;
- approximate output rate;
- record sizes;
- recipient online status;
- cancellation timing.

Mitigations:

- use coarse batching;
- use minimal padding for small records where it is cheap;
- avoid putting prompt text or model names in transport-visible fields;
- keep final usage details inside the encrypted final app payload;
- rotate stream ids per response;
- avoid long-lived relay-visible identifiers when a per-stream value works.

## Failure behavior

Potential failures and first-pass behavior:

- Start message delivered, QUIC unavailable: no live preview; final message still arrives.
- QUIC stream starts before MLS start is processed: receiver buffers briefly or rejects until start arrives.
- Chunk decrypt fails: drop the stream preview and wait for final.
- Transcript hash mismatch: mark the preview unverified and show the final MLS message as authoritative.
- Sequence gap: stall that lane, request short replay if supported, or mark preview incomplete.
- Sender cancels: close the QUIC stream and publish abort/final state if the group should see it.
- Relay disappears: reconnect to another hinted endpoint or fall back to final MLS message.
- Epoch changes: close and restart under the new epoch.
- Final transcript hash mismatch: treat the preview as unverified and show the final MLS message as authoritative.

## Conformance ideas

Useful test vectors later:

- start event id to stream key derivation;
- record encryption and decryption for several sequence numbers;
- duplicate sequence rejection;
- transcript hash update;
- unsigned preview replacement by final message;
- final hash mismatch;
- epoch restart link;
- relay replay within a TTL;
- direct QUIC and relay fallback path selection.

Useful simulation scenarios:

- two clients watch one agent stream;
- one client joins late and receives only final;
- tool and citation frames interleave with text frames;
- sender cancels after partial output;
- group member is removed mid-stream;
- relay reorders or duplicates records;
- forged preview chunk fails final transcript-hash validation.

## Side ideas to revisit

- Let a stream spawn child streams for tool calls, with the UI deciding how to display them.
- Use a Merkle tree over chunks for efficient partial verification.
- Add a "draft answer" app event that updates every few seconds for clients without QUIC.
- Let users scrub back through a retained live stream while it is still running.
- Add a low-bandwidth mode that sends sentence-level deltas only.
- Add a privacy mode that hides token cadence through fixed-interval records.
- Add an agent handoff frame so one agent can pass the live stream to another agent.
- Use QUIC datagrams for low-value cursor/status pings while keeping text on reliable streams.
- Let a final message reference multiple stream ids when a long task restarts across epochs.
- Define a local-only UI rule where unverified live text is visually distinct from final group history.

## Open questions

- Which exact typed frames belong in v1 besides `TextDelta`, `ToolDelta`, `Status`, `Checkpoint`, `Abort`, and
  `FinalNotice`?
- Should preview chunks be exposed only to rendering code, or can application code subscribe to them with an explicit
  provisional marker?
- Should retained replay exist in v1, or should late observers always wait for the final message?
- What minimal padding rule gives enough confidentiality without wasting mobile bandwidth?
- Which agent profile fields belong in KeyPackages, profile events, or app payloads?
- What is the exact boundary between this feature and the raw QUIC transport binding once the transport doc exists?

## Rough first pass

A small first pass could do this:

1. Add a feature capability for receiving QUIC text streams.
2. Add `marmot.group.agent-text-stream.quic.v1` as a required app component for agent-session groups.
3. Define start and final Marmot app payloads.
4. Pin each stream to one MLS epoch.
5. Derive one record key from an MLS exporter.
6. Send unsigned, ordered `TextDelta` records over one reliable QUIC stream.
7. Publish the final transcript as a normal group message with `transcript_hash`.
8. Treat all live chunks as transient preview.

That gives the product the main UX win while leaving retained replay, child streams, datagrams, hosted-agent delegation,
and media preview for later.
