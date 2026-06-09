# Spec layout

Status: draft for internal review.

The current MIP set mixes stable protocol surfaces with feature behavior. The
v2 draft organizes docs around the surface an implementer is building.

MIPs remain useful history. They SHOULD point to the stable docs they changed.

## Top Level

```text
spec/
  README.md
  principles.md
  mip-coverage.md
  foundation/
    identity.md
    key-packages.md
    canonical-encoding.md
    wire-envelopes.md
    application-messages.md
    mls-protocol.md
    errors.md
    registries.md
  protocol-core/
    README.md
    group-setup.md
    joining.md
    group-messaging.md
    member-departure.md
    group-state.md
    publish-lifecycle.md
    inbound-processing.md
    convergence.md
    retained-history.md
  app-components/
    README.md
    group-profile-v1.md
    group-blossom-image-v1.md
    admin-policy-v1.md
    nostr-routing-v1.md
    message-retention-v1.md
    agent-text-stream-quic-v1.md
  transports/
    README.md
    nostr.md
  features/
    README.md
    encrypted-media.md
    push-notifications.md
    multi-device.md
    agent-text-streams-quic.md
  implementation-model.md
```

## Foundation

Foundation documents define shared surfaces:

- identity, credentials, KeyPackages, and capability negotiation
- canonical encodings
- app payload shape
- wire envelopes
- MLS protocol choices
- error and stale-result taxonomy
- registries for component ids, proposal ids, and extension ids

Foundation documents SHOULD change rarely. They carry stable Marmot invariants: Nostr identity, unsigned Nostr-shaped
app payloads, MLS group security, canonical byte rules, capability advertisement, and Marmot-owned registries.

## Protocol Core

Protocol-core documents define protocol behavior that every transport and feature relies on:

- group setup
- joining through MLS Welcomes
- group messaging
- member departure
- local publish lifecycle
- inbound message processing
- group lifecycle states
- duplicate handling
- convergence and branch selection
- retained history requirements
- non-application input classification

These documents describe required transitions and validation rules. They do not prescribe local module names, queues,
database schemas, or API boundaries.

## App Components

App component documents define custom MLS app components carried in the
GroupContext `app_data_dictionary`.

Each component document owns:

- component id
- component name and version
- payload schema
- update schema
- canonical encoding
- authorization
- update operation
- removal behavior
- migration behavior

Most feature-owned group state SHOULD land here.

## Transports

Transport documents define how Marmot bytes move over a network.

Transport documents MAY define transport-specific delivery addresses, event shapes, relay or endpoint selection, fetch
rules, and app components. They SHOULD NOT define generic group semantics.

## Features

Feature documents describe optional or user-facing behavior that spans components or protocol surfaces.

A feature document SHOULD mostly reference foundation, protocol-core, and component documents. It SHOULD NOT duplicate
their rules.

Feature documents stay separate from app components. The feature doc explains the flow. The app component doc owns the
component bytes. Encrypted media follows that split: [app-components/group-encrypted-media-v1.md](./app-components/group-encrypted-media-v1.md)
owns group policy bytes, while [features/encrypted-media.md](./features/encrypted-media.md) owns message attachment
format, key derivation, and AEAD behavior.

When a feature has an interop-visible breaking change, the owning document MUST name the new version in a capability,
component id, proposal id, event kind, or feature document. Git history is useful, but it is not a version-negotiation
mechanism.

## Implementation Model

The implementation model is non-normative. It can map the protocol to local terms used by this repository, including
local APIs, queues, storage choices, and diagnostics.

## MIP Coverage

The v2 draft keeps MIP history separate from normative organization.

Use [mip-coverage.md](./mip-coverage.md) to see where current MIP-era concerns moved. The stable spec SHOULD be readable
without replaying the MIP history.
