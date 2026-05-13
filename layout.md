# Spec layout

Status: sketch.

The current MIP set mixes stable protocol surfaces with feature behavior. The rewrite organizes docs around the surface
an implementer is building.

MIPs remain useful history. They should point to the stable docs they changed.

## Top Level

```text
spec/
  README.md
  principles.md
  foundation/
    identity.md
    canonical-encoding.md
    wire-envelopes.md
    application-messages.md
    mls-protocol.md
    errors.md
    registries.md
  state-machine/
    README.md
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
  transports/
    README.md
    nostr.md
  features/
    README.md
    self-remove.md
    encrypted-media.md
    push-notifications.md
    multi-device.md
  mips/
    mip-0000-history.md
    mip-0001-history.md
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

Foundation documents should change rarely. They carry stable Marmot invariants: Nostr identity, unsigned Nostr-shaped
app payloads, MLS group security, canonical byte rules, capability advertisement, and Marmot-owned registries.

## State Machine

State-machine documents define protocol behavior that every transport and feature relies on:

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

Most feature-owned group state should land here.

## Transports

Transport documents define how Marmot bytes move over a network.

Transport documents may define transport-specific delivery addresses, event shapes, relay or endpoint selection, fetch
rules, and app components. They should not define generic group semantics.

## Features

Feature documents describe behavior that spans components or user-facing operations.

A feature document should mostly reference foundation, state-machine, and component documents. It should not duplicate
their rules.

Feature documents stay separate from app components. The feature doc explains the flow. The app component doc owns the
bytes.

When a feature has an interop-visible breaking change, the spec must name the new version in a capability, component id,
proposal id, event kind, or feature document. Git history is useful, but it is not a version-negotiation mechanism.

## Implementation Model

The implementation model is non-normative. It can map the protocol to local terms used by this repository, including
engine APIs, queues, storage choices, and diagnostics.

## MIPs

MIPs become change records.

After the rewrite, a MIP should say what changed, why it changed, and which canonical spec documents were updated. The
stable spec should be readable without replaying the MIP history.
