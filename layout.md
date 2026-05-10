# Proposed Spec Layout

Status: sketch.

The current MIP set mixes stable protocol surfaces with feature behavior. This
layout separates the parts that should rarely change from the parts that should
grow often.

## Top Level

```text
spec/
  README.md
  laws.md
  foundation/
    identity.md
    credentials.md
    canonical-encoding.md
    wire-envelopes.md
    mls-profile.md
    errors.md
    registries.md
  state-machine/
    group-state.md
    transitions.md
    publish-lifecycle.md
    inbound-processing.md
    convergence.md
    retained-history.md
  app-components/
    README.md
    group-profile-v1.md
    group-image-v1.md
    admin-policy-v1.md
    nostr-routing-v1.md
    message-retention-v1.md
  transports/
    nostr.md
  features/
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

- identity and credentials
- KeyPackage publication and validation
- canonical encodings
- wire envelopes
- MLS profile choices
- error and stale-result taxonomy
- registries for component ids, proposal ids, and extension ids

Foundation documents should change rarely.

## State Machine

State-machine documents define protocol behavior that every transport and
feature relies on:

- local publish lifecycle
- inbound message processing
- duplicate handling
- convergence and branch selection
- retained history requirements
- non-application input classification

These documents describe required transitions and validation rules. They do not
prescribe local module names, queues, database schemas, or API boundaries.

## App Components

App component documents define versioned group-context dictionaries.

Each component document owns:

- component id
- version
- payload schema
- update schema
- canonical encoding
- authorization
- update operation
- removal behavior
- migration behavior

Most new features should land here.

## Transports

Transport documents define how Marmot bytes move over a network.

Transport documents may define transport-specific app components. They should
not define generic group semantics.

## Features

Feature documents describe behavior that spans components or user-facing
operations.

A feature document should mostly reference foundation, state-machine, and
component documents. It should not duplicate their rules.

## Implementation Model

The implementation model is non-normative. It can map the protocol to local
terms used by this repository, including engine APIs, queues, storage choices,
and diagnostics.

## MIPs

MIPs become change records.

After the rewrite, a MIP should say what changed, why it changed, and which
canonical spec documents were updated. The stable spec should be readable
without replaying the MIP history.
