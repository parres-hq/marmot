# Marmot Implementation Model

Status: non-normative draft for internal review.

This document describes one way to implement the Marmot protocol. It is not a wire contract.

The normative rules live in the protocol documents. A compliant client can use different module names, queues, database
tables, and API shapes.

## Boundary

A Marmot client needs one local component that owns group-state transitions. That component may be an engine, state
machine, actor, service, library, or process.

Other local code can ask it to create local actions, feed it inbound protocol bytes, publish its outbound bytes, and
confirm or fail pending publication.

## Local State Owner

For each group, an implementation will usually track:

- the current canonical state;
- one unresolved local publish obligation, if any;
- retained prior states or anchors within the active retention policy;
- received protocol bytes and their classified outcomes;
- local actions that must be regenerated after convergence changes the canonical state.

These are local mechanics. They are not wire types.

## Publish Obligations

A useful local API can return a publish obligation with:

- the outbound bytes to publish;
- the group or recipient class those bytes target;
- the source epoch and target epoch;
- a local pending reference.

After transport publication succeeds, the caller confirms the pending reference. After transport publication fails, the
caller fails the pending reference.

The pending reference is local. Marmot protocol bytes do not carry it.

## Replay And Convergence

Implementations need enough retained material to replay candidate state transitions during the policy window. This often
means storing raw MLS message bytes, welcome bytes, prior state snapshots, and local classification metadata.

The protocol defines what must be reproducible. It does not define table names, cache keys, or snapshot formats.

## Outcomes

Local APIs should expose classified outcomes for inputs that do not produce application content.

The API names can vary. The categories should map to the Marmot classification surface for duplicates, own echoes, wrong
recipients, unknown groups, already-applied commits, stale epochs, invalid encodings, authorization failures, and
missing history.

## Diagnostics

Logs, errors, metrics, and traces should avoid account ids, group ids, message ids, relay URLs, pubkeys, payloads,
ciphertext, plaintext, and key material.

Use aggregate counts, method names, local enum names, and redacted or hashed values when a diagnostic needs correlation.

## Darkmatter Mapping

This repository maps the model above to code using names such as:

- `CgkaEngine`;
- `PendingStateRef`;
- `drain_auto_publish`;
- `confirm_published`;
- `publish_failed`;
- retained snapshots;
- the convergence simulator.

Those names are darkmatter implementation details. They are not part of the Marmot wire spec.
