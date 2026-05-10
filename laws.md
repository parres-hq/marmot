# Marmot Protocol Laws

Status: sketch.

These laws are the top-level Marmot protocol rules. They are not a description
of any specific implementation.

A compliant implementation can use any internal architecture. It must produce,
validate, store, replay, and publish protocol bytes according to these laws.

## Terms

- A **Marmot client** is any implementation that creates, validates, or applies
  Marmot group state.
- **Group state** means the MLS group state plus Marmot-defined state carried in
  MLS extensions or application components.
- **Canonical state** is the state a client accepts as the selected local view of
  a group after validation and convergence.
- A **publish obligation** is the set of outbound protocol bytes that must become
  available through transport before a locally generated group-state change can
  be applied locally.

## L1. Canonical Bytes

Any byte string that is signed, hashed, referenced, stored for replay, or used
for branch selection MUST have one canonical encoding.

Equivalent protocol values MUST encode to identical bytes. Two byte strings that
encode the same human-facing value are still different protocol values unless
Marmot defines a canonical normalization rule for that value.

## L2. Marmot-Defined Transitions

A Marmot client MUST apply a group-state change only through a Marmot-defined
transition.

Each transition MUST have:

- the prior state required;
- the exact input bytes consumed;
- the validation and authorization checks;
- the deterministic state update;
- the output bytes, if any;
- the failure result.

An implementation may expose this through any local interface. That interface is
not part of the protocol.

## L3. Publish Before Apply

A locally generated group-state change MUST NOT become local canonical state
until its publish obligation is confirmed.

This rule applies to user actions, application actions, and policy-generated
actions such as SelfRemove auto-commits.

A client MAY prepare a commit and retain pending local state before publication.
Prepared pending state is not canonical group state.

## L4. One Unresolved Local Evolution

For a given group, a Marmot client SHOULD have at most one unresolved local
group-evolution publish obligation at a time.

If another local group-evolution action is requested while one is unresolved, the
client SHOULD defer the later action and regenerate it from the selected
canonical state after the unresolved obligation is confirmed, failed, or
superseded by a valid inbound transition.

## L5. Transport Order Is Not Consensus

Transport arrival order MUST NOT decide the canonical branch.

Branch selection MUST use protocol bytes, retained prior states, negotiated
policy, and deterministic tie-break rules. Relay timestamps, Nostr event ids,
subscription order, and local receive order are transport evidence only.

## L6. Replayable State

A Marmot client MUST retain enough protocol material to reproduce its canonical
state decisions within the retention window required by the active policy.

This includes material needed to detect duplicates, validate pending proposals,
replay candidate commits, explain branch selection, and reject stale inputs.

The required retained material and the retention window are protocol policy
values. Database schemas and storage APIs are local implementation choices.

## L7. Classified Non-Application Inputs

Every Marmot client MUST classify inputs that do not produce application
content.

At minimum, the interoperable classification surface MUST cover duplicates, own
echoes, messages for another recipient, unknown groups, already-applied commits,
stale epochs, invalid encodings, authorization failures, and inputs that require
more history than the client retained.

Local APIs may use different names, but each local outcome MUST map to the
interoperable category that Marmot defines.

## L8. Component Isolation

Feature state SHOULD live in small MLS application components.

Each component owns its state schema, update schema, canonical encoding,
validation, authorization, removal rule, and migration rule.

A new feature SHOULD add a component or a component version unless it changes a
shared protocol surface.

## L9. Component Update Determinism

For a given component, the same prior component state and the same ordered
component update list MUST produce the same new state or the same invalid result
on every compliant client.

Component update logic MUST NOT depend on wall-clock time, local storage order,
transport arrival order, random numbers, relay state, UI state, or local
configuration outside the negotiated protocol policy.

## L10. Required Components Fail Closed

A client that does not understand a required component MUST NOT join the group or
process the group state as if it understood the group.

Marmot uses the MLS `app_components` component in the GroupContext to identify
required application components. Unknown non-required component data in an
`app_data_dictionary` MUST be preserved byte-for-byte when a client rewrites the
dictionary.

## L11. Transport Opaqueness

Transport routing ids are opaque protocol values.

They MUST NOT be derived from account ids, member ids, public keys, MLS group
ids, KeyPackage ids, message ids, or other stable identity material.

## L12. Identity Separation

Identity material proves who a member is. Routing material tells a transport
where bytes should be delivered.

Marmot MUST NOT use identity material as routing material, and MUST NOT use
routing material as identity proof.

## L13. Transport Boundaries

Transport-specific data belongs in transport-specific documents or components.

Generic group semantics MUST NOT depend on Nostr event ids, relay URLs, Nostr
pubkeys, or Nostr tag shape. A non-Nostr transport must be able to implement the
same group semantics by replacing only the transport mapping and any
transport-specific components.

## L14. Welcome Lands Post-Commit

A welcome join lands the recipient at the post-commit epoch carried by the
welcome.

If the matching commit later arrives at that recipient, the client MUST treat the
commit as already represented by the joined state or otherwise stale. The
ordinary welcome handoff MUST NOT be treated as a fork.

## L15. Component Data Minimization

GroupContext component data SHOULD be small.

Large data SHOULD be represented by hashes, content ids, encrypted media
references, or application-layer records. Component data is signed group state
and is replayed during convergence; it is not a general storage layer.

## L16. Versioned Change

Every extensible surface MUST define its versioning rule.

For Marmot app components, the major version is part of the component id. A
breaking schema, validation, authorization, canonical-encoding, removal, or
migration change MUST use a new component id.

Component state and update payloads SHOULD NOT carry a second major-version
field. Compatible changes must be explicitly reserved by the active component
version.

## L17. No Cross-Surface Feature Churn

A protocol extension SHOULD update only the surfaces it changes.

Adding a new feature should usually add one component document, one registry
entry, and conformance cases. It should not require edits to identity, wire
envelopes, transport mapping, lifecycle, and old feature documents unless the
feature changes those contracts.

## Non-Normative Material

Implementation architecture, local API shapes, diagnostics, logging rules,
database schemas, queue mechanics, and test harness design belong in
[implementation-model.md](./implementation-model.md) or implementation-specific
documents.
