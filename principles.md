# Principles for writing Marmot specs

Status: draft for internal review.

These principles are for the Marmot v2 draft. They explain how we decide where rules belong and how much detail a spec
document needs before another implementation could build from it.

They are intentionally more prescriptive than style notes. When a principle starts defining exact client behavior, move
that behavior into the document for the surface it affects and leave only the placement rule here.

## Write the stable Marmot invariants once

Foundation docs own the choices that make Marmot Marmot:

- Nostr public keys are Marmot account identity.
- Marmot app payloads use an unsigned Nostr event shape inside MLS.
- MLS is the current continuous group key agreement layer.
- Marmot transports MUST support redundant delivery so a group does not depend on one server, relay, or endpoint.
- Marmot specs SHOULD avoid new metadata leaks unless the feature cannot work without them.
- Encodings that are commonly used across multiple surfaces.

Do not restate these rules in every feature doc. Point to the foundation doc and describe only what the feature adds.

If one of these invariants changes, treat it as a protocol-level change. It SHOULD NOT be hidden inside a feature or
transport document.

## Organize the spec by surfaces, not by MIP history

MIPs are useful historical change records. They SHOULD NOT be the only way to understand the protocol.

A clean implementation SHOULD be able to find each rule by the surface it is implementing:

- identity and credentials in foundation;
- byte encoding and registries in foundation;
- MLS protocol choices in foundation;
- group flows and group-state transitions in protocol-core docs;
- feature state in app component docs;
- transport-specific delivery in transport docs;
- local implementation advice in `implementation-model.md` or crate docs.

When a feature changes one surface, edit that surface. When it changes several surfaces, name each one and update each
owning document.

## Delegate to rules that exist

A document MAY delegate a rule to the surface that owns it. A delegation names the owning document, and the owning
document contains the rule.

A delegation to a class of documents — for example "the active transport binding" — is a requirement on every document
in that class: each transport binding MUST either define the delegated behavior or state explicitly that it does not
provide it.

Two documents MUST NOT delegate the same rule to each other. When neither side defines the behavior, the rule does not
exist, and both documents read as complete when they are not.

## Define protocol bytes exactly

Anything signed, hashed, referenced, stored for replay, compared for equality, or used to choose state needs a canonical
byte encoding.

The owning document MUST say:

- which encoding is used;
- field lengths and bounds;
- list ordering rules;
- duplicate rules;
- whether text is raw UTF-8 bytes or has a normalization rule;
- which bytes are preserved when a client does not understand an optional value.

If two human-readable values can look equivalent, the owning document MUST say whether they are the same protocol value.
The default is byte equality.

## Keep implementation details out of protocol documents

Protocol docs describe bytes, validation, authorization, state changes, and interop-visible results.

They SHOULD NOT describe Rust crate names, database tables, queue shapes, retry workers, local API names, test harness
helpers, or logging implementations. Those belong in `implementation-model.md`, architecture notes, or crate docs.

It is fine for a protocol doc to say that a client MUST retain enough material to reproduce a decision. It SHOULD NOT
say which table stores that material.

## Keep identity, delivery addressing, and transport separate

Identity says who an account or member is.

Delivery addressing says which delivery coordinates are used for a class of bytes. Examples are a group delivery
address, a recipient inbox, a relay list, a topic, or an endpoint set.

Transport says how a network carries, publishes, fetches, wraps, and validates those bytes.

For Marmot group messages using Nostr relays for transport, the random `nostr_group_id` and signed group relay list are
delivery-address state. The Nostr event shape, relay behavior, gift wrapping, filters, and publishing rules belong in
the Nostr transport binding.

Do not derive delivery addresses from identity material. Do not let a generic group rule depend on Nostr event ids,
relay URLs, pubkeys, tag shapes, or any other transport-specific address shape.

## Describe state changes completely

When a document defines a state change, it MUST include enough information for another implementation to apply or reject
the change the same way.

That means naming:

- the prior state the change consumes;
- the input bytes;
- validation checks;
- authorization checks;
- deterministic update rules;
- output bytes, if any;
- rejection result.

This applies to group-state transitions, component updates, transport-owned state updates, and foundation-level changes
such as credential validation.

## Do not let transport behavior choose group state

Transport input is evidence that bytes exist. It is not consensus.

Transport arrival order, transport timestamps, event ids, subscription order, fetch order, and local receive order MUST
not choose the canonical group branch. Protocol-core docs own convergence, publish-before-apply, retained history,
duplicate handling, and stale-input handling.

A transport doc can say how to find and deliver bytes. It SHOULD NOT define which commit branch wins.

## Keep feature state small and owned

Feature state SHOULD live in small versioned app components unless the feature changes a shared foundation or
protocol-core surface.

Each component SHOULD own:

- its component id;
- state bytes;
- update bytes;
- validation;
- proposal and commit authorization;
- removal rules;
- migration rules;
- compatible and breaking change rules.

Large objects SHOULD NOT be stored directly in GroupContext component data. Store hashes, content ids, encrypted media
references, or application-layer records when the data belongs elsewhere.

## Make errors part of interop when they affect behavior

When different clients need to react the same way to a failure, the owning document SHOULD name the result.

Examples include duplicate input, wrong recipient, stale epoch, invalid encoding, missing history, unsupported required
feature, authorization failure, and publish-before-apply failure.

Local error objects can vary. Interop-visible outcomes SHOULD be stable enough for conformance tests and for another
implementation to understand what happened.

## Write for implementation and tests

A spec section is not done because it sounds reasonable. It is done when another implementation could build it and a
test could check it.

For every new surface, ask:

- what bytes would a fixture contain?
- what valid case SHOULD pass?
- what malformed case SHOULD fail?
- what authorization case SHOULD fail?
- what backward or migration case matters?

If the answer is unclear, the spec needs more detail in the owning document.

## Keep prose plain

Prefer direct explanations over compressed slogans. Short is useful only when it is still clear.

Use `MUST`, `SHOULD`, and `MAY` only when the sentence is meant to become normative. Use ordinary language for notes,
rationale, and examples.
