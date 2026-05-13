# Marmot v2 Protocol Draft

Status: draft for internal review.

This directory contains the proposed Marmot v2 protocol text. The existing MIP documents remain the current production
reference until this draft is adopted.

The draft is organized by protocol surface. Foundation documents define stable Marmot invariants. Protocol-core
documents define how Marmot groups move through MLS flows. Transport documents define how Marmot bytes move over a
network. App component documents define versioned group-state payloads. Feature documents describe optional or
user-visible flows and point to the surfaces they touch.

## What is Marmot?

Marmot is a protocol for end-to-end encrypted group messaging. It uses Nostr public keys for identity, Nostr
event-shaped app payloads inside MLS, and MLS as the continuous group key agreement layer. Those three choices are the
current protocol invariants.

Transport beyond that stays agnostic. Marmot clients currently move messages over Nostr relays, but the identity,
content, and key agreement layers do not depend on Nostr relays as the only possible transport.

Marmot is designed for group messaging that keeps working when parts of the transport fail. With Nostr, clients connect
to several relays at once, so a relay that goes down, gets blocked, or turns malicious does not break the group. Any
future transport binding needs the same redundancy and failover properties.

The protocol also tries to expose as little metadata as the design allows. Perfect metadata privacy is not possible in a
decentralized messaging system, but Marmot should avoid new metadata leaks unless a feature cannot work without them.

## Review Status

This is not adopted spec text yet. Treat it as the working v2 draft for team review.

For review, focus on these questions:

- Are rules in the right surface?
- Are byte encodings exact enough?
- Are authorization and validation rules clear?
- Are transport-specific rules kept out of foundation and protocol-core docs?
- Could another implementation build the behavior and write conformance tests from the text?

## Draft Map

- [principles.md](./principles.md) - principles for organizing and writing the spec.
- [layout.md](./layout.md) - proposed shape for the Marmot v2 spec set.
- [foundation/](./foundation/) - identity, app payload, encoding, MLS, wire, and registry rules.
- [protocol-core/](./protocol-core/) - group setup, joining, messaging, lifecycle, convergence, and retained history.
- [app-components/](./app-components/) - custom app component model and draft component payload schemas.
- [transports/](./transports/) - transport bindings for moving Marmot MLS bytes over a network.
- [features/](./features/) - optional and user-visible feature flows.
- [mip-coverage.md](./mip-coverage.md) - map from current MIPs to the v2 draft surfaces.
- [implementation-model.md](./implementation-model.md) - non-normative local implementation notes.

## Working Rules

- Keep implementation architecture out of normative protocol documents.
- Prefer short normative rules over long explanation.
- Use `MUST`, `SHOULD`, and `MAY` only when the sentence is meant to become normative.
- Put transport-specific fields in transport-specific components or transport docs.
- Put group flow semantics in protocol-core docs or group app components.
- A feature should usually point to one app component or add one component version.
- A feature should name every surface it changes.
- App component docs own component bytes. Feature docs own user-visible flows and the surfaces those flows touch.
