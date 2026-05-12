# Marmot Spec Rewrite Sandbox

Status: experimental.

This directory is a clean space for rewriting the Marmot spec by surface and invariant. The existing MIP documents
remain the historical source while this draft settles.

The goal is to stop making every new feature edit the same old documents. Fixed protocol surfaces should live in fixed
documents. Feature work should add or revise small versioned app components.

## What is Marmot?

Marmot is a protocol for end-to-end encrypted group messaging. It uses Nostr public keys for identity, Nostr
event-shaped app payloads inside MLS, and MLS as the continuous group key agreement layer. Those three choices are the
current protocol invariants.

Transport beyond that stays agnostic. All Marmot clients currently move messages over Nostr relays today but this could
change tomorrow without changing the identity, content, or key agreement layers.

The protocol aims at two things, in priority order. The first is an unstoppable messaging layer that never depends on
any single server, relay, or transport endpoint to keep a group working. The second is end-to-end encryption that
exposes as little metadata as possible.

Unstoppable means a group keeps running when parts of the transport fail. With Nostr, Marmot clients connect to several
relays at once, so a relay that goes down, gets blocked, or turns malicious does not break the group. Any transport
added to Marmot needs to be built the same way, with failover and redundancy from the start.

Marmot is unstoppable end-to-end encrypted messaging. Perfect privacy is not always possible in a decentralized system,
but the protocol does its absolute best to hide as much metadata as is possible.

## Draft Map

- [principles.md](./principles.md) - principles for organizing and writing the spec.
- [layout.md](./layout.md) - proposed shape for the rewritten spec set.
- [foundation/](./foundation/) - shared Marmot identity, message payload, encoding, MLS, wire, and registry rules.
- [state-machine/](./state-machine/) - group lifecycle, inbound processing, convergence, and retained history.
- [app-components.md](./app-components.md) - custom app component model.
- [app-components/](./app-components/) - draft component payload schemas.
- [transports/](./transports/) - transport bindings for moving Marmot MLS bytes over a network.
- [features/](./features/) - feature-level flows that point to foundation, state-machine, transport, and component docs.
- [implementation-model.md](./implementation-model.md) - non-normative local implementation notes.

## Working Rules

- Keep this directory easy to delete or reshape.
- Prefer short normative rules over long explanation.
- Use "MUST", "SHOULD", and "MAY" only when the sentence is meant to become normative.
- Put transport-specific fields in transport-specific components.
- Put group semantics in group components.
- A new feature should usually point to one app component or add one component version.
- A feature should not require edits across identity, wire format, transport, lifecycle, and storage documents unless it
  changes those surfaces.
- App component docs own component bytes. Feature docs own user-visible flows and the surfaces those flows touch.
- Keep implementation architecture out of normative protocol documents.
