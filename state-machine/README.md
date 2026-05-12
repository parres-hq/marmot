# Marmot state machine

Status: sketch.

These documents define how a Marmot group moves from one canonical MLS state to the next.

The state machine owns group lifecycle, inbound processing, publish-before-apply, retained history, and convergence.
Transport documents say how bytes arrive. App component documents say how component bytes change. The state machine says
when those bytes become canonical group state.

## Files

- [group-state.md](./group-state.md) - the per-group lifecycle states and legal transitions.
- [publish-lifecycle.md](./publish-lifecycle.md) - publish-before-apply for local group-state changes.
- [inbound-processing.md](./inbound-processing.md) - how incoming bytes are stored, classified, and retried.
- [convergence.md](./convergence.md) - how candidate branches are built, scored, selected, and applied.
- [retained-history.md](./retained-history.md) - retained state, rollback horizon, and late input rules.

## Core rule

Marmot clients choose group state from MLS-valid protocol bytes and the group's convergence policy.

They MUST NOT choose group state from transport arrival order, transport envelope timestamps, outer event ids, local
receive order, or which transport source delivered a message first.
