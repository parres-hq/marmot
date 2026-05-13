# Group messaging

Status: draft for internal review.

This document describes group control messages and encrypted app payloads.

## Surfaces

- Foundation application payloads.
- MLS protocol: Proposals, Commits, PublicMessage, PrivateMessage, application messages, and epochs.
- Protocol-core publish lifecycle, inbound processing, retained history, and convergence.
- Active transport binding for group message delivery.
- App components for admin policy, routing, and message retention.
- SelfRemove as the member-departure flow.

## Behavior

Marmot group traffic carries three kinds of MLS work:

- Proposals that ask the group to change state later.
- Commits that advance group state.
- MLS application messages that carry Marmot app payloads.

All three are delivered through the active transport binding. The transport owns the outer envelope. Protocol core owns
which peeled MLS bytes become canonical group state.

## App payloads

Marmot app payloads use an unsigned Nostr event shape inside MLS.

Common app payload kinds include:

- kind `9` for chat text;
- kind `7` for reactions;
- feature-specific app events such as push-notification token events.

The inner app event has an `id` but no `sig`. It must not include transport routing tags.

Receivers validate that the inner app event `pubkey` matches the Marmot account identity authenticated by MLS.
Unsupported app-event kinds do not change group state unless the owning feature says otherwise.

## Commit authorization

Admins can commit ordinary group-state changes.

Non-admin members can commit only the narrow flows that the spec explicitly allows:

- a self-update Commit that updates only the sender's own LeafNode;
- a dedicated SelfRemove-only Commit that processes valid pending SelfRemove proposals by reference.

Those two non-admin commit shapes must not be combined with each other or with other proposal types.

All other Commits from non-admins are invalid.

## Publish before apply

A locally generated Commit must not become the sender's canonical local state until its publish obligation succeeds.

The sender publishes the transport envelope required by the active transport binding and waits for the transport publish
success required by the publish lifecycle.

If the Commit adds members, the associated Welcomes are sent only after the Commit publish obligation succeeds.

## Race handling

Convergence uses content-derived commit ordering, retained MLS states, and group policy. Transport evidence must not
choose the winning branch.

## Message retention

When message retention is enabled, the active transport binding applies its own retention hint if it has one.

When retention is disabled, callers cannot force retention data onto the group message envelope. The sender removes or
replaces retention data so the on-wire behavior is determined by group state.

## Migration notes

MIP-03 remains the canonical description of current group messages until the v2 draft is adopted. The MIP coverage map
records where each MIP-03 concern lives in the v2 draft.
