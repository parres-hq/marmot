# Self-remove

Status: sketch.

Self-remove lets a current member leave a group without asking an admin to remove them.

This feature uses the MLS SelfRemove proposal from the MLS extensions work. It does not define a Marmot custom proposal
type.

## Surfaces

- MLS proposal: SelfRemove.
- State machine: proposal ingest, deterministic commit, convergence, retained history.
- App component: `marmot.group.admin-policy.v1` for admin leave constraints.
- Transport: whichever transport carries the proposal and commit.

## Behavior

A current member may create a SelfRemove proposal for itself.

A non-admin may self-remove if the MLS proposal is valid.

An admin may self-remove only if at least one other admin remains after the removal. The admin check uses the prior
epoch state.

The leaving member MUST NOT commit its own SelfRemove proposal. A remaining authorized member commits it.

## Deterministic auto-commit

Clients that auto-commit a peer SelfRemove proposal need a deterministic committer rule so the group does not fork from
several equivalent commits.

The current policy is:

- build the eligible committer set from current members excluding the leaving member;
- remove members that are not allowed to commit the resulting state;
- choose the eligible member with the lowest MLS leaf index.

Only that member SHOULD auto-commit the proposal.

If the selected member cannot publish, another member MAY commit later through a user or recovery action. This draft
does not define an automatic fallback timer.

## Validation

A SelfRemove flow is invalid if:

- the proposal does not target the sender;
- the leaving member commits the proposal;
- the proposal would remove the last admin;
- the committer is not a current member;
- the commit fails the normal MLS and Marmot convergence checks.

## Migration notes

MIP-era Marmot treated SelfRemove as part of group messaging behavior. In this rewrite, SelfRemove is a feature doc
because it touches MLS proposals, admin policy, deterministic commit behavior, and transport delivery.
