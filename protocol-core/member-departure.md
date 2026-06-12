# Member departure

Status: draft for internal review.

Member departure covers two paths: a member leaving on its own through SelfRemove, and an admin removing another
member. This document specifies the SelfRemove path in full. Ordinary admin-initiated removal is an admin-gated
group-state change whose authorization is owned by
[../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) ("remove another member"); it otherwise
follows the normal commit, publish-lifecycle, and convergence rules.

SelfRemove lets a current member leave a group without asking an admin to remove them. It uses the MLS SelfRemove
proposal from the MLS extensions work and does not define a Marmot custom proposal type.

## Surfaces

- MLS proposal: SelfRemove.
- Protocol core: proposal ingest, deterministic commit, convergence, retained history.
- App component: `marmot.group.admin-policy.v1` for admin leave constraints.
- Transport: whichever transport carries the proposal and commit.

## Behavior

A current member MAY create a SelfRemove proposal for itself.

A non-admin member MAY self-remove if the MLS proposal is valid. A SelfRemove proposal whose sender is an active admin
in the prior epoch is invalid (see [../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) for the
definition of an active admin).

A departing admin first commits an admin-policy update that removes it from the admin list, then uses SelfRemove. The
admin-policy update is an ordinary admin-gated group-state change and is valid only if at least one other active admin
remains, so the last active admin MUST designate another admin before leaving.

This two-step flow applies to voluntary departure through SelfRemove only. An admin removed by another admin does not
use it: the removing commit drops the account's last leaf and its `admins` key together, under the coupling rule in
[../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) ("Active admins").

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
- the proposal sender is an active admin in the prior epoch;
- the leaving member commits the proposal;
- applying the commit would leave the group with no active admin;
- the committer is not a current member;
- the commit fails the normal MLS and Marmot convergence checks.

## Migration notes

MIP-era Marmot treated SelfRemove as part of group messaging behavior. In the v2 draft it lives in protocol core because
SelfRemove affects the required group-state flow.
