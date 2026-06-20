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

The eligible committer list is:

1. start with the current members in the proposal's source epoch;
2. remove the leaving member;
3. remove members that are not allowed to commit the resulting state;
4. sort the remaining members by increasing MLS leaf index.

Initially, eligible member position `0` SHOULD auto-commit the proposal promptly when the group lifecycle permits
local group-state commits.

If no accepted commit consumes the SelfRemove, later members MAY auto-commit through deterministic fallback rounds:

- round `0` selects eligible member position `0`;
- round `1` selects eligible member position `1` after one fallback quiescence window;
- round `n` selects eligible member position `n` after `n` fallback quiescence windows.

If a fallback round has no eligible member at its selected position, automatic fallback rounds are exhausted. The retained
SelfRemove then awaits an explicit user or recovery action; this draft defines no further automatic committer.

The fallback quiescence window is the pinned convergence-policy `settlement_quiescence_ms`. It is a local scheduling
gate only: it tells a client when it is allowed to try a later-round commit. It MUST NOT enter branch scoring, same-epoch
commit ordering, message identity, duplicate handling, or validation. If several fallback commits are published, ordinary
convergence chooses the canonical branch from their MLS-valid commit bytes.

A client starts counting fallback windows for a retained SelfRemove only while it is allowed to prepare local group-state
commits and has no accepted commit that consumes that SelfRemove. If new convergence-relevant input for the proposal's
source epoch arrives before the client's next fallback round opens, the client SHOULD re-run convergence before preparing
a fallback commit. A client whose own fallback publish fails MUST follow the normal publish-before-apply failure rule:
discard the pending state, keep the SelfRemove available if it is still valid, and wait for another fallback quiescence
window before retrying automatically.

The leaver MAY rebroadcast the same serialized SelfRemove proposal bytes while no accepted commit consumes it. The
leaver MUST NOT generate an unbounded stream of fresh SelfRemove proposals for the same source epoch. A client that
receives multiple SelfRemove proposals from the same leaving member for the same source epoch before one is consumed
MUST bound storage and commit eligibility to one retained proposal; byte-identical rebroadcasts are duplicates under
[inbound-processing.md](./inbound-processing.md), and non-identical redundant proposals are stale unless a future
protocol version defines a distinct retry identity.

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
