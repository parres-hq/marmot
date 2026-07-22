# Member departure

Status: adopted.

Member departure covers two paths: a member leaving on its own through SelfRemove, and an admin removing another
member. This document specifies the SelfRemove path in full. Ordinary admin-initiated removal is an admin-gated
group-state change whose authorization is owned by
[../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) ("remove another member"); it otherwise
follows the normal commit, publish-lifecycle, and convergence rules. Both paths end with the removed member realizing
its own removal; that flow is "Realizing removal" below.

SelfRemove lets a current member leave a group without asking an admin to remove them. It uses the MLS SelfRemove
proposal from the MLS extensions work and does not define a Marmot custom proposal type.

## Surfaces

- MLS proposal: SelfRemove.
- Protocol core: proposal ingest, opportunistic SelfRemove commits, convergence, retained history.
- App component: `marmot.group.admin-policy.v1` for admin leave constraints.
- Transport: whichever transport carries the proposal and commit.

## Behavior

A current member MAY create a SelfRemove proposal for itself.

A non-admin member MAY self-remove if the MLS proposal is valid. A SelfRemove proposal whose sender is an active admin
in the prior epoch is invalid (see [../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) for the
definition of an active admin).

A departing admin MUST first complete an accepted admin-policy update that removes its account from the admin list
before creating a SelfRemove proposal. The admin-policy update is an admin-gated group-state change and is valid only
if at least one other active admin remains, so the last active admin MUST designate another admin before leaving.

This two-step flow applies to voluntary departure through SelfRemove only. An admin removed by another admin does not
use it: the removing commit drops the account's last leaf and its `admins` key together, under the coupling rule in
[../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) ("Active admins").

The leaving member MUST NOT commit its own SelfRemove proposal. A remaining authorized member commits it.

After handing the SelfRemove proposal to the active transport, the leaving member enters a local `Leaving` state for
that group. While `Leaving`, the member MUST NOT send MLS application messages, group-state commits, or non-SelfRemove
MLS proposals in that group; it MAY publish a fresh SelfRemove proposal for a newer source epoch when the prior
SelfRemove becomes stale. Transport-level retries of the same serialized SelfRemove proposal MAY continue, but the
client MUST NOT generate fresh SelfRemove proposal bytes for the same source epoch. The `Leaving` state is backed by a
durable leave request and ends only when an accepted commit removes the member, the member repairs or rejoins through a
future specified recovery flow, a future explicit cancel flow clears the request, or the client discards the local group
copy.

If an accepted commit advances the group to a later epoch without removing the leaving member, the prior SelfRemove is
stale because MLS proposals are epoch-bound. The client remains in `Leaving`, MUST NOT reuse the old SelfRemove
proposal bytes, and SHOULD publish a fresh SelfRemove proposal for the new source epoch once local group-state commits
are allowed.

## SelfRemove commits

A SelfRemove-only Commit MAY reference one or more valid retained SelfRemove proposals and MUST NOT contain another
proposal type. Each referenced SelfRemove proposal is validated independently, and one invalid proposal makes the whole
Commit invalid.

Any remaining member that is authorized to commit the resulting state MAY commit the retained SelfRemove proposals.
Marmot does not elect one deterministic SelfRemove committer.

A client that observes a valid peer SelfRemove proposal SHOULD schedule a SelfRemove-only Commit after a short
randomized jitter while the group lifecycle permits local group-state commits. Before preparing the commit, the client
SHOULD re-check whether an accepted commit already consumed that SelfRemove. If the group lifecycle or convergence
status does not allow local group-state commits when the jitter expires, the client waits until local group-state
commits are allowed and then re-checks the retained SelfRemove.

The jitter is local scheduling only. It MUST NOT enter branch scoring, same-epoch commit ordering, message identity,
duplicate handling, or validation. If several members publish SelfRemove-only commits for the same proposal, ordinary
convergence chooses the canonical branch from their MLS-valid commit bytes.

A client whose own SelfRemove-only commit publish fails MUST follow the normal publish-before-apply failure rule:
discard the pending state and keep the SelfRemove available if it is still valid and unconsumed.

A client that receives multiple SelfRemove proposals from the same leaving member for the same source epoch before one
is consumed MUST retain only the proposal with the lexicographically lowest `self_remove_proposal_digest`, where:

```text
self_remove_proposal_digest = SHA-256(serialized_proposal_mls_message)
```

`serialized_proposal_mls_message` is the complete serialized handshake `MLSMessage` carrying the SelfRemove proposal,
under Marmot's pinned [handshake wire format](../foundation/mls-protocol.md#handshake-wire-format). If a lower-digest
proposal arrives, it replaces the retained proposal for commit eligibility and the replaced proposal becomes stale.
Byte-identical repeats are duplicates under
[inbound-processing.md](./inbound-processing.md); other non-selected proposals are stale. Local arrival order MUST NOT
choose the retained proposal.

## Realizing removal

Both departure paths end the same way for the removed member: its client realizes that its membership ended, tells the
application, and stops treating the group as active.

The authenticated evidence of removal is always the same bytes: an accepted commit on the selected canonical branch
that removes this local client's own MLS leaf — an admin-initiated Remove or a committed SelfRemove — recorded in
retained canonical state. This evidence is leaf-scoped: other current leaves with the same Marmot account identity do
not prevent this local leaf from realizing its removal. When the client applies such a commit, it MUST emit a
self-removed state notification (see [inbound-processing.md](./inbound-processing.md), "Application-visible output")
and mark the local group copy removed.

Realization is a state-derived obligation, not a one-shot event at commit-apply time: whenever retained canonical group
state records the local member's removal and the local group copy is not yet marked removed, the client MUST perform
the realization above. A client MAY have recorded the removing commit without the application ever observing the
resulting notification; the obligation stands until the group copy is marked removed.

Later group input for such a group is the fallback trigger. It receives the `SelfEvicted` outcome (`stale`
disposition, `stale_epoch` category, see [../foundation/errors.md](../foundation/errors.md)). `SelfEvicted` attaches
to that later input, not to the removing commit and not to a local presentation mismatch; the input itself proves
nothing and need not be decrypted or authenticated, because the evidence of removal is the retained canonical state —
the input is classified by its group, like other stale input for groups the client cannot process further. Processing
it MUST perform the realization above when it has not already happened. The client MUST NOT classify such input as
ordinary stale traffic while continuing to present the group as active.

Failure to decrypt group traffic is not, by itself, evidence of removal. Without authenticated evidence that the local
member's own leaf was removed, undecryptable input is a missing-history or repair condition (see
[retained-history.md](./retained-history.md) and [group-state.md](./group-state.md), "Unrecoverable cases"), and the
client MUST NOT present the group as removed.

A removed group copy is retained inactive, not deleted. The removed member:

- MUST NOT prepare or publish commits, proposals, or MLS application messages for the group;
- MUST NOT present the group to the user as active or sendable;
- MAY retain previously delivered content and group history for local display;
- MAY discard the local group copy at any time.

Removal is terminal for that group copy. Rejoining happens only through a new Welcome, which creates a new local group
state under [joining.md](./joining.md). Retention does not weaken forward secrecy: a removed member cannot decrypt
traffic from epochs after its removal.

## Validation

A SelfRemove-only Commit is invalid if:

- it references no SelfRemove proposal or includes a proposal of another type;
- any referenced proposal does not target its authenticated sender;
- any referenced proposal sender is an active admin in the prior epoch;
- the committer is the sender and target of any referenced SelfRemove proposal;
- the committer is not a current member;
- the commit fails the normal MLS and Marmot convergence checks.

## Migration notes

MIP-era Marmot treated SelfRemove as part of group messaging behavior. In this spec it lives in protocol core because
SelfRemove affects the required group-state flow.
