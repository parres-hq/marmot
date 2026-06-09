# Convergence

Status: draft for internal review.

Convergence chooses one canonical branch from unordered group input.

Commits are the consensus log. MLS application messages can witness that members used a branch, but they do not create
epochs and they do not replace MLS commit validation.

## Group policy

Group policy is the signed group-state value that tells clients how to run convergence for this group.

A client MAY choose policy values when it creates a group. Members MAY change policy values through a group-state
update. Once a policy is active, it is not a local preference: every member processing the same group epoch MUST use the
same policy bytes.

A client that cannot apply the active group policy MUST NOT join the group.

A policy format or policy value that changes convergence behavior is a required capability. A group-state update that
changes the active policy is valid only if every current member has advertised support for the resulting policy. A
client MUST reject any commit that would make the active policy unsupported by a current member.

The active convergence policy contains:

- `policy_version`: the version of the convergence policy format.
- `max_rewind_commits`: how far back from the current tip a branch MAY fork and still be eligible.
- `app_payload_past_epoch_limit`: how many past MLS epochs MAY still produce delivered app payloads or app-payload
  witnesses.
- `settlement_quiescence_ms`: the minimum time without new convergence-relevant input before a client MAY treat a
  convergence pass as settled and release queued outbound work.
- `witness_quorum_senders_per_epoch`: the number of distinct senders needed for one branch epoch to count toward witness
  quorum.
- `witness_quorum_epochs`: the number of branch epochs that MUST meet sender quorum.
- `max_witness_override_depth`: the maximum commit-depth boost a branch MAY receive from witness quorum.

`max_witness_override_depth` MUST NOT exceed `max_rewind_commits`. The witness-quorum boost is bounded so it can never
push a branch past the rollback horizon; allowing it to would let app-payload traffic beat an arbitrarily longer valid
commit branch, violating the invariant below. A policy that violates this bound MUST be rejected rather than applied.

`settlement_quiescence_ms` gates when a client decides it has waited long enough to run or finish convergence. It MUST NOT
enter the branch score.

Group policy MUST be encoded canonically and authenticated as group state. It MUST NOT depend on transport arrival
order, transport timestamps, outer transport event ids, or local receive order.

A convergence pass uses the active policy from the retained parent state being used for selection. A branch MUST NOT
score itself with policy values introduced by commits on that same branch. Policy changes apply after the
policy-changing commit becomes canonical.

Groups that do not yet carry explicit policy use the default policy for their group profile. A client MUST treat that
default as the active policy and persist it once the group records explicit policy bytes.

## Candidate branches

A client builds candidate branches by replaying MLS commit bytes from retained group states.

A commit creates a candidate edge only when it validates against exactly one parent state. A commit whose parent is not
available remains deferred until the parent appears or the input expires.

A client MUST NOT trust transport-provided parent metadata when building a branch. Parentage is derived by replaying MLS
bytes against retained candidate states.

Each candidate branch has:

- `fork_epoch`: the epoch where the branch diverged from retained canonical state;
- `tip_epoch`: the epoch reached after replaying the branch's valid commits;
- `tip_digest`: a digest of the tip commit bytes;
- `raw_commit_depth`: the number of valid commits from `fork_epoch` to `tip_epoch`;
- app-payload witnesses that decrypt on candidate states in the branch.

## Eligibility

Only branches inside the rollback horizon are eligible:

```text
current_tip_epoch - fork_epoch <= max_rewind_commits
```

Branches outside that horizon MUST NOT be selected.

A branch that needs a retained state older than the retained anchor MUST NOT be selected.

## App-payload witnesses

An app-payload witness is an MLS application message whose Marmot app payload decrypts against a candidate branch state.

Witnesses are counted by distinct Marmot sender identity per branch epoch. The sender identity is the account identity
authenticated by the MLS leaf credential for the application message, not an outer transport public key, Nostr event
author, relay, local device id, or transient leaf index.

One sender identity cannot increase a branch score by sending many messages in the same epoch. In a multi-device group,
multiple MLS leaves for the same Marmot account count as one sender identity for witness quorum.

For each branch epoch:

```text
epoch_witness_score =
  min(distinct_valid_app_senders_at_epoch,
      witness_quorum_senders_per_epoch)
```

For the candidate branch as a whole:

```text
app_witness_score =
  sum over branch epochs:
    min(distinct_valid_app_senders_at_epoch,
        witness_quorum_senders_per_epoch)
```

A branch meets witness quorum when at least `witness_quorum_senders_per_epoch` distinct senders witnessed at least
`witness_quorum_epochs` branch epochs.

When a branch meets witness quorum, the branch receives a bounded depth boost:

```text
effective_commit_depth =
  raw_commit_depth
  + (witness_quorum_met ? max_witness_override_depth : 0)
```

The boost is capped by group policy. App payload traffic MUST NOT let a branch beat an arbitrarily longer valid commit
branch.

## Branch selection

Eligible branches are compared in this order:

1. Higher `effective_commit_depth`.
2. Witness quorum beats no quorum.
3. Higher `raw_commit_depth`.
4. Higher `app_witness_score`.
5. Lower `tip_digest`.

Lower digest means lexicographic order over the 32 digest bytes.

Every value in this comparison MUST come from MLS-valid bytes, retained state, decrypted app payloads, or the group's
convergence policy.

Transport arrival order, transport timestamps, outer transport event ids, and local receive order MUST NOT participate
in branch selection.

## Same-epoch races

When two commits both advance the same source epoch, the lower content-derived ordering key wins:

```text
CommitOrderingKey {
  source_epoch,
  commit_digest = SHA-256(mls_bytes)
}
```

For same-epoch races, `source_epoch` is equal, so the lower `commit_digest` decides. Lower digest means lexicographic
order over the 32 digest bytes.

This rule is for branch choice only. The stored message id used to mark a losing commit is still separate from the
content-derived ordering key.

## Applying the selected branch

After selecting a branch, a client applies the selected branch by replaying the selected commit path from the retained
parent state.

The client then assigns dispositions:

- commits on the selected path are accepted;
- proposals consumed by selected commits are accepted;
- proposals consumed only by losing branches are dropped;
- app payloads from MLS application messages that decrypt on the selected branch are delivered;
- app payloads from MLS application messages that decrypt only on losing branches are invalidated;
- commits and MLS application messages beyond retained history are dropped.

Applying the selected branch also produces application-visible state notifications for changes the application MAY need
to render or act on. Examples include epoch advancement, member additions, member removals, app component changes,
branch recovery, and app payload invalidation.

If the required retained state is missing, the client MUST report the missing retained anchor and MUST NOT mutate
canonical group state. If the missing state is inside the rollback horizon, the client enters `Unrecoverable` until it
has a verified repair path.

After applying the selected branch, the client MAY release retained states older than the rollback horizon.
