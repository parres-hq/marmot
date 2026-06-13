# Convergence

Status: draft for internal review.

Convergence chooses one canonical branch from unordered group input.

Commits are the consensus log. MLS application messages can witness that members used a branch, but they do not create
epochs and they do not replace MLS commit validation.

## Convergence policy

The convergence policy tells clients how to run convergence. The v1 convergence policy is a set of protocol constants:
every client MUST use exactly the values below. The policy is not carried in group state and is not a local preference;
every convergence pass, and every branch scored within it, uses the same values.

The convergence policy contains:

- `max_rewind_commits`: how far back from the current tip a branch MAY fork and still be eligible.
- `app_payload_past_epoch_limit`: how many past MLS epochs MAY still produce delivered app payloads or app-payload
  witnesses (the exact window formula is in [retained-history.md](./retained-history.md), "App-payload retention").
- `settlement_quiescence_ms`: the minimum time without new convergence-relevant input before a client MAY treat a
  convergence pass as settled and release queued outbound work.
- `witness_quorum_senders_per_epoch`: the number of distinct senders needed for one branch epoch to count toward witness
  quorum.
- `witness_quorum_epochs`: the number of branch epochs that MUST meet sender quorum.
- `max_witness_override_depth`: the maximum commit-depth boost a branch MAY receive from witness quorum.

The Marmot convergence policy, version 1, is:

| Field                               | Value   |
| ----------------------------------- | ------- |
| `max_rewind_commits`                | `5`     |
| `app_payload_past_epoch_limit`      | `5`     |
| `settlement_quiescence_ms`          | `1000`  |
| `witness_quorum_senders_per_epoch`  | `2`     |
| `witness_quorum_epochs`             | `1`     |
| `max_witness_override_depth`        | `1`     |

`policy_version` names this pinned profile, not a wire field: the table above is convergence policy version 1.

`max_witness_override_depth` MUST NOT exceed `max_rewind_commits`. The witness-quorum boost is bounded so it can never
push a branch past the rollback horizon; allowing it to would let app-payload traffic beat an arbitrarily longer valid
commit branch, violating the invariant below. The version-1 values satisfy this bound, and any future policy component
MUST satisfy it.

`settlement_quiescence_ms` gates when a client decides it has waited long enough to run or finish convergence. It MUST
NOT enter the branch score.

Convergence parameters are deliberately not group-tunable: a bad policy choice can fork a group. A future protocol
version that changes convergence behavior MUST ship the new policy as a new app component behind a required capability.
Until such a component exists, there is no mechanism to change the active policy.

## Candidate branches

A client builds candidate branches by replaying MLS commit bytes from retained group states.

A commit creates a candidate edge only when it validates against exactly one parent state. A commit whose parent is not
available remains deferred until the parent appears or the input expires.

A client MUST NOT trust transport-provided parent metadata when building a branch. Parentage is derived by replaying MLS
bytes against retained candidate states.

Each candidate branch has:

- `fork_epoch`: the epoch where the branch diverged from retained canonical state;
- `tip_epoch`: the epoch reached after replaying the branch's valid commits;
- `tip_priority`: the authenticated ordering class of the branch's tip commit. `privileged` commits are valid commits
  that require an administrator according to the group's application policy (membership changes, app-data component
  updates, and any other admin-only staged commit). `ordinary` commits are valid member commits that do not require an
  administrator (for example member self-updates and self-removes).
- `tip_committer`: the authenticated Marmot account identity of the branch's tip commit sender, derived from the MLS
  credential/leaf that authenticated the commit, not from transport metadata.
- `tip_digest`: `SHA-256` of the serialized MLS message bytes of the branch's tip commit (the same Commit
  `MLSMessage` bytes the branch replayed to reach `tip_epoch`). These bytes are deterministic because Marmot pins one
  handshake wire format, so the same authenticated commit cannot yield two different digests (see
  [../foundation/mls-protocol.md](../foundation/mls-protocol.md), "Handshake wire format"). It is exactly 32 bytes. For a
  branch whose only commit is its tip, `tip_digest` is byte-for-byte the same value as that commit's `commit_digest` in
  "Same-epoch races" below; both are `SHA-256` over the one Commit's MLS bytes. `tip_digest` is only a final tie-breaker
  after fixed authenticated metadata.
- `raw_commit_depth`: the number of valid commits from `fork_epoch` to `tip_epoch`;
- app-payload witnesses that decrypt at the branch epochs defined below.

The branch epochs of a candidate are the epochs strictly greater than `fork_epoch` and at most `tip_epoch`.

## Eligibility

Only branches inside the rollback horizon are eligible:

```text
current_tip_epoch - fork_epoch <= max_rewind_commits
```

Branches outside that horizon MUST NOT be selected.

A branch that needs a retained state older than the retained anchor MUST NOT be selected.

## App-payload witnesses

An app-payload witness is an MLS application message whose Marmot app payload decrypts against a candidate branch state
at one of that branch's branch epochs. An MLS application message that decrypts at `fork_epoch` or earlier is not an
app-payload witness for any candidate. A witness MUST also be inside the retained app-payload window, evaluated with
the candidate's `tip_epoch` as the reference tip (the window formula is in
[retained-history.md](./retained-history.md), "App-payload retention").

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

For the candidate branch as a whole, sum that per-epoch score:

```text
app_witness_score =
  sum over branch epochs of epoch_witness_score
```

`witness_quorum_met` is the boolean used below. It is true when at least `witness_quorum_senders_per_epoch` distinct
senders witnessed each of at least `witness_quorum_epochs` branch epochs, and false otherwise.

When `witness_quorum_met` is true, the branch receives a bounded depth boost:

```text
effective_commit_depth =
  raw_commit_depth
  + (witness_quorum_met ? max_witness_override_depth : 0)
```

The boost is capped by the pinned policy. App payload traffic MUST NOT let a branch beat an arbitrarily longer valid
commit branch.

## Branch selection

Eligible branches are compared in this order:

1. Higher `effective_commit_depth`.
2. Witness quorum beats no quorum.
3. Higher `raw_commit_depth`.
4. Higher `app_witness_score`.
5. Lower `tip_priority` (`privileged` before `ordinary`).
6. Lower `tip_committer`.
7. Lower `tip_digest`.

Lower `tip_committer` means lexicographic order over the authenticated member-id bytes. Lower digest means
lexicographic order over the 32 digest bytes. Digest ordering is a same-committer fallback, not the primary fork winner.

Every value in this comparison MUST come from MLS-valid bytes, retained state, decrypted app payloads, or the pinned
convergence policy.

Transport arrival order, transport timestamps, outer transport event ids, and local receive order MUST NOT participate
in branch selection.

## Same-epoch races

When two commits both advance the same source epoch, the lower authenticated ordering key wins:

```text
CommitOrderingKey {
  source_epoch,
  priority,       // privileged < ordinary
  committer,      // authenticated Marmot account id
  commit_digest = SHA-256(mls_bytes)
}
```

For same-epoch races, `source_epoch` is equal. A valid privileged commit wins over an ordinary commit before byte
ordering, so an admin removal or other authorized membership change is not defeated by a targeted member's concurrent
self-update solely by choosing different commit bytes. If both commits have the same `priority`, lower `committer`
lexicographically wins. The lower `commit_digest` decides only when the same authenticated committer produced multiple
same-priority commits for the same source epoch.

This rule is for branch choice only. The stored message id used to mark a losing commit is still separate from the
ordering key. Implementations MUST NOT use transport source, relay metadata, or any unauthenticated sender claim in this
key.

## Applying the selected branch

After selecting a branch, a client applies the selected branch by replaying the selected commit path from the retained
parent state.

The client then assigns dispositions (the disposition vocabulary is pinned in
[../foundation/errors.md](../foundation/errors.md)):

- commits on the selected path are accepted;
- proposals consumed by selected commits are accepted;
- proposals consumed only by losing branches are stale;
- MLS application messages that decrypt on the selected branch are accepted, and their Marmot app payloads are
  delivered to the application;
- MLS application messages that decrypt only on losing branches are invalidated, and their app payloads are withdrawn
  from application output;
- commits and MLS application messages beyond retained history are stale (a commit older than the retained anchor is
  reported as `BeyondAnchor`).

Applying the selected branch also produces application-visible state notifications for changes the application MAY need
to render or act on. Examples include epoch advancement, member additions, member removals, app component changes,
branch recovery, and app payload invalidation.

If the required retained state is missing, the client MUST report the missing retained anchor and MUST NOT mutate
canonical group state. If the missing state is inside the rollback horizon, the client enters `Unrecoverable` until it
has a verified repair path.

After applying the selected branch, the client MAY release retained states older than the rollback horizon.
