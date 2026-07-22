# Convergence

Status: adopted.

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
- `max_convergence_pass_ms`: the maximum duration of one convergence pass. This deadline is measured from the start of
  the pass and MUST NOT be extended by later input.
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
| `max_convergence_pass_ms`           | `5000`  |
| `witness_quorum_senders_per_epoch`  | `2`     |
| `witness_quorum_epochs`             | `1`     |
| `max_witness_override_depth`        | `1`     |

`policy_version` names this pinned profile, not a wire field: the table above is convergence policy version 1.

`max_witness_override_depth` MUST NOT exceed `max_rewind_commits`. The witness-quorum boost is bounded so it can never
push a branch past the rollback horizon; allowing it to would let app-payload traffic beat an arbitrarily longer valid
commit branch, violating the invariant below. The version-1 values satisfy this bound, and any future policy component
MUST satisfy it.

`settlement_quiescence_ms` and `max_convergence_pass_ms` bound one convergence pass. A pass starts when the client first
retains or reclassifies input that can change convergence. Both intervals are measured with the client's local
monotonic clock. The quiescence interval restarts only when newly retained or reclassified input can still change the
current pass's branch selection, for example by adding or invalidating an eligible candidate edge, changing a bounded
witness score, supplying a missing parent, or making deferred input processable. Ordinary app-payload delivery that
cannot change branch selection does not restart quiescence. Neither do duplicate, invalid, stale, already-dominated, or
already-fully-counted witness inputs.

The absolute pass deadline starts when the pass starts and MUST NOT restart. A client closes the pass at the earlier of:

1. `settlement_quiescence_ms` elapsing without score-changing input; or
2. `max_convergence_pass_ms` elapsing.

At that cutoff, the client freezes the pass's retained input batch, reaches a fixed point over that batch, selects and
applies the canonical branch, and returns to `Stable`. Input retained after the cutoff is not discarded; it belongs to
a later pass. The local cutoff controls scheduling and batch membership only. Input arrival time, cutoff time, and pass
membership MUST NOT enter candidate validity or the branch score.

After a bounded pass returns the group to `Stable`, the client MUST give one already-queued, admin-authorized local
group-state intent an opportunity to be prepared against the selected canonical state before it begins another
convergence pass solely because more inbound input is queued. Inbound input remains durably retained during that
opportunity. The prepared commit then follows the normal publication and convergence rules; this scheduling guarantee
does not make it valid, accepted, or canonical.

Convergence parameters are deliberately not group-tunable: a bad policy choice can fork a group. A future protocol
version that changes convergence behavior MUST ship the new policy as a new app component behind a required capability.
Until such a component exists, there is no mechanism to change the active policy.

## Candidate branches

A client builds candidate branches by replaying MLS commit bytes from retained group states.

A commit creates a candidate edge only when it validates against a candidate parent state. Validation here is full
commit validity: MLS validation; authorization of the authenticated committer against that parent state; and Marmot
component validation of the resulting state, including cross-component resulting-epoch checks such as the admin/leaf
coupling in [../app-components/admin-policy-v1.md](../app-components/admin-policy-v1.md) ("Validation").

Authorization is parent-relative. A committer can be authorized on one retained branch and unauthorized on another, so
failure against one candidate parent MUST NOT reject the commit against every parent. The commit creates an edge only
from a parent against which all checks succeed. A candidate edge whose resulting state fails Marmot component
invariants MUST NOT be created, so convergence can never select that invalid transition. A commit that is unauthorized
for every available matching parent is rejected as `authorization_failed` only when no unavailable parent could change
that result; otherwise it remains deferred while that parent may still arrive.

A commit whose parent is not available remains deferred until the parent appears or the input expires.

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
senders witnessed each of at least `witness_quorum_epochs` branch epochs, and false otherwise. Each epoch is evaluated
independently; the qualifying sender set MAY differ from epoch to epoch, and no single cohort is required to span all
quorum-counted epochs.

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
3. Higher `app_witness_score`.
4. Lower `tip_priority` (`privileged` before `ordinary`).
5. Lower `tip_committer`.
6. Lower `tip_digest`.

`raw_commit_depth` has no separate comparison step. It is already part of `effective_commit_depth`; if effective depth
and witness-quorum status are both tied, a further raw-depth comparison is necessarily tied as well.

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

State notifications are derived only from accepted commits on the selected branch and the canonical resulting state
they produce. A state notification derived from a commit is attributed to that commit's `commit_digest` (the same
`SHA-256` over the commit's MLS bytes defined in "Same-epoch races"). When branch selection supersedes a commit the
client previously applied — including the client's own published and confirmed commit — the client MUST emit a
group-state-change invalidation naming the superseded commit, and every state notification attributed to that commit
is withdrawn: the application treats the changes it announced as not having happened. This is the state-notification
counterpart of app-payload invalidation.

Notification objects are local API surface, so their exact shape is implementation-defined; the conformance
requirement is the resulting view. Once convergence is settled, the state notifications still in effect are exactly
those derivable from the accepted commits on the selected branch, and a group-state change that lost branch selection
MUST NOT remain visible to the application as a completed change.

If the required retained state is missing, the client MUST report the missing retained anchor and MUST NOT mutate
canonical group state. If the missing state is inside the rollback horizon, the client enters `Unrecoverable` until it
has a verified repair path.

After applying the selected branch, the client MAY release retained states older than the rollback horizon.
