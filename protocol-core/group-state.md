# Group state

Status: draft for internal review.

Each Marmot group has one canonical MLS state at a time. A client MAY temporarily hold candidate or pending state, but
only one state is visible as the group's canonical state.

## Lifecycle states

The group lifecycle has five states:

- `Stable`: the group has a canonical MLS epoch. Normal inbound processing and outbound work MAY proceed.
- `PendingPublish`: the client has prepared a local group-state commit, but has not confirmed that the required bytes
  were published.
- `Merging`: publication was confirmed, and the client is applying the staged commit to its local canonical state.
- `Recovering`: the client detected a fork-shaped conflict and is trying to select a safe branch from retained state.
- `Unrecoverable`: the client cannot safely select a branch from its retained local material.

`Unrecoverable` is local to one client. It does not mean the Marmot group is dead. It means that this client MUST repair
its group state, restore retained material, rejoin, or discard the local group copy before it can safely send or apply
more group traffic.

`Stable` is the only state where a client MAY prepare a new local group-state commit. Outbound app payloads are also
held while convergence input is unresolved, because they MUST be encrypted against the selected canonical state.

## Legal transitions

```text
Stable
  -> PendingPublish      local group-state commit prepared
PendingPublish
  -> Merging             publish obligation confirmed
PendingPublish
  -> Stable              publish obligation failed or was abandoned
Merging
  -> Stable              staged commit applied
Stable
  -> Recovering          fork detected and retained recovery is required
Recovering
  -> Stable              a canonical branch was selected and applied
Recovering
  -> Unrecoverable       no safe branch can be selected from retained local material
Unrecoverable
  -> Stable              state was repaired, restored, or replaced by a verified join
```

Fork detection runs only from `Stable`, against settled canonical state. There is no `Merging -> Recovering` edge: a
competing branch observed while the client is applying its own confirmed commit is retained, the merge completes to
`Stable`, and fork detection then runs from `Stable`. `Recovering` re-entry is implicit: convergence-relevant input
that arrives while the group is already in `Recovering` is folded into the same recovery pass, and the group stays in
`Recovering` until a branch is selected and applied (`-> Stable`) or no safe branch exists (`-> Unrecoverable`).

A client MUST reject a local group-state commit while the group is in `PendingPublish`, `Merging`, `Recovering`, or
`Unrecoverable`.

Inbound group messages MAY be retained in any non-`Stable` state. Whether retained inbound may change canonical group
state depends on the state:

- during `PendingPublish` and `Merging`, retained inbound MUST NOT be applied to canonical group state;
- during `Recovering`, retained inbound is replayed only as candidate material for convergence; canonical group state
  changes only when a selected branch is applied (see below);
- during `Unrecoverable`, retained inbound MUST NOT be applied to canonical group state until a verified repair path
  restores, repairs, or replaces the local group state.

While a group is in `Recovering`, a client MAY process or reprocess retained input to build candidate branches, score
them, and select a canonical branch. That processing MUST NOT release outbound work or emit delivered app payloads until
the selected branch has been applied and the lifecycle returns to `Stable`.

## Unrecoverable cases

A client enters `Unrecoverable` when it cannot determine the canonical branch without violating the group's retention or
validation rules.

Examples include:

- the client needs a retained state inside the rollback horizon, but that state is missing;
- the client cannot validate any candidate branch from the retained anchor;
- local group state is corrupted and cannot validate the retained commit path.

A client in `Unrecoverable` MUST NOT choose the current local state merely because it is the only state available. It
MUST stop applying group-state changes until it has a verified repair path.

A repair path MAY restore retained state, import a verified current snapshot, rejoin through MLS, or use another
recovery method defined by a future protocol-core document.

## Convergence status

Convergence has a separate derived status:

- `Syncing`: convergence-relevant input is still arriving or the quiescence window has not elapsed.
- `Resolving`: the quiescence window has elapsed, but the client still has unresolved convergence work, such as a child
  commit whose parent has not been retained or fetched yet.
- `Settled`: candidate processing reached a fixed point and the selected branch, if any, has been applied.
- `Blocked`: candidate processing cannot safely continue without a repair path or missing retained material.

Convergence status is derived from stored input and policy. It is not a claim made by the transport.

The lifecycle state is authoritative; convergence status is a derived view of how convergence is progressing within it.
The legal combinations are:

| Convergence status | Lifecycle states it can appear in | Notes                                                                 |
| ------------------ | --------------------------------- | --------------------------------------------------------------------- |
| `Syncing`          | `Stable`, `Recovering`            | input still arriving or quiescence not elapsed                        |
| `Resolving`        | `Stable`, `Recovering`            | quiescence elapsed, work outstanding (e.g. a child commit's parent)   |
| `Settled`          | `Stable`                          | fixed point reached and any selected branch applied                   |
| `Blocked`          | `Recovering`, `Unrecoverable`     | needs a repair path or missing retained material                      |

Two couplings follow from this table. A group leaves `Recovering` for `Stable` only after convergence reaches
`Settled` (a selected branch was applied). A `Blocked` convergence status that cannot be cleared by retained material
is the `Unrecoverable` condition: when recovery has no safe branch and no repair path, the lifecycle moves to
`Unrecoverable`. `PendingPublish` and `Merging` are local-publish states, not convergence passes, so convergence status
is not meaningful while the group is in them.

## Local actions during convergence

When convergence status is `Syncing`, `Resolving`, or `Blocked`, a client SHOULD queue local outbound intents instead
of preparing them against a state that MAY lose branch selection or require repair.

Queued app-payload sends are encrypted after convergence status reaches `Settled` and the lifecycle state allows
outbound work.

Queued group-state changes are regenerated after convergence status reaches `Settled` and the lifecycle state allows
outbound work. A staged commit created before branch selection MUST NOT be reused after convergence changes the
canonical state.
