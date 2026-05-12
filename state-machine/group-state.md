# Group state

Status: sketch.

Each Marmot group has one canonical MLS state at a time. A client may temporarily hold candidate or pending state, but
only one state is visible as the group's canonical state.

## Lifecycle states

The group lifecycle has five states:

- `Stable`: the group has a canonical MLS epoch. Normal inbound processing and outbound work may proceed.
- `PendingPublish`: the client has prepared a local group-state commit, but has not confirmed that the required bytes
  were published.
- `Merging`: publication was confirmed, and the client is applying the staged commit to its local canonical state.
- `Recovering`: the client detected a fork-shaped conflict and is trying to select a safe branch from retained state.
- `Unrecoverable`: the client cannot safely select a branch from its retained local material.

`Unrecoverable` is local to one client. It does not mean the Marmot group is dead. It means that this client must repair
its group state, restore retained material, rejoin, or discard the local group copy before it can safely send or apply
more group traffic.

`Stable` is the only state where a client may prepare a new local group-state commit. Outbound app payloads are also
held while convergence input is unresolved, because they must be encrypted against the selected canonical state.

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

A client MUST reject a local group-state commit while the group is in `PendingPublish`, `Merging`, `Recovering`, or
`Unrecoverable`.

Inbound group messages MAY be retained during `PendingPublish`, `Merging`, `Recovering`, or `Unrecoverable`. They MUST
be processed or reprocessed only after the group returns to `Stable`.

## Unrecoverable cases

A client enters `Unrecoverable` when it cannot determine the canonical branch without violating the group's retention or
validation rules.

Examples include:

- the client needs a retained state inside the rollback horizon, but that state is missing;
- the client cannot validate any candidate branch from the retained anchor;
- local group state is corrupted and cannot validate the retained commit path.

A client in `Unrecoverable` MUST NOT choose the current local state merely because it is the only state available. It
MUST stop applying group-state changes until it has a verified repair path.

A repair path may restore retained state, import a verified current snapshot, rejoin through MLS, or use another
recovery method defined by a future state-machine document.

## Sync states

Convergence has a separate sync result:

- `Syncing`: convergence-relevant input is still arriving or the quiescence window has not elapsed.
- `Canonicalizing`: the client is building candidate branches and assigning dispositions.
- `Stable`: candidate processing reached a fixed point and the selected branch, if any, has been applied.

Sync state is derived from stored input and policy. It is not a claim made by the transport.

## Local actions during sync

When a group is syncing, a client SHOULD queue local outbound intents instead of preparing them against a state that may
lose branch selection.

Queued app-payload sends are encrypted after the selected branch is stable.

Queued group-state changes are regenerated after the selected branch is stable. A staged commit created before branch
selection MUST NOT be reused after convergence changes the canonical state.
