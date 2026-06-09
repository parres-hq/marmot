# Retained history

Status: draft for internal review.

Marmot clients need retained group state so they can recover from forks and late delivery.

Retention is a protocol tradeoff. Keeping more history improves recovery from delayed or withheld commits. Keeping less
history limits how far a client can be forced to replay old state and improves forward secrecy guarantees.

## Retained anchor

The retained anchor is the oldest group state from which a client can rebuild a candidate branch.

A client MUST retain enough state to replay candidate branches inside the group's rollback horizon. The storage format
is implementation-defined.

At minimum, a client needs retained state for:

- the current canonical tip;
- each epoch inside `max_rewind_commits` from the current tip;
- any staged local commit waiting for publish confirmation;
- any candidate parent state still needed by deferred input inside the rollback horizon.

## Late commits

Late commits are judged by their source epoch:

- If the source epoch is at or after the retained anchor, the commit MAY be replayed during convergence.
- If the source epoch is older than the retained anchor, the commit MUST be dropped as `BeyondAnchor`.
- If the source epoch is inside the rollback horizon but the required retained state is missing, convergence MUST report
  `MissingRetainedAnchor`, leave canonical group state unchanged, and move the local group to `Unrecoverable`.

The third case is storage loss, not a transport gap. A commit whose parent state has not yet been replayed — because the
parent commit has not arrived — is **deferred**, not `Unrecoverable`: it waits for the parent under
[convergence.md](./convergence.md) ("Candidate branches") and [inbound-processing.md](./inbound-processing.md#deferred-input)
("Deferred input"). `MissingRetainedAnchor` and the move to `Unrecoverable` apply only when retained state that a candidate
branch requires inside the rollback horizon has been *lost from storage* (see [convergence.md](./convergence.md): "the
client enters `Unrecoverable` until it has a verified repair path").

## App-payload retention

MLS application messages have their own retained decryption window for app payloads. The width of that window is the
signed convergence-policy field `app_payload_past_epoch_limit` (the number of past MLS epochs that may still produce
delivered app payloads or app-payload witnesses; see [convergence.md](./convergence.md)).

An MLS application message that is older than the retained app-payload window (`app_payload_past_epoch_limit` past
epochs) MUST expire.

An MLS application message for a future candidate epoch MAY remain deferred until convergence selects a branch that can
decrypt its Marmot app payload or until the message expires.

## Pruning

After convergence reaches a settled selected branch, a client SHOULD prune retained states older than the group's
rollback horizon.

Pruning MUST NOT remove retained state that is still needed to resolve an active `PendingPublish`, `Merging`,
`Recovering`, or `Unrecoverable` state.
