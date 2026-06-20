# Publish lifecycle

Status: draft for internal review.

This document states the publish-before-apply rule for locally generated group-state changes.

## Rule

A locally generated group-state change MUST NOT become local canonical state until the client has confirmed that its
publish obligation succeeded.

This rule applies to:

- group creation (see "Group creation" below — the obligation shape differs from all other operations)
- invite
- member removal by an admin
- group profile update
- capability upgrade
- admin policy update
- policy-generated commits, including SelfRemove auto-commits

A member's own departure is a SelfRemove *proposal*, not a local commit. The leaver publishes the proposal and does not
apply any pending state, because another authorized member commits it (see
[member-departure.md](./member-departure.md)). Publish-before-apply binds the committer of that SelfRemove, which is
covered by the auto-commit entry above, not the leaver.

## Shape

```text
prepare local commit
  -> retain pending state
  -> produce publish obligation
  -> publish required bytes
  -> confirm or fail publication
  -> apply or discard pending state
```

## Publish obligation

A publish obligation has four protocol-relevant parts:

- outbound MLS or Marmot bytes;
- the recipient scope for those bytes;
- the prior canonical state they were generated from;
- the pending state they would make canonical after publication.

The exact local representation is implementation-defined.

A publish obligation succeeds when the active transport binding reports an acknowledged accept for the obligation's
bytes from at least one endpoint in the obligation's recipient scope. Each transport binding MUST define its
acknowledgement signal. A transport binding or client MAY apply a stricter success rule, but at least one acknowledged
accept is the minimum, and a client MUST NOT treat anything weaker (such as a queued or sent-without-acknowledgement
state) as success.

Group creation is special because there is no existing group recipient set before the group exists.

For one-member group creation, the creation publish obligation has an empty outbound byte set and an empty recipient
scope. The creator MUST treat the empty obligation as immediately satisfied and make the initial state canonical
without publishing any group message bytes.

For founding creation with initial invitees, the creation publish obligation contains the MLS Welcome deliveries for the
initial invitees whose KeyPackages were consumed. Its recipient scope is exactly those initial invitees, addressed by the
active transport binding for Welcome delivery. It does not include a group-message publish of the founding Add
commit to existing members, because no existing peers can be forked by a missing creation Commit. This exception
is limited to the epoch-0 founding commit. Any further commits — including additional component bootstrapping
bundled with group creation — follow the normal publish-before-apply rule.

The founding creator's local state becomes canonical immediately after the epoch-0 founding commit, regardless
of Welcome delivery outcome. Welcome delivery to initial invitees is a separate retryable per-invitee obligation:
each invitee's Welcome delivery succeeds or fails independently and does not affect the group's canonical state.
Consumed KeyPackage material for founding invitees cannot be restored on Welcome delivery failure; if a Welcome
cannot be delivered, the founding creator MAY re-invite the unreachable member using a new Add commit against
the now-canonical group with a fresh KeyPackage.

## Auto-commit handling

Policy-generated commits produce publish obligations too.

When a client receives a proposal and policy selects that client to commit it, the client prepares the commit, retains
pending state, and exposes a publish obligation. The pending state does not become canonical until publication is
confirmed.

This applies to SelfRemove auto-commits, including later fallback-round commits described in
[member-departure.md](./member-departure.md). A fallback round only selects who may try to publish next; it does not
weaken publish-before-apply and it does not decide canonical group state.

## Failure

If publication fails, the client discards the pending state and keeps the inbound proposal or local action available if
retry is valid.

For a SelfRemove auto-commit, publication failure leaves the SelfRemove proposal available for retry or for a later
eligible fallback committer, as long as the proposal has not been consumed by an accepted commit and remains inside
retained history.

If another member publishes an equivalent or conflicting commit first, ordinary convergence decides the result.
