# Publish lifecycle

Status: draft for internal review.

This document states the publish-before-apply rule for locally generated group-state changes.

## Rule

A locally generated group-state change MUST NOT become local canonical state until the client has confirmed that its
publish obligation succeeded.

This rule applies to:

- group creation
- invite
- leave
- group profile update
- capability upgrade
- admin policy update
- policy-generated commits, including SelfRemove auto-commits

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

## Auto-commit handling

Policy-generated commits produce publish obligations too.

When a client receives a proposal and policy selects that client to commit it, the client prepares the commit, retains
pending state, and exposes a publish obligation. The pending state does not become canonical until publication is
confirmed.

This applies to SelfRemove auto-commits.

## Failure

If publication fails, the client discards the pending state and keeps the inbound proposal or local action available if
retry is valid.

If another member publishes an equivalent or conflicting commit first, ordinary convergence decides the result.
