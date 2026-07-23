# Results and rejections

Status: adopted.

Marmot clients SHOULD be able to describe why an input did not produce application content.

This file names shared categories. It does not require local APIs to use these exact enum names.

## Input categories

An input that does not produce application content SHOULD map to one of these categories:

- `duplicate`: the same protocol input was already seen.
- `own_echo`: the input is the client's own already-accounted-for output.
- `wrong_recipient`: the input targets another account, device, group, or routing id.
- `unknown_group`: the client has no group state that can process the input.
- `stale_epoch`: the input is from an epoch the client will not process.
- `invalid_encoding`: bytes failed the owning document's parser or length rules.
- `invalid_signature`: a required MLS, Nostr, or component signature check failed.
- `unsupported_required_feature`: the group requires a feature the client does not understand.
- `authorization_failed`: the sender or committer is not allowed to make the change.
- `missing_history`: the client would need retained state it no longer has.
- `transport_rejected`: an outbound publication or delivery attempt failed at the transport layer. This category does
  not describe inbound bytes that were never received.

Protocol-core docs can split these into more detailed outcomes when needed.

## Dispositions

Inbound protocol input that passes the branch-independent admission gate — it parses, its branch-independent required
signatures verify, and the client supports its required features — can enter convergence and receive one of four
convergence dispositions; the processing flow that assigns them is
[../protocol-core/inbound-processing.md](../protocol-core/inbound-processing.md):

- `accepted`: the input is part of, or was consumed by, the selected canonical branch.
- `deferred`: the input cannot yet receive a terminal classification or canonical acceptance and is reconsidered when
  missing state arrives or convergence advances.
- `stale`: the input can no longer affect the group.
- `invalidated`: the input's MLS application message decrypts only on a losing branch, so its app payload is withdrawn
  from application output.

Input that fails a branch-independent gate does not reach convergence and receives no convergence disposition. It is
rejected before convergence — the `fail closed` path in
[../protocol-core/inbound-processing.md](../protocol-core/inbound-processing.md) — and is described by
`unknown_group`, `invalid_encoding`, `invalid_signature` when the failed signature check is branch-independent, or
`unsupported_required_feature`. An input for an unknown group cannot be authenticated against group state the client
does not have; `unknown_group` is therefore a pre-convergence category, not a `stale` disposition.

Local admission checks for byte-identical duplicates, already-accounted-for own echoes, and inputs addressed to another
recipient likewise produce `duplicate`, `own_echo`, or `wrong_recipient` without a convergence disposition. `stale` is
reserved for input admitted to convergence that can no longer affect the group.

Some MLS authentication, including membership-tag or sender-signature checks, requires retained source-epoch or
candidate-parent state. Those checks run during convergence candidate construction, not in the branch-independent
admission gate. If no retained state authenticates the membership tag, the input remains deferred while its parent may
still arrive. Once that authentication identifies the candidate parent, a failed sender-signature or other terminal MLS
authentication check is `invalid_signature` and receives no convergence disposition.

Authorization can depend on the prior group state. A Commit's authorization is therefore evaluated against the
candidate parent identified by parent-dependent MLS authentication during candidate construction, not as one
branch-independent gate. A retained state that does not authenticate the Commit cannot cause an authorization failure.
If no retained state passes parent-dependent MLS authentication, the Commit remains deferred while its source epoch is
inside or ahead of the rollback horizon. Once authentication identifies the candidate parent, failed authorization is
terminal `authorization_failed` and receives no convergence disposition.
`transport_rejected` is an outbound transport outcome, not an inbound or convergence disposition. Every received
inbound input therefore has exactly one current outcome: a convergence disposition when convergence classifies it,
otherwise an inbound rejection category. A convergence disposition is a live classification, not an immutable
processing-history label. It MAY change when missing state arrives or a later pass selects a different canonical
branch; at every point the input still has only one current disposition.

`delivered` is not a disposition. It names the application-visible output of an `accepted` MLS application message: the
Marmot app payload handed to the application. `dropped` is not a disposition either; where older versions of this
document said an input was dropped, this vocabulary says `stale`.

A disposition says what happened to an input. The categories above say why. A `stale` or `deferred` input SHOULD carry
a category, such as `duplicate` or `stale_epoch`.

## Named convergence outcomes

Protocol-core documents name some outcomes in `PascalCase`. Each maps to one disposition and one category:

| Outcome                 | Disposition | Category          | Defined in                                                  |
| ----------------------- | ----------- | ----------------- | ----------------------------------------------------------- |
| `BeyondAnchor`          | `stale`     | `stale_epoch`     | [retained-history.md](../protocol-core/retained-history.md) |
| `MissingRetainedAnchor` | `deferred`  | `missing_history` | [retained-history.md](../protocol-core/retained-history.md) |

`BeyondAnchor` is window exclusion by design: the source epoch is older than the retained anchor, and the input will
never be processed. `MissingRetainedAnchor` is storage loss: required retained state inside the rollback horizon is
gone, canonical group state does not change, and the group moves to `Unrecoverable` (a group lifecycle state, not a
disposition) until a verified repair path exists; the input stays deferred rather than terminal. A local member's own
removal is instead a canonical-state-derived obligation defined in
[member-departure.md](../protocol-core/member-departure.md) ("Realizing removal"); it is not a disposition assigned to
later input.

## Protocol and local errors

Protocol rejections are part of interop. Local failures are not.

For example, `invalid_encoding` is a protocol rejection. A database write failure is a local implementation failure. A
transport publish failure matters to publish-before-apply, but the exact retry queue or error object is local.

## Privacy

Diagnostics for these outcomes MUST avoid account ids, group ids, message ids, relay URLs, pubkeys, payloads,
ciphertext, plaintext, and key material unless a document defines a safe redaction rule.
