# Results and rejections

Status: draft for internal review.

Marmot clients SHOULD be able to describe why an input did not produce application content.

This file names shared categories. It does not require local APIs to use these exact enum names.

## Input categories

An input that does not produce application content SHOULD map to one of these categories:

- `duplicate`: the same protocol input was already seen.
- `own_echo`: the input is the client's own already-accounted-for output.
- `wrong_recipient`: the input targets another account, device, group, or routing id.
- `unknown_group`: the client has no group state that can process the input.
- `already_applied`: the input is represented by the current canonical state.
- `stale_epoch`: the input is from an epoch the client will not process.
- `invalid_encoding`: bytes failed the owning document's parser or length rules.
- `invalid_signature`: a required MLS, Nostr, or component signature check failed.
- `unsupported_required_feature`: the group requires a feature the client does not understand.
- `authorization_failed`: the sender or committer is not allowed to make the change.
- `missing_history`: the client would need retained state it no longer has.
- `transport_rejected`: publication or delivery failed at the transport layer.

Protocol-core docs can split these into more detailed outcomes when needed.

## Dispositions

Inbound protocol input receives exactly one of four dispositions; the processing flow that assigns them is
[../protocol-core/inbound-processing.md](../protocol-core/inbound-processing.md):

- `accepted`: the input is part of, or was consumed by, the selected canonical branch.
- `deferred`: the input cannot be processed yet and is retried when missing state arrives or convergence advances.
- `stale`: the input can no longer affect the group.
- `invalidated`: the input's MLS application message decrypts only on a losing branch, so its app payload is withdrawn
  from application output.

`delivered` is not a disposition. It names the application-visible output of an `accepted` MLS application message: the
Marmot app payload handed to the application. `dropped` is not a disposition either; where older drafts said an input
was dropped, this vocabulary says `stale`.

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
disposition) until a verified repair path exists; the input stays deferred rather than terminal.

## Protocol and local errors

Protocol rejections are part of interop. Local failures are not.

For example, `invalid_encoding` is a protocol rejection. A database write failure is a local implementation failure. A
transport publish failure matters to publish-before-apply, but the exact retry queue or error object is local.

## Privacy

Diagnostics for these outcomes MUST avoid account ids, group ids, message ids, relay URLs, pubkeys, payloads,
ciphertext, plaintext, and key material unless a document defines a safe redaction rule.
