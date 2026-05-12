# Results and rejections

Status: sketch.

Marmot clients should be able to describe why an input did not produce application content.

This file names shared categories. It does not require local APIs to use these exact enum names.

## Input categories

An input that does not produce application content should map to one of these categories:

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

State-machine docs can split these into more detailed outcomes when needed.

## Protocol and local errors

Protocol rejections are part of interop. Local failures are not.

For example, `invalid_encoding` is a protocol rejection. A database write failure is a local implementation failure. A
transport publish failure matters to publish-before-apply, but the exact retry queue or error object is local.

## Privacy

Diagnostics for these outcomes must avoid account ids, group ids, message ids, relay URLs, pubkeys, payloads,
ciphertext, plaintext, and key material unless a document defines a safe redaction rule.
