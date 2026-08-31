# Consensual history purge

Status: adopted.

Consensual history purge is a narrow, one-shot flow for changing a group's prospective disappearing-message duration while asking every active member to remove application plaintext from before the change. It is not remote wipe, moderation, sender retraction, or an arbitrary-range deletion protocol.

## Surfaces

- [`marmot.group.history-purge.v1`](../app-components/history-purge-v1.md) owns the request bytes, member decision proof, control app event, committed authorization, negotiation, and validation.
- [`marmot.group.message-retention.v1`](../app-components/message-retention-v1.md) owns the replacement prospective retention state.
- [Retained history](../protocol-core/retained-history.md) owns the boundary between application plaintext and protocol recovery material.
- [Durability](../protocol-core/durability.md) owns restart-safe application effects.

## Starting one request

An active administrator MAY start one request for the group's current canonical parent state. The request fixes the proposed retention duration and the complete sorted set of active member account identities. It is valid only while that exact parent remains canonical, so V1 has no independent distributed request state and no custom expiry clock.

The administrator MUST NOT emit the request unless every active leaf advertises V1 support. The UI MUST show the proposed duration, that all pre-activation application plaintext is in scope, the active account identities that must decide, that any No or the next unrelated Commit ends the request without deletion, and the external-copy limits below. V1 has no custom prompt text.

A client presents exactly two explicit, accessible actions: Yes and No. Dismissal, timeout, silence, leaving the screen, and a preselected control are not consent. Each account produces at most one signed answer for the exact request. A No ends the request for conforming participants because that account cannot also provide the Yes proof required by finalization.

Only one request per group SHOULD be presented at a time. A second request does not cancel or supersede the first; each remains independently bound to its parent, and at most one can be finalized because ordinary convergence selects only one canonical child.

## Unanimous finalization

No deletion occurs when the request or an individual response is received. An active administrator may construct the authorizing Commit only after collecting one valid Yes proof from every account in the fixed snapshot.

The Commit atomically carries the canonical unanimous authorization and activates the exact requested retention value. It must be the direct child of the request's parent and may not mix membership, admin, capability, or unrelated component changes. The resulting epoch is the activation epoch.

Any No prevents a conforming unanimous authorization. Any other canonical child Commit expires the request without deletion. A join, removal, leave, member-identity replacement, capability change, admin-policy change, or different retention change necessarily changes the bound parent or violates the allowed Commit shape, so a fresh request is required. Transport order, receipt order, and local clocks are not authority.

## Local application

While the authorizing Commit is on the selected branch, a client MUST suppress from application surfaces every delivered Marmot app payload whose MLS source epoch is less than the activation epoch. Suppression covers conversation history, search, notifications, exports created by the application, reply previews, text-to-speech, thumbnails, and application-controlled plaintext media caches. If convergence supersedes that Commit while its parent is still inside the rollback horizon, the client withdraws the suppression with the Commit's other application effects; it cannot already have destroyed the plaintext.

The client begins idempotent local best-effort deletion only after convergence is settled, the selected branch still contains the authorizing Commit, and the request's parent epoch is outside the current tip's rollback horizon. This irreversible-effect gate is part of the purge contract, not an implementation delay: no still-eligible branch can then supersede the authorization. The client keys deletion by `request_id` and activation epoch, durably records or reconstructs the suppression boundary before exposing the post-activation view, and resumes unfinished cleanup after restart. Reprocessing the same Commit cannot duplicate the effect. A late or replayed target payload is suppressed before any application surface can render or emit it.

An offline conforming client validates and applies the canonical authorization before rendering newly recovered target history. A member that was offline while votes were collected is never assumed to agree; without its Yes proof the authorizing Commit is invalid.

Clients MAY report only local states such as "approved" and "removed on this device". V1 defines no cleanup receipt, group-wide completion claim, per-member application tracking, partial-completion state, message count, deleted-content hash, filename list, device inventory, or precise cleanup timestamp.

## Preserved data and limits

The purge does not change the prospective invariant in [`marmot.group.message-retention.v1`](../app-components/message-retention-v1.md): without a valid unanimous authorization, a later retention update never shortens, extends, or restores an earlier message's expiry.

The local effect removes application plaintext only. It MUST NOT remove MLS group state, commits, proposals, retained anchors, candidate-parent material, pending publication obligations, replay markers, encrypted transport objects needed for protocol operation, or audit/security records required for correctness before their owning protocol release rules permit it.

The effect is best effort, not secure erasure. Marmot cannot force deletion from former members, hostile or non-conforming clients, relays, recipients outside the fixed cohort, screenshots, independent exports, device or cloud backups, filesystem snapshots, or copies held by another application. Storage encryption and physical overwrite are platform concerns. A client MUST NOT describe the action as removing every copy or as group-wide completion.

## Scope exclusions

V1 authorizes exactly the pre-activation application-plaintext range for one retention activation. It does not authorize a custom range, selected messages, sender retraction, admin moderation, delete-for-me, group disbanding, cleanup receipts, or a continuing retention policy. Those require separate designs and cannot reinterpret this component.
