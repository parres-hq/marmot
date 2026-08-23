# Multi-device

Status: experimental draft. Non-normative.

Requirement keywords in this document constrain the proposed design only. Nothing here is adopted, and no wire bytes,
component ids, extension types, event kinds, or capability identifiers in this document are assigned. The document
records the agreed working baseline from the MDK multi-device exploration so the team can review it in this spec's
format. Component documents will be added under [../app-components/](../app-components/) once the baseline settles.

This document replaces a withdrawn branch-draft that joined a device through an External Commit, an administrator
join-authorization proof, and a group-derived join PSK. That design is obsolete; see
[Migration from the withdrawn draft](#migration-from-the-withdrawn-draft).

Multi-device support lets one Marmot account participate in a group from more than one MLS leaf. Marmot account
identity remains the Nostr public key. Each physical device is an independent MLS client bound to that account
identity, with its own leaf, leaf secret, and local state in every enrolled group.

"Multi-device" is really several separate problems:

1. authorizing a new device and adding it to existing MLS groups;
2. deciding which device KeyPackage another account uses when first inviting the account;
3. synchronizing accepted message history and private application state;
4. removing or recovering devices and the authority they held.

These problems can share one user-facing workflow without sharing one protocol mechanism. Problem 3 is separated into
the exploratory [account-sync](./account-sync.md) document and is not required for multi-device v1 interoperability.

## Surfaces

- Foundation identity and credentials; the required
  [`marmot.member.account-identity-proof.v2`](../app-components/account-identity-proof-v2.md) LeafNode component.
- Protocol-core commit authorization ([../protocol-core/group-messaging.md](../protocol-core/group-messaging.md)) and
  convergence ([../protocol-core/convergence.md](../protocol-core/convergence.md)). This feature proposes a new
  authorized Commit shape for existing members and does not change convergence itself.
- New group-level capabilities for same-account admission and removal (names and negotiation mechanics below; ids and
  bytes unassigned).
- A short-lived pairing session between two devices of one account, carried over an authenticated encrypted channel.
  The pairing channel is application-scoped and assigns no transport event kinds.
- Content synchronization: out of scope here; see [account-sync](./account-sync.md).

## Same-account admission

A new device joins a group through an ordinary inline-`Add` Commit authored by an existing leaf of the same account.
No External Commit, join PSK, externally provisioned GroupInfo, or administrator signature is involved.

The proposed authorization rule:

> A current member who is not an administrator MAY commit an Add-only membership change when the negotiated
> same-account capability is enabled and required in the GroupContext, every added KeyPackage carries a valid
> `marmot.member.account-identity-proof.v2`, every added credential identity exactly equals the committer's
> MLS-authenticated account identity, and all limits below pass.

Proposed constraints:

- A separately assigned and negotiated capability gates the behavior. Every current member advertises support, and the
  GroupContext explicitly enables and requires it. Creating a group may enable it only when all initial members
  support it; enabling it in an existing group uses the ordinary administrator-authorized capability-upgrade flow.
- The Commit contains one to four inline `Add` proposals and nothing else: no referenced proposals and no other
  proposal types. Its normal MLS UpdatePath is required and permitted. Standalone `Add` proposals remain
  administrator-only.
- The resulting group MAY contain at most five current leaves for one account, including the sponsoring leaf. The
  limit is evaluated against canonical resulting state, so concurrent sibling Adds that individually fit but jointly
  exceed it resolve through ordinary convergence: the winning epoch stands and the losing joiner rejects at Welcome
  validation.
- The KeyPackages and leaf signature keys added by one Commit MUST be distinct and MUST NOT duplicate a current leaf.
- A valid same-account Add has ordinary rather than administrator-privileged convergence priority.

The one-to-four bound keeps a single same-account Commit small and bounds how many leaves one compromised device can
mint per Commit; four additions plus the sponsoring leaf exactly fill the five-leaf per-account limit. An
account-identity proof establishes account-key authorization of a leaf signature key, not a human identity. The
authorization chain is: a current member's MLS-authenticated control of its leaf, plus the new leaf's account-key
proof, plus exact equality of their account identities, plus the committer's signature over the Commit.

Security consequences: possession of the Nostr account key alone is not sufficient to add a device; the sponsor must
also control a current MLS leaf. Conversely, compromise of a current device allows minting persistent same-account
leaves, which is why removal authority (below) is part of the same baseline.

## Welcome validation

The joining device recognizes two distinct authorization paths: the existing administrator invitation path and the
negotiated same-account path. For the same-account path it requires:

- the exact KeyPackage created for the active pairing session;
- the expected MLS group id and sponsor account from the authenticated pairing manifest;
- the same-account capability enabled and required in the joined GroupContext;
- a current, non-blank GroupInfo signer whose validated account identity equals the joining leaf's identity;
- valid account-identity proofs on the sponsor and joining leaves; and
- no more than five resulting leaves for that account.

The receiver records which authorization path succeeded and does not silently fall back from a failed same-account
check unless the GroupInfo signer independently qualifies as an active administrator. A Welcome receiver cannot
reconstruct the candidate parent and revalidate the inline-Add-only Commit shape; existing members validate that
candidate-parent rule, while the joining device validates the authenticated pairing intent and resulting group state.

## Pairing and enrollment

Adding a leaf remains a per-group MLS operation; there is no protocol shortcut that places a device in every group at
once. A short-lived pairing session coordinates the work so it feels like one bounded operation.

### Pairing session

1. The user signs in to the same Nostr account on the new device.
2. The new device starts a short-lived, single-use pairing session and displays a QR descriptor containing a version,
   random session id, ephemeral X25519 public key, account public key, expiry, rendezvous hints, and an account
   signature. It contains no group graph, KeyPackages, or MLS secrets.
3. The QR lifetime defaults to two minutes and MUST NOT exceed five minutes. An expired descriptor is replaced rather
   than extended.
4. The scanning device verifies the descriptor against its own account, asks for explicit approval, contributes a
   signed ephemeral key, and derives a transcript-bound encrypted channel. A separate visual short-authentication
   string is not required for the first version.
5. The existing device sends an encrypted eligibility catalog; the user selects active, non-archived groups by default,
   all groups, or a custom subset.
6. The new device creates one fresh, group-bound KeyPackage per selected group.
7. The existing device creates and publishes the per-group inline-`Add` Commits and delivers each `Welcome`
   redundantly over the shared transport.
8. The new device processes only Welcomes expected by the pairing manifest.
9. Optional content bootstrap may follow per group; see [account-sync](./account-sync.md).

Pairing channel keys MAY remain memory-only. Durable progress survives restart, but continuing unfinished work
requires a newly authenticated pairing session that first reconciles already-completed membership.

### Enrollment lifecycle

Enrollment is durable per-group work, not one cross-group transaction. For each selected group the enroller records
intent, stages and publishes the Commit under publish-before-apply, delivers the Welcome, validates the join, and
records an authenticated acknowledgement.

Progress distinguishes pending, Commit published, Welcome delivered, joined, retryable failure, terminal failure, and
skipped. The authenticated acknowledgement is signed by the joining device's post-join leaf signing key — the only key
that proves both identity and completed MLS admission — and binds the joined group id, epoch, staged KeyPackage
reference, and pairing session id. It travels over the shared transport rather than the pairing channel.

Retry rules:

- A lost acknowledgement retries the same Welcome rather than issuing another Add. Retrying the same Welcome remains
  valid only while the joining device still holds the staged KeyPackage secret; if that staging is lost, the item
  terminates as a terminal failure reconciled by a fresh pairing session.
- A Commit that loses convergence restarts from canonical state with a fresh KeyPackage.
- A failed attempt consumes or retires that group's KeyPackage; paired enrollment never falls back to public relay
  discovery.

Automatic Welcome acceptance is restricted to the active pairing manifest: expected group, expected KeyPackage
reference, expected same-account sponsor, unexpired session, compatible feature set.

## Same-account removal

- A separately negotiated same-account-remove capability permits a non-administrator to commit one to four inline
  `Remove` proposals targeting current sibling leaves whose credential identity equals the committer's account
  identity.
- The committer cannot target its own leaf; SelfRemove remains the self-departure path. The Commit carries no other
  proposal types and the normal UpdatePath, and has ordinary convergence priority.
- Every current leaf has reciprocal authority to remove its own siblings. This deliberately accepts that compromise of
  one current device can cause denial of service by removing other devices.
- The operation is scoped to one group. There is no first-version cross-group tombstone, atomic remove-everywhere
  operation, or claim of global completion. Any bulk-removal UX is a best-effort orchestrator over independently
  evidenced per-group results.
- Pairing MAY maintain a private device identifier and per-group leaf mapping for local presentation. That mapping is
  not protocol authority and never appears in public KeyPackages or MLS credentials.

## Initial invitation

When an account is not yet represented in a group, an administrator admits exactly one initial leaf:

- select exactly one valid, compatible KeyPackage using the existing deterministic candidate-ranking rules;
- after admission, that account uses the same-account Add path to enroll siblings.

Public KeyPackage publication-slot tags remain opaque and are not physical device identifiers; discovery never fans
out across every apparently valid KeyPackage. Inviting every discovered slot can duplicate leaves for one device,
admit lost devices, inflate group size, and produce inconsistent results from incomplete relay views.

Ambiguous Welcome delivery retries the same Welcome; it does not trigger an automatic Add for another KeyPackage.
Replacing an unreachable initial leaf requires an explicit administrator removal followed by a fresh invitation.

## Optional history bootstrap

Content bootstrap is optional and separate from enrollment. If implemented, it transfers accepted, locally retained
application history directly over the authenticated pairing channel, beginning only after that group's join has
validated. Boundaries, record format direction, and trust limitations are owned by
[account-sync](./account-sync.md). Implementations MAY omit it without blocking enrollment or future messaging.

## Out of scope

- Continuous background synchronization, journals, checkpoints, and CRDT-style merges (see
  [account-sync](./account-sync.md)).
- Copying any local database, MLS-library state, epoch secrets, sender ratchets, KeyPackage private keys, or pending
  operations between devices.
- Cross-group atomic device removal or identity tombstones.
- Deriving device identity from public KeyPackage publication-slot tags.
- MLS Virtual Clients (one virtual leaf per account emulated by device peers): tracked as an alternative model, not a
  baseline. It hides device count from groups but shares one virtual secret across emulators and expects stronger
  delivery-service serialization than Marmot transports provide.

## Open questions

Carried from the design review; these must be settled before any component or capability document is written:

- Should the add and remove capabilities be negotiated as a pair — or collapsed into one capability — so no group can
  enable same-account admission without reciprocal sibling removal?
- Exact mechanics of enabling a required capability in an existing group: must every current member consent through
  its own Update, or are non-supporting members removed? The upgrade flow must not silently change membership.
- Handling of orphaned same-account leaves when no surviving sibling shares their group; whether administrator-side
  discovery suffices or some private device-directory visibility is needed in v1.
- Recovery when lost or unreachable devices exhaust the per-account leaf budget; whether documented administrator
  cleanup is acceptable for v1.
- Exact signed inputs of the account-identity proof binding (does it commit to the KeyPackage hash?) and validation
  behavior across account-key rotation.
- Pairing-batch size bound and maximum concurrently in-flight group Commits per session.
- What the pairing approval dialog must display to avoid confused-deputy approval of an entire batch.

## Migration from the withdrawn draft

The withdrawn branch-draft used an External Commit with `ExternalInit`, a group-derived join PSK, externally supplied
GroupInfo, an administrator-signed join-authorization proof (component id `0x800a`, kind `452`), and the
`marmot.multi-device.v1` (`0xf2f0`) signaling gate. None of that was ever normative. Those ids are retired in
[../foundation/registries.md](../foundation/registries.md) and MUST NOT be reused. Implementations of the old draft
MUST reject it and MUST NOT emit it.

The pairing payload of the withdrawn draft also transferred the Nostr outer-encryption group event key; the baseline
here transfers no live group keys of any kind.
