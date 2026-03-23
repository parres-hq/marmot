# Decentralized Consistency Analysis for Marmot

## Status

`draft` `informational`

This document captures research, design discussion, and recommendations for making Marmot more reliable in production while preserving its decentralized trust model. It is not yet normative protocol text. Its purpose is to record the reasoning behind proposed future changes to the Marmot specification.

## Why This Document Exists

Marmot combines MLS with Nostr relays. This provides strong end-to-end security properties without requiring a trusted central messaging server, but it also means Marmot operates over a weakly ordered and potentially adversarial transport.

During dogfooding and mixed-client testing, Marmot encountered join failures that appear consistent with ratchet tree divergence rather than simple message delivery failure. That made it necessary to analyze whether Marmot is pursuing an impossible architecture, whether centralized ordering is effectively required by MLS, and what changes would make Marmot viable in production without abandoning decentralization.

This document records the conclusions of that analysis.

## Core Conclusion

Marmot is not attempting an impossible thing.

MLS does not require a centralized delivery service for confidentiality or authenticity. However, MLS does require the group to converge on a single epoch history. Centralized deployments usually make this easy by providing strong ordering, global visibility, and commit serialization. Marmot does not get those properties from Nostr relays for free.

The main problem is therefore not that decentralized MLS is impossible. The main problem is that decentralized MLS requires an explicit convergence and coordination model above the cryptographic protocol.

The right way to think about Marmot is:

- MLS provides the cryptographic state machine.
- Nostr provides a decentralized dissemination layer.
- Marmot must define the convergence rules needed to safely operate MLS over that transport.

## Research Findings

### Production MLS Usually Uses Centralized or Strongly Coordinated Delivery

The current industry pattern appears to be that production-grade MLS deployments use centralized or strongly coordinated services for delivery and ordering. This matches both practical deployment experience and the architecture described by the IETF.

This is not because MLS cryptography requires a trusted server. It is because epoch progression is operationally easier when one service can:

- serialize commits,
- reject stale writes,
- ensure broad visibility of a winning commit,
- and reduce branch ambiguity before Welcomes or later Commits are emitted.

### MLS Itself Is Transport-Agnostic

RFC 9420 and RFC 9750 both support the idea that the delivery service is largely untrusted and that MLS can operate over different transport models, including federated or peer-to-peer environments.

What MLS needs is not centralization as such. What it needs is enough delivery and convergence behavior that all members can eventually agree on one Commit chain.

### Decentralized Delivery Is Viable, But Harder

The IETF architecture explicitly acknowledges that eventually consistent or peer-to-peer systems can run MLS. The tradeoff is that they must solve more of the distributed systems problem themselves:

- competing Commits,
- delayed or missing visibility,
- partitioned views,
- replay and suppression,
- and recovery from divergent branches.

Marmot therefore sits in a valid but harder design space.

## The Failure That Motivated This Analysis

Observed user-facing error:

```text
Failed to join group with any matching key package. Last error: non-blank intermediate node must list leaf node in its unmerged_leaves
```

This failure is most consistent with ratchet tree consistency drift rather than simple invitation transport failure.

Interpretation:

- the Welcome was received,
- decryption advanced far enough to parse and validate group state,
- and the join path failed on a strict ratchet tree invariant inside the MLS implementation.

That implies the joiner was not merely missing transport. It implies the Welcome referenced a tree view or branch state that was structurally inconsistent, stale, or produced by a forked implementation state.

## What The Tests Suggest

Deterministic and semi-deterministic tests around invite/join failure suggest several recurring risk factors:

- aggressive self-updates around invite windows,
- concurrent membership-changing commits from different admins,
- stale local state when producing an add Commit and Welcome,
- out-of-order relay ingestion,
- mixed-implementation differences in proposal bundling or commit sequencing,
- and implementation-specific tree-state divergence that later poisons future Welcomes.

The newer [`epoch_authenticator` Welcome-path cases](https://github.com/marmot-protocol/marmot-ts/blob/docs/invite-join-drift-analysis/src/__tests__/epoch-authenticator-drift.test.ts) sharpen one part of this analysis. They support using `epoch_authenticator` as a post-join same-epoch consistency signal: in the honest case it confirms that inviter and joiner derived the same Welcome-epoch state, while in branch-race, wrong-branch, or forged-claim scenarios it helps distinguish successful join from successful join onto suspicious or misbound state.

These scenarios do not suggest that Marmot is impossible. They suggest that Marmot needs stronger coordination rules around activation, commit creation, and recovery.

## Mental Model

The most important mental model change is this:

Nostr relays are a dissemination substrate, not an ordering oracle.

Marmot clients cannot assume that publication to one relay means:

- the group has converged,
- other admins have seen the Commit,
- all members are on the same epoch,
- or that a Welcome derived from that Commit is immediately safe to activate.

Because of this, Marmot should distinguish between:

- cryptographic validity,
- branch viability,
- and activation safety.

A Welcome or Commit may be cryptographically valid and still unsafe to activate if the surrounding observed branch state is uncertain.

## Design Goal

The goal is not perfect coordination. In a decentralized asynchronous environment, that is not achievable.

The goal is instead:

- safe eventual convergence,
- early containment of drift,
- reduction of state-poisoning behavior,
- clear recovery paths,
- and minimal additional public metadata.

## Recommended Direction

The best pure-decentralized hardening strategy is to make Marmot's operational convergence guidance more explicit without introducing a mandatory coordinator.

The proposed shape is:

- stronger Commit discipline,
- clearer post-join and post-offline send hygiene,
- drift and fork containment,
- same-epoch conflict handling,
- and recovery semantics.

This is a strengthening of Marmot, not a reinvention of it.

## Recommended Additions

### 1. Clarify Post-Join Send Hygiene

From the recipient's point of view, a Welcome is the start of group membership. The new member does not have meaningful access to earlier encrypted group history and cannot use older ciphertexts to reconstruct prior state.

The real risk begins immediately after successful Welcome processing: newer Commits may already exist on reachable relays, and a freshly joined member can fork itself out of the group if it sends a self-update or application traffic from stale visible state.

Future Marmot text should therefore say clearly that after processing a Welcome, clients SHOULD make a bounded best-effort attempt to process newer visible group state before sending their first self-update or other outbound traffic.

This should also be paired with an explicit distinction between:

- MLS validation of the Welcome-derived state itself,
- confirmation that the joined epoch matches the inviter's intended branch,
- and bounded catch-up for newer visible Commits.

That distinction matters because a newly added member cannot meaningfully validate pre-join encrypted history. What the new member can validate is the joined epoch and whether it still appears safe to act from.

### 2. Require Freshness Checks Before Structural Commits

The same discipline that applies after joining or resuming from stale state should also apply to commit creation.

Before sending any structural Commit, especially member add or remove Commits, the client should:

- perform bounded catch-up,
- avoid sending if local state is uncertain,
- and defer the Commit if known branch conflict exists.

Without this, stale admins or stale devices can keep creating new state from obsolete branches.

### 3. Treat Drift As A First-Class Operational Condition

State drift should not be treated as a mere debugging concern. It should become an explicit operational condition.

Possible triggers include:

- competing Commits for the same epoch,
- ratchet tree invariant failures on join or commit processing,
- evidence of same-epoch divergent state,
- repeated authenticated failures that imply stale local state rather than junk input.

When drift is detected, the client should:

- suspend outbound application messages,
- avoid structural Commits,
- attempt recovery catch-up,
- and quarantine unresolved or losing branches.

This can be specified as required behavior under uncertainty without standardizing a full client lifecycle state machine.

### 4. Use RFC-Aligned Consistency Signals

The MLS RFCs already provide two useful consistency signals that Marmot can build on without changing core MLS behavior:

- `tree_hash`, which is already part of `GroupContext` and is carried inside the `GroupInfo` encrypted in the MLS `Welcome`,
- `epoch_authenticator`, which RFC 9420 describes as a per-epoch value for confirming that two clients have the same view of the group.

This distinction is important for avoiding redundant event data.

#### `epoch_authenticator` Is The Best Additional Signal

Unlike `tree_hash`, `epoch_authenticator` is not already carried in the Welcome path. It is therefore the most useful low-overhead value to add if Marmot wants a stronger branch-consistency check in mixed-client or adversarial delivery environments.

This is also a natural extension of how MLS implementations already treat the value in practice: as a compact equality check that two parties derived the same epoch state. The Marmot-specific proposal is not to give `epoch_authenticator` a different meaning, but to carry that same signal across the Welcome boundary so the joiner can compare the inviter's claim against locally derived state after successful Welcome processing.

The right use is narrow and specific:

- the inviter includes the welcome epoch's `epoch_authenticator` in encrypted Welcome-associated metadata,
- the joiner derives its own `epoch_authenticator` after successful Welcome processing,
- the joiner compares the two,
- a mismatch is treated as evidence of drift, fork, or implementation inconsistency.

This does not prove that no newer Commit exists elsewhere. It does prove something narrower and still valuable: the joiner and inviter agree on the cryptographic state of the welcome epoch.

#### Normative Direction

For Marmot, these checks should not remain soft diagnostics in mixed-client ecosystems.

The honest-path result is important but limited: when the Welcome is valid and the inviter is honest, `epoch_authenticator` is mostly confirmatory. Its real value appears in the non-ideal cases that decentralized delivery makes plausible, especially raced branches, mixed implementations, buggy state production, or adversarially wrong metadata.

The intended direction is:

- MLS tree validation remains mandatory through normal Welcome processing,
- clients MUST fail closed on ratchet-tree or related MLS validation failures,
- Marmot SHOULD add encrypted `epoch_authenticator` confirmation for the Welcome epoch,
- clients that support this confirmation SHOULD compare it before first outbound traffic,
- clients MUST quarantine state on mismatch and MUST NOT send application traffic or structural Commits from that state.

Failure to enforce these checks materially increases the risk of silent drift and persistent forks in mixed-client environments.

### 5. Strengthen Same-Epoch Conflict Handling

Marmot already has a deterministic same-epoch Commit selection rule. That rule is useful, but insufficient by itself.

Future spec work should also define:

- how clients behave while the winning branch is still uncertain,
- what happens to Welcomes produced from the losing branch,
- when local state becomes uncertain,
- and when re-invitation is required.

### 6. Add Recovery Semantics

The protocol should define what clients do when they cannot safely converge.

This includes:

- losing Welcome-producing branch,
- invalid ratchet tree state,
- persistent drift after catch-up,
- and repeated invalid artifacts from the same source.

Recovery should fail closed. The right answer is not to weaken MLS validation. The right answer is to quarantine unsafe state and require resync or fresh invitation.

### 7. Add Relay Discipline Guidance

Even in the pure decentralized profile, deployment guidance matters.

Recommended guidance:

- groups SHOULD use a small number of well-connected relays,
- groups SHOULD maximize relay overlap among members,
- groups SHOULD avoid excessive relay sprawl,
- admins SHOULD avoid structural operations when relay visibility is degraded.

This does not solve ordering, but it materially improves convergence in practice.

### 8. Add An Interop-Safe Operational Profile

Even before assisted coordination is standardized, Marmot should document a safer behavior profile for mixed implementations or unreliable environments.

Recommended behaviors:

- serialize or slow down membership-changing operations when possible,
- avoid aggressive self-updates near add/join windows,
- treat post-join and post-offline self-updates conservatively,
- prefer fewer concurrent admin actions.

This can begin as guidance and later become a formal deployment profile.

## What Should Probably Not Be Added Yet

The following ideas may become useful later, but they are probably too heavy for the first hardening round of the pure decentralized profile:

- mandatory relay quorum thresholds for commit publication,
- mandatory fixed quiet periods between Commits,
- public graph references that increase metadata leakage,
- coordinator or ordering-assistant roles,
- commit locks or leases,
- fork-witness or relay-attestation mechanisms.

Those are future options, not good first moves.

## Problems That Are Not Fully Solvable In The Pure Decentralized Profile

Some limitations are fundamental to asynchronous decentralized systems and should be acknowledged directly.

### No Global Certainty

Clients cannot know with certainty that no competing Commit exists somewhere on an unseen relay.

### No Perfect Global Visibility

Neither a newly joined member nor an existing member returning from an offline period can know with certainty that no unseen competing Commit exists somewhere beyond their current relay view.

### No Complete Prevention Of Stale Writers

Clients can be required to catch up, but they cannot guarantee that their relay view is globally complete.

### No Total Protection From Buggy Implementations

Mixed-client divergence cannot be completely prevented by transport rules. It must also be addressed by interop testing, tighter normative behavior, and strict quarantine of bad state.

These limitations do not make Marmot impossible. They simply define the boundary between what Marmot can guarantee and what it can only mitigate.

## Relationship To Centralization

This analysis does not conclude that Marmot should centralize. It concludes that decentralized messaging needs more explicit local coordination behavior.

At the same time, this work also makes clear where optional helper services would eventually make sense:

- fast and safe onboarding,
- large groups,
- many concurrent admins,
- mobile-first clients,
- and predictable delivery under poor relay conditions.

Such helper services can remain optional and untrusted for content while still improving consistency. That is a possible future direction, but not required for the pure decentralized profile.

## Recommended Future Spec Work

The next stage of protocol work should likely be organized around the following topics:

### Post-Join And Resume Hygiene

- define what newly joined members should do before first outbound traffic,
- define what returning members should do before creating new Commits,
- define conservative guidance for post-join self-updates.

### Welcome Handling

- clarify that Welcome processing initializes membership for the Welcome epoch,
- define failure handling for invalid or losing Welcome-derived state,
- define optional diagnostic metadata only if it provides clear value,
- avoid duplicating `tree_hash` outside standard MLS `GroupInfo`,
- define whether encrypted Welcome-associated `epoch_authenticator` confirmation becomes required for interoperable mixed-client safety.

### Commit Discipline

- define pre-Commit bounded catch-up,
- define stale-state deferral,
- define structural Commit restrictions under uncertainty.

### Drift Containment

- define drift triggers,
- define send suspension behavior,
- define losing-branch handling.

### Recovery

- define retry, quarantine, re-invite, and fail-closed behavior.

### Deployment Guidance

- define relay selection and overlap recommendations,
- define degraded-mode behavior,
- define safer interop guidance.

## Summary

The main insight of this analysis is simple:

Marmot is decentralized in trust, but it cannot be coordination-free.

That does not weaken Marmot. It clarifies what is required to make it real.

The strongest path forward is not to weaken MLS validation or add unnecessary public metadata. It is to make Marmot more explicit about:

- when clients must reconcile visible newer state before sending,
- when clients must defer Commits,
- which consistency signals are already provided by MLS and which are worth adding,
- when clients must pause under uncertainty,
- and how clients recover from drift or losing branches.

If Marmot adopts that model, then a pure decentralized profile remains viable, privacy-preserving, and much more production-capable than it is today.
