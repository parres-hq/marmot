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

The best pure-decentralized hardening strategy is to add a convergence model to Marmot without introducing a mandatory coordinator.

The proposed shape is:

- activation safety,
- commit discipline,
- drift and fork containment,
- bounded catch-up rules,
- and recovery semantics.

This is a strengthening of Marmot, not a reinvention of it.

## Recommended Additions

### 1. Add a Local Convergence State Machine

Future spec work should define explicit local client states for group activation and recovery. Suggested states:

- `PendingJoin`
- `Active`
- `StateUncertain`
- `Quarantined`

Purpose:

- prevent immediate use of uncertain state,
- make recovery behavior interoperable,
- and stop drifted clients from continuing to emit damaging traffic.

### 2. Separate Welcome Processing From Join Activation

Marmot should stop modeling Welcome processing as equivalent to a fully active join.

Instead:

- processing a Welcome creates candidate group state,
- activation happens only after bounded catch-up and branch checks,
- and clients remain non-sending until activation conditions are met.

This is one of the highest-value changes Marmot can make.

### 3. Bind Welcome To Its Parent Commit Privately

The parent Commit identity should be available to the recipient, but should not be made unnecessarily public.

The current preferred approach is to include the parent Commit event id inside the inner NIP-59 rumor, not on the outer gift-wrap. This gives the recipient the exact transport-level branch anchor while minimizing public metadata leakage.

Recommended private rumor tags:

- `commit`: parent `kind: 445` Commit event id
- `epoch`: post-Commit epoch, optional but recommended

This allows the recipient to:

- fetch the intended parent Commit,
- reason about same-epoch conflicts,
- diagnose stale or losing branches,
- and keep the branch linkage private from relays and observers.

### 4. Require Bounded Catch-Up Before Activation

After processing a Welcome, a client should not immediately begin sending messages or self-updating. Instead, the client should perform bounded catch-up from the configured relay set.

At a minimum, future normative text should require the client to:

- fetch recent group events from all configured relays that are currently reachable,
- process unseen Commits and relevant Proposals,
- and remain pending if the parent Commit cannot be located or branch uncertainty remains.

The catch-up procedure must be bounded so clients do not wait forever.

### 5. Require Freshness Checks Before Structural Commits

The same discipline that applies to join activation should also apply to commit creation.

Before sending any structural Commit, especially member add or remove Commits, the client should:

- perform bounded catch-up,
- avoid sending if local state is uncertain,
- and defer the Commit if known branch conflict exists.

Without this, stale admins or stale devices can keep creating new state from obsolete branches.

### 6. Treat Drift As A First-Class Protocol Condition

State drift should not be treated as a mere debugging concern. It should become an explicit operational condition.

Possible triggers include:

- competing Commits for the same epoch,
- missing or ambiguous Welcome parent Commit,
- ratchet tree invariant failures on join or commit processing,
- evidence of same-epoch divergent state,
- repeated authenticated failures that imply stale local state rather than junk input.

When drift is detected, the client should:

- suspend outbound application messages,
- avoid structural Commits,
- attempt recovery catch-up,
- and quarantine unresolved or losing branches.

### 7. Strengthen Same-Epoch Conflict Handling

Marmot already has a deterministic same-epoch Commit selection rule. That rule is useful, but insufficient by itself.

Future spec work should also define:

- how clients behave while the winning branch is still uncertain,
- what happens to Welcomes produced from the losing branch,
- when local state becomes `StateUncertain`,
- and when re-invitation is required.

### 8. Add Recovery Semantics

The protocol should define what clients do when they cannot safely converge.

This includes:

- missing parent Commit after bounded retry,
- losing Welcome branch,
- invalid ratchet tree state,
- persistent drift after catch-up,
- and repeated invalid artifacts from the same source.

Recovery should fail closed. The right answer is not to weaken MLS validation. The right answer is to quarantine unsafe state and require resync or fresh invitation.

### 9. Add Relay Discipline Guidance

Even in the pure decentralized profile, deployment guidance matters.

Recommended guidance:

- groups SHOULD use a small number of well-connected relays,
- groups SHOULD maximize relay overlap among members,
- groups SHOULD avoid excessive relay sprawl,
- admins SHOULD avoid structural operations when relay visibility is degraded.

This does not solve ordering, but it materially improves convergence in practice.

### 10. Add An Interop-Safe Operational Profile

Even before assisted coordination is standardized, Marmot should document a safer behavior profile for mixed implementations or unreliable environments.

Recommended behaviors:

- serialize or slow down membership-changing operations when possible,
- avoid aggressive self-updates near add/join windows,
- treat join-time and post-join self-updates conservatively,
- prefer fewer concurrent admin actions.

This can begin as guidance and later become a formal deployment profile.

## Why The Welcome Rumor Tag Approach Is Good

The preferred binding design is to place the parent Commit event id inside the Welcome rumor rather than in public outer event metadata.

Why this is attractive:

- it is private to the recipient,
- it does not change the MLS Welcome object,
- it does not require a new private payload format,
- it fits NIP-59 naturally,
- and it gives the recipient a clear branch anchor.

This is a good example of the kind of change Marmot should prefer: operationally useful, privacy-preserving, and additive.

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

### No Perfect Immediate Activation

There is no perfect rule that makes immediate activation after Welcome always safe in a partitioned or delayed network.

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

### Convergence Model

- define local activation and uncertainty states,
- define activation criteria,
- define state transitions.

### Welcome Hardening

- define private parent Commit binding in the rumor,
- define join activation rules,
- define pending and quarantine semantics.

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

- when state is only tentative,
- when clients must catch up,
- when clients must pause,
- and how clients recover from uncertainty or drift.

If Marmot adopts that model, then a pure decentralized profile remains viable, privacy-preserving, and much more production-capable than it is today.
