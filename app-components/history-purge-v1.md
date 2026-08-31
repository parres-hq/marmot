# marmot.group.history-purge.v1

Status: adopted.

`marmot.group.history-purge.v1` carries one unanimous, commit-scoped authorization to remove application plaintext from before a new retention policy takes effect. It does not create persistent group state.

## Registry

- Component id: `0x800d`
- Name: `marmot.group.history-purge.v1`
- Purge control app-event kind: `453`
- Member decision proof kind: `454`
- Valid carrier: one inline MLS `AppEphemeral` proposal in the authorizing Commit
- Default requirement: optional

The component is invalid as component data in a GroupContext, LeafNode, KeyPackage, or GroupInfo and is invalid as a SafeAAD item.

## Request bytes

The request binds the complete candidate parent state, the replacement retention duration, and the active account identities that must decide:

```text
struct {
  opaque account_pubkey[32];
} MarmotHistoryPurgeMemberV1;

struct {
  opaque group_id<1..255>;
  uint64 parent_epoch;
  opaque parent_group_context_hash[32];
  uint64 target_retention_secs;
  MarmotHistoryPurgeMemberV1 members<32..32768>;
} MarmotHistoryPurgeRequestV1;
```

These structures use the Marmot binary profile in [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md). `members` contains between one and 1024 entries, sorted by `account_pubkey` bytes with no duplicate. It MUST equal the sorted unique set of 32-byte Marmot account identities in all nonblank leaves of the candidate parent state.

`group_id`, `parent_epoch`, and `parent_group_context_hash` MUST equal the candidate parent's MLS GroupContext, where:

```text
parent_group_context_hash = SHA-256(TLS-serialize(candidate_parent_group_context))
```

The TLS serialization is owned by MLS and is not re-encoded with the Marmot binary profile. Its tree hash and confirmed transcript hash bind the request to the exact parent state, including the active leaves and prior commits. `target_retention_secs` MUST differ from the retention value in that parent. An absent `marmot.group.message-retention.v1` component is read as zero for this comparison.

The request identity is:

```text
request_id = SHA-256(
  "marmot-history-purge-request-v1" ||
  0x00 ||
  encode(MarmotHistoryPurgeRequestV1)
)
```

The domain string is 31 ASCII bytes. The encoded request supplies an unambiguous boundary for every variable field.

## Member decision proof

Each account in `request.members` makes exactly one explicit Yes or No decision by producing a `MarmotAuthorizationProof` from [../foundation/authorization-proofs.md](../foundation/authorization-proofs.md). Construct this exact local-only Nostr event:

```text
pubkey     = lowercase-hex(proof.signer_pubkey)
created_at = proof.created_at
kind       = 454
tags       = [
  ["d", "marmot-history-purge-decision-v1"],
  ["component", "0x800d"],
  ["group_id", group_id_hex],
  ["parent_epoch", parent_epoch_decimal],
  ["request", request_id_hex],
  ["decision", decision]
]
content    = "Approve deletion of pre-activation application plaintext"
             when decision is "yes", otherwise
             "Reject deletion of pre-activation application plaintext"
```

`group_id_hex` and `request_id_hex` are lowercase hexadecimal with no prefix. `parent_epoch_decimal` is canonical unsigned decimal ASCII with no leading zero except that zero itself is `"0"`. `decision` is exactly `"yes"` or `"no"`. The tags appear exactly once and in the order shown, and the event has no other tags. This signing event is not a transport event and MUST NOT be published to relays.

The producer MUST set `proof.created_at` to its local current Unix time when requesting the signature. Receivers do not compare it with their local wall clock. The proof signer MUST be one of `request.members`. A conforming account MUST produce at most one decision for a `request_id`; a No therefore makes a unanimous authorization impossible. Silence, dismissal, timeout, and an invalid proof are not Yes.

## Purge control app events

Requests and responses use kind `453` Marmot app events carried as ordinary MLS application messages. Their shared envelope follows [../foundation/application-messages.md](../foundation/application-messages.md).

A request event has exactly these tags:

```text
[
  ["v", "marmot-history-purge-v1"],
  ["type", "request"],
  ["request", request_id_hex]
]
```

Its `content` is standard padded base64 of the exact `MarmotHistoryPurgeRequestV1` bytes. The MLS-authenticated sender MUST be an active administrator in the bound parent state. A recipient ignores the request unless the bytes decode exactly, reproduce the tagged `request_id`, match its current canonical state, and pass the negotiation rules below.

A response event has exactly these tags:

```text
[
  ["v", "marmot-history-purge-v1"],
  ["type", "response"],
  ["request", request_id_hex],
  ["decision", decision]
]
```

Its `content` is standard padded base64 of exactly one 104-byte `MarmotAuthorizationProof`. The MLS-authenticated sender account MUST equal `proof.signer_pubkey`, the proof MUST reconstruct the tagged decision for the exact request, and the signer MUST occur in `request.members`. Invalid control events are ignored as feature data; they do not invalidate the carrying MLS application message or alter group state.

## AppEphemeral authorization bytes

The inline `AppEphemeral` proposal uses component id `0x800d` and this data:

```text
struct {
  MarmotHistoryPurgeRequestV1 request;
  MarmotAuthorizationProof approvals<104..106496>;
} MarmotHistoryPurgeAuthorizationV1;
```

`approvals` contains exactly one 104-byte Yes proof for every identity in `request.members`, sorted by `proof.signer_pubkey` bytes. Missing, duplicate, extra, out-of-order, invalid, or No proofs invalidate the authorization.

## Negotiation

Before emitting a request, every nonblank leaf in the bound parent state MUST advertise proposal type `app_ephemeral` (`0x0009`) and component id `0x800d`. The GroupContext MUST permit `app_ephemeral` under MLS RequiredCapabilities. A leaf that does not advertise both values blocks the feature; it is never treated as consenting.

The component id need not be in the GroupContext required-component list because the authorization is one-shot and commit-scoped. A client MUST NOT add a persistent `0x800d` dictionary entry.

## Commit authorization and validation

Only an active administrator in the candidate parent state MAY commit the purge authorization. The authorizing Commit MUST:

- apply directly to the request's exact candidate parent;
- have a complete proposal set consisting of exactly one inline `0x800d` `AppEphemeral` proposal carrying this
  authorization and exactly one `marmot.group.message-retention.v1` full-replacement `AppDataUpdate` whose value equals
  `request.target_retention_secs`;
- reject every other proposal or component mutation, including a standalone or second `0x800d` proposal, an
  `AppEphemeral` proposal for any other component id, any other `AppDataUpdate`, and any MLS proposal type other than
  the two allowed proposals, whether inline or referenced; and
- satisfy every request, negotiation, approval, ordinary MLS, and candidate-parent authorization rule above.

The retention `AppDataUpdate` MAY be inline or a valid referenced proposal. Resolving that reference does not widen the
allowed set. The Commit's required UpdatePath, confirmation tag, and other mandatory MLS framing are not proposals and
remain governed by the ordinary MLS validation rule; they do not permit another proposal or app-component mutation.

The Commit that satisfies these rules is the request's only valid finalization. Its resulting epoch is the activation epoch. Any other canonical child of the bound parent expires the request without purge, including a membership, capability, admin-policy, or retention change. Local wall clocks and transport arrival order do not decide validity.

The authorization is invalid for any other group, parent state, epoch, member set, target retention value, or Commit shape. Replay of the same Commit follows ordinary Marmot duplicate handling and MUST NOT create a second deletion effect.

## Effect boundary

While the authorizing Commit is selected, each conforming client applies the reversible suppression effect defined by
[../features/consensual-history-purge.md](../features/consensual-history-purge.md) and
[../protocol-core/retained-history.md](../protocol-core/retained-history.md). The target is delivered application
plaintext whose MLS source epoch is less than the activation epoch. If convergence supersedes the authorizing Commit
while its parent remains inside the rollback horizon, the client withdraws that suppression with the Commit's other
application effects and MUST NOT have destructively deleted the target.

Local best-effort deletion becomes eligible only after convergence is settled, the selected branch still contains the
authorizing Commit, and the request's parent epoch is outside the current tip's rollback horizon. At that point no
eligible branch can supersede the authorization. The authorization never deletes or shortens retention for protocol
recovery material.

## Removal and migration

This component has no persistent state to remove or replace. V1 defines one-shot pre-activation application-plaintext deletion only. It does not authorize sender retraction, administrator moderation, local delete-for-me, custom prompts, arbitrary ranges, or secure erasure. An incompatible request, proof, carrier, or target rule requires a new component id and proof event kind.
