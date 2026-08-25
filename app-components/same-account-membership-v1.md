# marmot.same-account-membership.v1

Status: experimental.

This component enables bounded same-account leaf admission and removal, and carries the sponsor's enrollment receipt in
the GroupInfo used by a same-account Welcome.

## Assignment

- Component id: `0x800d`
- Name: `marmot.same-account-membership.v1`
- Valid locations: GroupInfo only
- GroupContext component data: none
- LeafNode component data: none
- KeyPackage component data: none
- AppEphemeral data: none
- SafeAAD data: none

Support and group enablement use the upstream `app_components` component. A supporting leaf lists `0x800d` in its
LeafNode `app_components` support list. An enabled group lists `0x800d` in its GroupContext `app_components` required
list. Neither location carries a `0x800d` dictionary entry.

A `0x800d` dictionary entry in GroupContext, LeafNode, or KeyPackage is invalid. A GroupInfo entry is valid only for the
same-account Welcome flow below; ordinary admin Welcomes omit it. GroupInfo data is fixed when that GroupInfo is
created and has no update or replacement operation.

## GroupInfo receipt bytes

A GroupInfo created for a same-account Welcome MUST contain exactly one `0x800d` dictionary entry with these bytes:

```text
struct {
  opaque pairing_session_id[32];
  opaque enrollment_intent_hash[32];
  opaque key_package_ref<V>;
  uint64 source_epoch;
  opaque candidate_parent_context_hash[32];
} MarmotSameAccountEnrollmentReceiptV1;
```

`key_package_ref` is the MLS KeyPackageRef of the single leaf added by the Commit. `source_epoch` is the candidate
parent epoch. `candidate_parent_context_hash` is:

```text
SHA-256(TLS-Serialize(candidate_parent_group_context))
```

The GroupInfo containing the receipt MUST describe the immediate result of the authorized Add Commit. Its group id and
epoch therefore identify the destination group and `source_epoch + 1`; its tree hash and confirmed transcript hash
commit to the resulting tree and Commit transcript. The GroupInfo signer MUST be the sponsor leaf that authored the
Commit.

The component bytes use the Marmot canonical encoding profile. `key_package_ref` MUST be non-empty and MUST equal the
reference of the KeyPackage consumed by the receiving device. Unknown trailing bytes, non-canonical vector lengths,
and any epoch other than exactly one greater than `source_epoch` are invalid.

## Enrollment intent

The receipt commits to this feature-owned canonical structure:

```text
struct {
  opaque pairing_session_id[32];
  opaque group_id<V>;
  opaque sponsor_account[32];
  opaque sponsor_leaf_node_hash[32];
  opaque key_package_ref<V>;
  uint64 approval_expires_at;
} MarmotSameAccountEnrollmentIntentV1;
```

`sponsor_leaf_node_hash` is `SHA-256(TLS-Serialize(sponsor_leaf_node))`, using the sponsor leaf in the candidate parent.
`enrollment_intent_hash` is `SHA-256(Marmot-Encode(MarmotSameAccountEnrollmentIntentV1))`. The intent's group id,
sponsor account, sponsor leaf hash, and KeyPackage reference MUST match the candidate parent, sponsor, and added leaf.
The sponsor MUST create the Commit no later than `approval_expires_at`, and the joiner MUST receive and validate its
Welcome no later than that time. Expiry is a pairing authorization check, not an input to convergence.

## Enablement

An active admin MAY enable `0x800d` only when every current leaf advertises support for it. Unsupported members MUST
NOT be removed automatically. Enablement follows the ordinary administrator-authorized GroupContext capability update
flow.

While enabled, every Commit MUST leave at most five current leaves for any one Marmot account identity. This is a
resulting-state invariant, including for administrator-authored Commits and Commits unrelated to membership.

An active admin MAY disable `0x800d` only when no account has more than one current leaf in the resulting state.
Disabling removes `0x800d` from the required `app_components` list; there is no component state entry to remove.

## Commit authorization

When `0x800d` is required in the candidate parent, a current leaf MAY author either of these narrow Commit shapes
without being an active admin:

- **Same-account Add:** exactly one inline Add, no referenced proposal, no other proposal, and a normal UpdatePath. The
  added KeyPackage has a valid `marmot.member.account-identity-proof.v2`; its account identity equals the committer's;
  its KeyPackage and leaf signature key are distinct from every current leaf; and the resulting-state limit passes.
- **Same-account Remove:** one to four inline Remove proposals, no referenced proposal, no other proposal, and a normal
  UpdatePath. Every target is a current leaf of the committer's account, no target is the committer, and targets are
  distinct. Self-removal continues to use SelfRemove.

The same shapes are valid for an active admin, but an admin gains no broader same-account shape. Standalone Add and
Remove proposals are not authorized by this component. Both Commit shapes have ordinary convergence priority.

The Add Commit MUST produce one GroupInfo for the added member with a valid receipt as defined above. Existing members
validate the Commit against its candidate parent. The joining member validates the sponsor-attested receipt and
resulting state as defined in [../features/multi-device.md](../features/multi-device.md).

If the five-leaf limit is reached, a sponsor first removes stale sibling leaves and waits for that Remove Commit to
become canonical, then starts a separate Add with a fresh KeyPackage. The two operations MUST NOT be combined.

An active admin MAY use the ordinary admin removal path to remove orphaned leaves only when that account controls no
current leaf in the group. If an account has no surviving group leaf and the group has no active admin, v1 defines no
in-band recovery path.

## Trust model

The receipt is a sponsor attestation, not an independently verifiable proof of the candidate parent. The pairing
sponsor is the trust root. A compromised sponsor can create a fork and attest false parent details. The GroupInfo
signature and confirmed transcript hash bind that attestation to the exact branch and Commit result the sponsor
provided; they do not establish global finality or agreement by another account.

## Migration

`0x800d` is the first version. A breaking change requires a new component id and document. Implementations of the
withdrawn External-Commit multi-device draft MUST NOT map its released identifiers or payloads to this component.
