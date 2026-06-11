# marmot.group.admin-policy.v1

Status: draft for internal review.

## Registry

- Component id: `0x8003`
- Name: `marmot.group.admin-policy.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional

## State

```text
struct {
  opaque xonly_pubkey[32];
} MarmotAdminKeyV1;

struct {
  MarmotAdminKeyV1 admins<V>;
} MarmotAdminPolicyV1;
```

`admins` is a sorted list of unique 32-byte x-only secp256k1 public keys.

Each admin key is a Marmot account identity: the same raw 32-byte x-only Nostr public key carried as a member's MLS
`BasicCredential` identity (see [../foundation/identity.md](../foundation/identity.md)). It is not a separate
authorization key. Admin authority is evaluated by matching a committer's MLS-authenticated account identity against
this list. A device leaf is an admin when its account identity appears here, so a multi-device account shares one admin
entry across all of its leaves.

## Update

The update payload is a full replacement state:

```text
MarmotAdminPolicyV1 MarmotAdminPolicyUpdateV1;
```

## Validation

An admin policy state is valid if:

- every admin key is exactly 32 bytes
- the admin list is sorted lexicographically by key bytes
- the admin list has no duplicates
- the admin list is not empty

## Authorization

Any current member MAY send a standalone admin policy proposal.

Only a current admin MAY commit an admin policy update.

The commit authorization is evaluated against the prior admin set. An update that removes the committer from the admin
set is valid only if at least one other admin remains.

## Admin-Gated Actions

In v1, the following operations require a current admin to commit:

- update `marmot.group.profile.v1`
- update `marmot.group.blossom.image.v1`
- update `marmot.group.admin-policy.v1`
- update `marmot.transport.nostr.routing.v1`
- update `marmot.group.message-retention.v1`
- invite a new member
- remove another member
- change required Marmot components

For Welcome-based joins, the receiver applies the same invite authorization check at join time. The receiver identifies
the inviter from the MLS GroupInfo signer leaf and rejects the Welcome unless that leaf's MLS-authenticated Marmot
account identity is in this admin set. If this component is absent, the receiver rejects the Welcome unless the active
application profile defines another membership-add authorization component.

SelfRemove is special:

- a non-admin MAY self-remove
- an admin MAY self-remove only if another admin remains
- the committer of a SelfRemove proposal MUST NOT be the leaving member

## Removal

If the component is absent, components and operations that require a current admin are invalid unless the active
application profile defines another authorization component.

## Migration

This component carries the `admin_pubkeys` field from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
