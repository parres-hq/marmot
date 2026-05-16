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

The admin key identifies an application authorization key. Binding this key to a member identity is defined by the
identity spec, not by this component.

## Update

The update payload is a full replacement state:

```text
MarmotAdminPolicyV1 MarmotAdminPolicyUpdateV1;
```

Partial admin mutations are not defined in v1.

## Validation

An admin policy state is valid if:

- every admin key is exactly 32 bytes
- the admin list is sorted lexicographically by key bytes
- the admin list has no duplicates
- the admin list is not empty

## Authorization

Any current member may send a standalone admin policy proposal.

Only a current admin may commit an admin policy update.

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

SelfRemove is special:

- a non-admin may self-remove
- an admin may self-remove only if another admin remains
- the committer of a SelfRemove proposal MUST NOT be the leaving member

## Removal

This component MUST NOT be removed while listed as required in the GroupContext `app_components` component.

If the component is absent, components and operations that require a current admin are invalid unless the active
application profile defines another authorization component.
