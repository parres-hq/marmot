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
authorization key.

## Active admins

An account is an active admin when its key is in `admins` and the account has at least one current member leaf in the
group. Admin authority is evaluated by matching a member's MLS-authenticated account identity against the active
admins; a multi-device account shares one admin entry across all of its leaves. Every Marmot document that authorizes
an action against the admin policy uses this term with this definition.

A commit that removes an account's last member leaf MUST also remove that account's key from `admins` in the same
commit. An admin-policy state that lists an account with no member leaf is invalid in the resulting epoch, so in valid
group state every key in `admins` names an active admin.

This coupling rule and the SelfRemove flow below are two different departure paths, not two orderings of one
transition. The coupling rule binds commits that remove a listed account's last leaf — for example, an admin removing
another listed account's last device with a Remove proposal. SelfRemove never triggers the coupling rule: a SelfRemove
proposal whose sender is still an active admin is invalid at the sender check, so a departing admin's admin-policy
update always lands in an earlier commit, and the account is no longer listed in `admins` by the time its SelfRemove
commits.

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
- every admin key corresponds to an account with at least one member leaf in the resulting epoch's group state

The last check is cross-component: it validates this component against the resulting epoch's member leaves rather than
against the component bytes alone. Commit validity already spans components, so a commit whose resulting epoch lists an
admin key with no member leaf is invalid.

## Authorization

Any current member MAY send a standalone admin policy proposal.

Only an active admin MAY commit an admin policy update.

The commit authorization is evaluated against the prior epoch's active admins. An update that removes the committer
from `admins` is valid only if at least one other active admin remains.

## Admin-Gated Actions

In v1, the following operations require an active admin to commit:

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
account identity is an active admin in the joined group state. If this component is absent, the receiver rejects the
Welcome unless the active application profile defines another membership-add authorization component.

SelfRemove is special:

- a non-admin member MAY self-remove
- a SelfRemove proposal whose sender is an active admin in the prior epoch is invalid
- a departing admin first commits an admin-policy update that removes it from `admins` (valid only if at least one
  other active admin remains), then uses SelfRemove
- the committer of a SelfRemove proposal MUST NOT be the leaving member

[../protocol-core/member-departure.md](../protocol-core/member-departure.md) owns the full SelfRemove flow.

## Removal

If the component is absent, components and operations that require an active admin are invalid unless the active
application profile defines another authorization component.

## Migration

This component carries the `admin_pubkeys` field from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
