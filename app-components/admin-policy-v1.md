# marmot.group.admin-policy.v1

Status: adopted.

## Registry

- Component id: `0x8003`
- Name: `marmot.group.admin-policy.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required for every Marmot group

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

v1 sets no smaller independent admin-count ceiling: every distinct current account may legitimately be an admin, and
the uniqueness and membership checks bound the list by the resulting group's distinct account count.

The last check is cross-component: it validates this component against the resulting epoch's member leaves rather than
against the component bytes alone. Commit validity already spans components, so a commit whose resulting epoch lists an
admin key with no member leaf is invalid.

The cross-component check is a property of the resulting epoch, not of the commits that carry admin-policy bytes. It
runs on every commit that changes the member leaf set or this component's state. When a commit carries no admin-policy
update, the resulting epoch's admin set is the prior epoch's admin set carried forward, and the check is evaluated
against that carried-forward set. A commit that removes a listed account's last member leaf without also updating this
component is therefore invalid whether or not the commit re-serializes this component's bytes.

## Authorization

Only an active admin MAY send a standalone admin policy update proposal.

Only an active admin MAY commit an admin policy update.

Commit authorization, including removal authorization, follows the shared prior-epoch rule in
[README.md](./README.md) ("Authorization Evaluation"). An update that removes the committer from `admins` is valid only
if at least one other active admin remains.

## Admin-Gated Actions

Every v1 group-level Marmot component update requires an active admin to commit unless the owning component document
explicitly defines a looser rule. No v1 group-level component currently defines one. This rule follows the component
class rather than an enumerated list, so adding a registered component does not silently make its updates ungoverned.

The following non-component operations also require an active admin to commit:

- invite a new member;
- remove another member; and
- change the GroupContext `app_components` list of required Marmot components.

For Welcome-based joins, the receiver applies the same invite authorization check at join time. The receiver identifies
the inviter from the MLS GroupInfo signer leaf and rejects the Welcome unless that leaf's MLS-authenticated Marmot
account identity is an active admin in the joined group state. This component is the sole membership-add authority for
v1 groups: if it is absent, no member is authorized to add, so the receiver rejects the Welcome. This check's trust
model and its limits are described in [../protocol-core/joining.md](../protocol-core/joining.md) ("Welcome-bootstrap
trust").

SelfRemove is special:

- a non-admin member MAY self-remove
- a SelfRemove proposal whose sender is an active admin in the prior epoch is invalid
- a departing admin first commits an admin-policy update that removes it from `admins` (valid only if at least one
  other active admin remains), then uses SelfRemove
- any remaining authorized member MAY commit a SelfRemove proposal
- the committer of a SelfRemove proposal MUST NOT be the leaving member

[../protocol-core/member-departure.md](../protocol-core/member-departure.md) owns the full SelfRemove flow.

## Removal

This component is the sole admin authority for v1 groups and MUST remain present and required for the lifetime of a
Marmot group. An AppDataUpdate `remove` operation targeting this component is invalid, so no member, including an
active admin, is authorized to commit one. Deleting or abandoning a local group is not a component removal and does not
require a group-state commit.

## Migration

This component carries the `admin_pubkeys` field from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
