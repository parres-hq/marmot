# marmot.transport.nostr.routing.v1

Status: adopted.

## Registry

- Component id: `0x8004`
- Name: `marmot.transport.nostr.routing.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required only for Nostr-routed Marmot groups

## State

```text
struct {
  opaque url<1..512>;
} MarmotNostrRelayV1;

struct {
  opaque nostr_group_id[32];
  MarmotNostrRelayV1 relays<V>;
} MarmotNostrRoutingV1;
```

`nostr_group_id` is the Nostr group routing handle used for group message delivery.

It is opaque. Every `nostr_group_id` value — the one chosen at group creation and any replacement committed by a
routing rotation — MUST be generated from cryptographically secure randomness. It MUST NOT be derived from any account
id, member id, public key, MLS group id, KeyPackage id, message id, or relay URL.

`relays` is the canonical sorted list of unique relay URL byte strings for a Nostr-routed group. The list is signed
group state.

A client MAY apply local safety policy before connecting or publishing. Local policy does not change the canonical relay
list.

## Update

The update payload is a full replacement state:

```text
MarmotNostrRoutingV1 MarmotNostrRoutingUpdateV1;
```

An update MAY change the relay list, `nostr_group_id`, or both. An update that changes `nostr_group_id` is a routing
rotation.

## Routing rotation

The commit that carries a routing change MUST be published to the delivery address of the prior epoch's routing state —
that is where members are listening. Publish-before-apply already implies this; it is stated here so a rotation commit
is never published only at the new address.

After applying the commit, members use the new routing state for subsequent traffic.

Members MUST continue to accept and fetch traffic at a prior routing address while any epoch that used it remains
inside either retained-history window: at or after the retained anchor for commits and proposals, or inside the retained
app-payload window for application messages
([../protocol-core/retained-history.md](../protocol-core/retained-history.md)). Members MUST be able to map more than one
routing id to the same group until both uses of the prior address have expired.

A member catching up across a rotation uses its recorded routing-state history to fetch older epochs at their
then-active addresses. A new joiner receives the current routing state in its Welcome and needs older addresses only
within the retained-history rules.

A group MAY be reachable at more than one Nostr routing address over its lifetime. v1 state carries exactly one current
`nostr_group_id`; a future component version MAY carry multiple concurrent routing ids.

Routing rotation after a member removal is optional. The removed member already knows the routing id and relay list
that were active before removal, so it can continue observing ciphertext metadata published at that address.

When a group chooses to hide its replacement routing id from that member, it uses two accepted commits:

1. a membership commit removes the member without changing `nostr_group_id` for this privacy purpose;
2. after that removal is canonical, a later commit rotates `nostr_group_id` from the post-removal epoch.

Changing membership and `nostr_group_id` in the same commit does not provide this property: the removed member can
decrypt the removal commit under the source epoch and read its routing update. The later rotation commit is still
published to the prior routing address under the publish rule above, but its Nostr group envelope uses the
post-removal epoch key, so the removed member learns only that ciphertext was published at the address it already knew.
This sequence does not require automatic rotation after every removal.

## Validation

A one-relay list is valid. Producers SHOULD propose at least two independently operated relays when the deployment
permits it, but relay diversity is an availability policy rather than a group-state validity condition. If every relay
in the signed routing state is unavailable or censors a routing-change commit, this component provides no out-of-band
recovery path; members have to regain delivery through that routing state or create another group.

A Nostr routing state is valid if:

- `nostr_group_id` is exactly 32 bytes
- the relay list is not empty
- the relay list contains at most 16 entries
- every relay URL satisfies the Nostr relay URL profile in [../transports/nostr.md](../transports/nostr.md)
- relay URLs are sorted lexicographically over the URL content bytes, per the default sort order in
  [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md) ("Sorting and duplicates")
- relay URLs have no duplicates

Clients compare relay URL bytes exactly after validation. Producers SHOULD normalize before proposing a group-state
update, but a client MUST NOT rewrite relay URL bytes while applying signed group state.

## Authorization

Only an active admin MAY send a standalone routing update proposal.

Only an active admin MAY commit a routing update. This includes routing rotations: a `nostr_group_id` change is
admin-gated like every other routing update.

Commit authorization, including removal authorization, follows the shared prior-epoch rule in
[README.md](./README.md) ("Authorization Evaluation").

## Removal

Only an active admin MAY commit removal of this component.

This component MUST NOT be removed while the group is Nostr-routed and lists it as required in GroupContext
`app_components`. It MAY be removed only from a group that no longer routes over Nostr. If it is removed from a group
that still exists over another transport, the Nostr transport can no longer route group messages from signed group
state.

## Migration

This component carries the `nostr_group_id` and `relays` fields from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
