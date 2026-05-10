# marmot.transport.nostr.routing.v1

Status: sketch.

## Registry

- Component id: `0x8004`
- Name: `marmot.transport.nostr.routing.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required only for Nostr-routed Marmot groups
- Replaces: `marmot_group_data.nostr_group_id`, `marmot_group_data.relays`

## State

```text
struct {
  opaque url<1..512>;
} MarmotNostrRelayV1;

struct {
  opaque nostr_group_id<32..32>;
  MarmotNostrRelayV1 relays<V>;
} MarmotNostrRoutingV1;
```

`nostr_group_id` is the Nostr group routing handle used for group message
delivery.

It is opaque. It MUST be generated from cryptographically secure randomness at
group creation. It MUST NOT be derived from any account id, member id, public
key, MLS group id, KeyPackage id, message id, or relay URL.

`relays` is the canonical sorted list of unique relay URL byte strings for a
Nostr-routed group. The list is signed group state.

A client MAY apply local safety policy before connecting or publishing. Local
policy does not change the canonical relay list.

## Update

The update payload can change relays only:

```text
struct {
  MarmotNostrRelayV1 relays<V>;
} MarmotNostrRoutingUpdateV1;
```

There is no v1 update that changes `nostr_group_id`.

## Validation

A Nostr routing state is valid if:

- `nostr_group_id` is exactly 32 bytes
- every relay URL is valid UTF-8
- every relay URL is at most 512 bytes
- relay URLs are sorted lexicographically by byte value
- relay URLs have no duplicates

The transport document defines URL scheme and normalization rules. Until that
document exists, clients compare relay URL bytes exactly.

## Authorization

Any current member may send a standalone relay update proposal.

Only a current admin may commit a relay update.

An inline relay update requires the sender to be a current admin because the
proposal sender and committer are the same member.

No member may propose or commit a `nostr_group_id` update in v1.

## Removal

This component MUST NOT be removed while Nostr routing is required by the
GroupContext `app_components` component.

If removed from a group that still exists over another transport, the Nostr
transport can no longer route group messages from signed group state.

## Migration

Migration from `marmot_group_data` copies `nostr_group_id` and decodes `relays`
into the sorted canonical relay list.

If the old `nostr_group_id` is derived from identity material, migration SHOULD
rotate the routing id by creating a new group or by a future component version
that defines safe routing-id rotation.
