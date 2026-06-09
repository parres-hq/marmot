# marmot.transport.nostr.routing.v1

Status: draft for internal review.

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

It is opaque. It MUST be generated from cryptographically secure randomness at group creation. It MUST NOT be derived
from any account id, member id, public key, MLS group id, KeyPackage id, message id, or relay URL.

`relays` is the canonical sorted list of unique relay URL byte strings for a Nostr-routed group. The list is signed
group state.

A client MAY apply local safety policy before connecting or publishing. Local policy does not change the canonical relay
list.

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
- every relay URL satisfies the Nostr relay URL profile in [../transports/nostr.md](../transports/nostr.md)
- relay URLs are sorted lexicographically by byte value
- relay URLs have no duplicates

Clients compare relay URL bytes exactly after validation. Producers SHOULD normalize before proposing a group-state
update, but a client MUST NOT rewrite relay URL bytes while applying signed group state.

## Authorization

Any current member MAY send a standalone relay update proposal.

Only a current admin MAY commit a relay update.

No member MAY propose or commit a `nostr_group_id` update in v1.

## Removal

This component MUST NOT be removed while the group is Nostr-routed and lists it as required in GroupContext
`app_components`. It MAY be removed only from a group that no longer routes over Nostr. If it is removed from a group
that still exists over another transport, the Nostr transport can no longer route group messages from signed group
state.

## Migration

This component carries the `nostr_group_id` and `relays` fields from the MIP-01 `marmot_group_data` extension (see
[../mip-coverage.md](../mip-coverage.md)). v1 is the first versioned form; a breaking change gets a new component id and
file.
