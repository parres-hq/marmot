# Marmot app components

Status: draft for internal review.

Marmot group state is split into custom MLS app components carried by the MLS `app_data_dictionary` extension. Each
component has a `ComponentID` and owns the opaque state bytes stored under that id.

The dictionary is the shared GroupContext carrier:

```text
uint16 ComponentID;

struct {
  ComponentID component_id;
  opaque data<V>;
} ComponentData;

struct {
  ComponentData component_data<V>;
} AppDataDictionary;
```

Dictionary entries are sorted by `component_id` and contain at most one entry for each component.

Marmot defines the bytes inside `data` for Marmot-owned component ids using the canonical encoding profile in
[../foundation/canonical-encoding.md](../foundation/canonical-encoding.md). Marmot does not wrap every entry in another
generic component envelope.

## Upstream Basis

This draft follows:

- [draft-ietf-mls-extensions-09](https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions-09)
- [OpenMLS AppData handling](https://book.openmls.tech/user_manual/app_data_updates.html)

OpenMLS exposes this support behind the `extensions-draft-08` feature.

## Component IDs

Marmot uses private MLS component ids in the `0x8000..0xffff` range.

Marmot does not plan to request public component ids for these components.

Each file defines one component id. Component names include `v1` for human readability. The versioning rule for breaking
changes is:

- a breaking v2 gets a new component id;
- a breaking v2 gets a new component file;
- component state and update payloads do not carry a second major-version field.

Compatible changes are valid only when the active component document explicitly reserves the needed field, value, or
behavior.

This is a Marmot policy choice, not a rule imposed by the MLS extensions draft. The MLS `app_components` mechanism
negotiates component ids, not `(component_id, version)` pairs.

Assigned component ids are registered in [../foundation/registries.md](../foundation/registries.md).

## Negotiation

Groups that use Marmot app components require MLS support for:

- the `app_data_dictionary` extension;
- the `app_data_update` proposal.

Marmot uses the upstream `app_components` component to advertise supported and required component ids:

- In a LeafNode, `app_components` lists the component ids supported by that member.
- In the GroupContext, `app_components` lists the component ids required by the group.

A member that does not support every required component id MUST NOT join the group.

## Common Rules

All state and update payloads use the Marmot binary profile unless a component says otherwise.

Each component document must define:

- component id
- component name
- component entry location
- state bytes
- update bytes
- validation
- proposal authorization
- commit authorization
- removal rule
- migration rule

## Update Processing

Each Marmot component document defines two byte formats:

- state bytes stored in `AppDataDictionary.component_data.data`;
- update bytes carried in `AppDataUpdate.update`.

Updates are diffs. They are not required to be complete replacement states.

For each Commit, a Marmot client groups AppDataUpdate proposals by component id. For each component id, the client
evaluates the prior state and ordered update bytes using that component's update rule.

The update rule returns new state bytes or rejects the Commit.

Update rules must be deterministic. They must not read local wall-clock time, transport state, random numbers, local UI
state, or local storage order.

AppDataUpdate proposals may appear inline in a Commit or as standalone MLS proposals later referenced by a Commit.
Inline updates are the default when the committer is authorized. Standalone proposals are for cases where a member may
request a component change but another member must commit it.

For a Commit, a Marmot client evaluates all AppDataUpdate proposals for a component in commit order. The component
validates the proposal sender, the committer, the prior state, and the ordered updates. It returns the new state bytes
or an invalid result. If any component update is invalid, the Commit is invalid.

## Removal

The MLS AppDataUpdate `remove` operation removes a component entry from the GroupContext dictionary. Each Marmot
component states whether removal is allowed.

Required components MUST NOT be removed while still listed in GroupContext `app_components`.

## Unknown Data

Unknown required components fail closed through negotiation.

Unknown non-required component entries MUST be preserved byte-for-byte when a client rewrites `app_data_dictionary`. The
client must not parse, normalize, sort inside, partially copy, or re-encode unknown component bytes.

## Default Authorization

The component validates authorization. OpenMLS validates the MLS message shape; Marmot validates whether the sender may
make the requested semantic change.

Each component document defines who may propose an update and who may commit an update. These may be different roles.

Group-level component commits are admin-gated by default.

A component can define a looser rule, but it must do so explicitly. In v1, the admin set is defined by
`marmot.group.admin-policy.v1`.

## Current Components

Assigned component ids are registered in [../foundation/registries.md](../foundation/registries.md).

- [marmot.group.profile.v1](./group-profile-v1.md)
- [marmot.group.blossom.image.v1](./group-blossom-image-v1.md)
- [marmot.group.admin-policy.v1](./admin-policy-v1.md)
- [marmot.transport.nostr.routing.v1](./nostr-routing-v1.md)
- [marmot.group.message-retention.v1](./message-retention-v1.md)
- [marmot.group.agent-text-stream.quic.v1](./agent-text-stream-quic-v1.md)

## Resolved Direction

- Marmot component ids stay in the private-use range for the foreseeable future.
- Marmot component major versions are represented by component ids.
- Marmot core components are optional unless a group profile, transport, or feature requires them.
- `marmot.group.blossom.image.v1` is Blossom-specific. Other image-reference models should use separate components.
- `marmot.transport.nostr.routing.v1` is required for Nostr-routed Marmot groups.
- Nostr relays in `marmot.transport.nostr.routing.v1` are canonical signed group state, not local hints.
- AppDataUpdate proposals may be inline or standalone. Inline is the default path when the committer is authorized.
