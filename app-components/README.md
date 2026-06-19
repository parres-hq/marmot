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

The `AppDataDictionary` and `ComponentData` structures are defined by the MLS extensions draft, not by Marmot. They are
reproduced here only for reference and use MLS/TLS encoding. Per
[../foundation/canonical-encoding.md](../foundation/canonical-encoding.md), Marmot treats these upstream structures as
opaque-from-MLS and owns only the bytes inside each `data` field for Marmot component ids, encoded with the Marmot
canonical encoding profile. Marmot does not wrap every entry in another generic component envelope.

## Upstream Basis

This draft follows:

- [draft-ietf-mls-extensions-09](https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions-09)
- [OpenMLS AppData handling](https://book.openmls.tech/user_manual/app_data_updates.html)

OpenMLS exposes this support behind its `extensions-draft-08` feature. Marmot targets the draft-09 code points; the
pinned ids below match draft-ietf-mls-extensions-09. Where OpenMLS's draft-08 implementation emits a different code
point or wire layout than draft-09, that gap MUST be reconciled before interop rather than papered over locally.

For the profile Marmot currently implements, the pinned upstream ids for `app_components`, `app_data_dictionary`, and
`app_data_update` are listed in [../foundation/registries.md](../foundation/registries.md). Changing them is a
wire-compatibility change, not a local implementation detail.

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

Groups that use Marmot app components require MLS support for the registered `app_data_dictionary` extension and
`app_data_update` proposal. Marmot uses the registered upstream `app_components` component to advertise supported and
required component ids:

- In a LeafNode, `app_components` lists the component ids supported by that member.
- In the GroupContext, `app_components` lists the component ids required by the group.

A member that does not support every required component id MUST NOT join the group.

## Common Rules

All state and update payloads use the Marmot binary profile unless a component says otherwise.

Each component document MUST define:

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

For v1 component documents, these defaults apply unless the component says otherwise:

- If the update payload is a full replacement state, partial field updates are not defined. A caller that wants to
  change one field reads the current state, changes that field, and sends a full replacement.
- An inline AppDataUpdate requires the sender to satisfy the component's commit authorization because the proposal
  sender and committer are the same member. For admin-gated components, the sender MUST be an active admin (defined
  in [admin-policy-v1.md](./admin-policy-v1.md)).
- A component MUST NOT be removed while it is listed as required in the GroupContext `app_components` component.

Component state and update decoders follow the canonical decoding rule in
[../foundation/canonical-encoding.md](../foundation/canonical-encoding.md): bytes that are not canonical are invalid,
and a decoder MUST NOT trim, case-fold, normalize, deduplicate, or reorder values while decoding. Fields an owning
component document marks as opaque hints are validated only against their stated bounds.

## Update Processing

Each Marmot component document defines two byte formats:

- state bytes stored in `AppDataDictionary.component_data.data`;
- update bytes carried in `AppDataUpdate.update`.

For each Commit, a Marmot client groups AppDataUpdate proposals by component id. For each component id, the client
evaluates the prior state and ordered update bytes using that component's update rule.

The update rule returns new state bytes or rejects the Commit. A component's update rule decides how update bytes relate
to prior state. In v1 every component document defines its update payload as a full replacement state, so the update
rule replaces the prior state with the update bytes (partial field updates are not defined; see "Common Rules" above). A
future component MAY define a diff-style update rule, but it MUST say so explicitly in its own document; no v1 component
does.

Update rules MUST be deterministic. They MUST NOT read local wall-clock time, transport state, random numbers, local UI
state, or local storage order.

AppDataUpdate proposals MAY appear inline in a Commit or as standalone MLS proposals later referenced by a Commit.
Inline updates are the default when the committer is authorized. Standalone proposals are for cases where a member MAY
request a component change but another member MUST commit it.

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
client MUST NOT parse, normalize, sort inside, partially copy, or re-encode unknown component bytes.

## Default Authorization

The component validates authorization. OpenMLS validates the MLS message shape; Marmot validates whether the sender MAY
make the requested semantic change.

Each component document defines who MAY propose an update and who MAY commit an update. These MAY be different roles.

Group-level component commits are admin-gated by default.

A component can define a looser rule, but it MUST do so explicitly. In v1, the admin set is defined by
`marmot.group.admin-policy.v1`.

## Current Components

Assigned component ids are registered in [../foundation/registries.md](../foundation/registries.md).

- [marmot.group.profile.v1](./group-profile-v1.md)
- [marmot.group.blossom.image.v1](./group-blossom-image-v1.md)
- [marmot.group.admin-policy.v1](./admin-policy-v1.md)
- [marmot.transport.nostr.routing.v1](./nostr-routing-v1.md)
- [marmot.group.message-retention.v1](./message-retention-v1.md)
- [marmot.group.agent-text-stream.quic.v1](./agent-text-stream-quic-v1.md)
- [marmot.group.avatar-url.v1](./group-avatar-url-v1.md)
- [marmot.group.encrypted-media.v1](./group-encrypted-media-v1.md)

## Resolved Direction

- Marmot component ids stay in the private-use range for the foreseeable future.
- Marmot component major versions are represented by component ids.
- Marmot core components are optional unless a group profile, transport, or feature requires them.
- `marmot.group.blossom.image.v1` is Blossom-specific. Other image-reference models SHOULD use separate components.
- `marmot.transport.nostr.routing.v1` is required for Nostr-routed Marmot groups.
- Nostr relays in `marmot.transport.nostr.routing.v1` are canonical signed group state, not local hints.
- AppDataUpdate proposals MAY be inline or standalone. Inline is the default path when the committer is authorized.
- `marmot.group.encrypted-media.v1` owns the group media policy. Individual media attachments remain message metadata
  and are described in [encrypted-media.md](../features/encrypted-media.md).
