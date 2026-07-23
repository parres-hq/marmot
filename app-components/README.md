# Marmot app components

Status: adopted.

Marmot app-owned MLS data is split into application components carried by the MLS `app_data_dictionary` extension. Each
component has a `ComponentID` and owns the opaque bytes stored under that id.

An `app_data_dictionary` can appear in a GroupContext, LeafNode, KeyPackage, or GroupInfo. The containing MLS object
determines the scope of its component entries:

- GroupContext entries are authenticated group state agreed for an epoch.
- LeafNode entries describe and advertise data associated with one member leaf.
- KeyPackage entries describe data associated with one KeyPackage, separate from entries in its embedded LeafNode.
- GroupInfo entries carry application data for a particular GroupInfo object.

The dictionary is the common carrier at all of those locations:

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

This spec follows:

- [draft-ietf-mls-extensions-10](https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions-10)
- [OpenMLS AppData handling](https://book.openmls.tech/user_manual/app_data_updates.html)

OpenMLS exposes this support behind its `extensions-draft-08` feature. Marmot targets the draft-10 code points and
semantics; the pinned ids in [../foundation/registries.md](../foundation/registries.md) match
draft-ietf-mls-extensions-10. Where OpenMLS's draft-08 implementation emits a different code point or wire layout than
draft-10, that gap MUST be reconciled before interop rather than papered over locally.

For the profile Marmot currently implements, the pinned upstream component, extension, and proposal ids are listed in
[../foundation/registries.md](../foundation/registries.md). Changing them is a wire-compatibility change, not a local
implementation detail.

## Component IDs

Marmot uses private MLS component ids in the `0x8000..0xffff` range.

Marmot does not plan to request public component ids for these components.

Each file defines one component id. Component names include `v1` for human readability. The versioning rule for breaking
changes is:

- a breaking v2 gets a new component id;
- a breaking v2 gets a new component file;
- component state and update payloads do not add a generic major-version field. A component-specific format constant
  retained as part of an inherited byte schema is not version negotiation and MUST NOT replace the component-id rule.

Compatible changes are valid only when the active component document explicitly reserves the needed field, value, or
behavior.

This is a Marmot policy choice, not a rule imposed by the MLS extensions draft. The MLS `app_components` mechanism
negotiates component ids, not `(component_id, version)` pairs.

Assigned component ids are registered in [../foundation/registries.md](../foundation/registries.md).

## Placement

Application data SHOULD use a component at the MLS location whose existing lifecycle matches the data. Leaf-scoped data
does not become a custom extension merely because it is security-critical or must be validated before accepting a
member. A custom MLS extension is appropriate only when the feature needs MLS protocol machinery or extension semantics
that `app_data_dictionary` and the safe application interface cannot express.

Persistent Marmot group state uses GroupContext components. Per-member application metadata or an application-owned
proof about a leaf normally uses a LeafNode component. A component document MUST state every valid location and define
the bytes and validation rules for each location.

Location also determines how the bytes change:

- GroupContext component entries change through `AppDataUpdate`.
- LeafNode component entries change only when a new or replacement LeafNode is created.
- KeyPackage and GroupInfo component entries are set when their containing object is created.
- Commit-scoped component data is carried by `AppEphemeral` and does not become persistent component state.
- A component that contributes MLS additional authenticated data uses `SafeAAD` when the group has negotiated it.

An `AppDataUpdate` targets only the GroupContext dictionary. It MUST NOT be used or reinterpreted as an update mechanism
for a LeafNode, KeyPackage, or GroupInfo component.

`AppEphemeral` and SafeAAD are not interchangeable. A value whose lifetime is exactly one Commit SHOULD use
`AppEphemeral`. SafeAAD is for component-separated contributions to the MLS `authenticated_data` field and changes the
framing of that entire field when enabled in the GroupContext.

## Negotiation

Every implementation that advertises support for `app_data_dictionary` MUST understand and advertise the registered
upstream `app_components` component, and MUST understand the registered upstream `safe_aad` component. A LeafNode
advertises supported component ids in its `app_components` entry. A GroupContext lists the component ids required by
the group in its `app_components` entry.

The LeafNode support list does not replace a required component's data. If a Marmot component requires an entry in each
member LeafNode, the owning component document MUST require and validate that entry separately.

A member that does not support every required component id MUST NOT join the group.

Groups that change GroupContext component state also require the registered `app_data_update` proposal.

## Common Rules

All state and update payloads use the Marmot binary profile unless a component says otherwise.

Each component document MUST define:

- component id
- component name
- every valid component entry location
- bytes and validation at each location
- negotiation and presence requirements
- the location-appropriate creation or update lifecycle
- any `AppEphemeral` or SafeAAD bytes and processing rules owned by the component
- authorization rules for every mutation the component permits
- removal or replacement rules
- migration rule

GroupContext component documents additionally MUST define state bytes, update bytes, proposal authorization, commit
authorization, and removal rules. LeafNode, KeyPackage, and GroupInfo component documents MUST NOT invent
`AppDataUpdate` bytes; they instead define validation and the rules for creating or replacing the containing MLS
object.

For v1 GroupContext component documents, these defaults apply unless the component says otherwise:

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

## GroupContext Update Processing

Each Marmot GroupContext component document defines two byte formats:

- state bytes stored in `AppDataDictionary.component_data.data`;
- update bytes carried in `AppDataUpdate.update`.

For each Commit, a Marmot client groups AppDataUpdate proposals by component id. For each component id, the client
evaluates the prior state and ordered update bytes using that component's update rule.

The update rule returns new state bytes or rejects the Commit. A component's update rule decides how update bytes relate
to prior state. In v1 every GroupContext component document defines its update payload as a full replacement state.
When a Commit contains one or more update operations for the same v1 component, the client MUST validate every proposal
sender and every update payload's component-local encoding and value rules in Commit order. Any invalid proposal or
payload makes the whole Commit invalid. Each valid payload replaces the working component state, so the last update
operation's payload is the resulting component state; earlier valid replacements do not override it. Resulting-epoch
and cross-component invariants are then checked against that final state. Partial field updates are not defined (see
"Common Rules" above).

A future component MAY define a diff-style update rule, but it MUST say so explicitly in its own document; no v1
component does.

Update rules MUST be deterministic. They MUST NOT read local wall-clock time, transport state, random numbers, local UI
state, or local storage order.

AppDataUpdate proposals MAY appear inline in a Commit or as standalone MLS proposals later referenced by a Commit.
Inline updates are the default when the committer is authorized. A standalone MLS proposal is not the default request
mechanism for an admin-gated component change: the component's proposal authorization defines who may create it, and v1
group-level components default to the same active-admin role that may commit it. A non-admin request for an admin-gated
component change, if a feature defines one, is carried as a Marmot app payload or feature-owned request flow rather than
as an MLS AppDataUpdate proposal.

For a Commit, a Marmot client evaluates all AppDataUpdate proposals for a component in Commit order. The component
validates every proposal sender, the committer, the prior state, and the ordered updates. It returns the new state bytes
or an invalid result. If any component update is invalid, the Commit is invalid.

## Authorization Evaluation

Standalone proposal authorization is evaluated against the authenticated candidate state for the proposal's MLS
source epoch. It checks the proposal sender independently from the later Commit's committer; a resulting-state update
does not retroactively grant or revoke the proposal sender's authority.

Commit authorization for every component operation, including update and removal, is evaluated against the candidate
parent state: the active-admin set and other authorization inputs from the epoch before the Commit. Updates carried in
the Commit cannot grant their own committer authority or revoke authority before the other operations in that Commit
are authorized. After authorization, every component and cross-component invariant is evaluated against the complete
resulting epoch state.

## GroupContext Removal

The MLS AppDataUpdate `remove` operation removes a component entry from the GroupContext dictionary. Each Marmot
component states whether removal is allowed.

Removal is a component change and inherits that component's commit authorization unless its owning document explicitly
defines a different removal actor. Each component's Removal section restates the authorized actor so the rule does not
depend on treating the word "update" as implicit coverage of `remove`.

Required components MUST NOT be removed while still listed in GroupContext `app_components`.

## Unknown Data

Unknown required components fail closed through negotiation.

Unknown non-required component entries MUST be preserved byte-for-byte when a client rewrites `app_data_dictionary`. The
client MUST NOT parse, normalize, sort inside, partially copy, or re-encode unknown component bytes.

## Default GroupContext Authorization

The component validates authorization. OpenMLS validates the MLS message shape; Marmot validates whether the sender MAY
make the requested semantic change.

Each component document defines who MAY propose an update and who MAY commit an update. These MAY be different roles
only when the component explicitly defines a separate proposal role.

Group-level component proposals and commits are admin-gated by default.

A component MAY define a looser rule, but it MUST do so explicitly. In v1, the admin set is defined by
`marmot.group.admin-policy.v1`.

## Current Marmot Components

Assigned component ids are registered in [../foundation/registries.md](../foundation/registries.md).

The currently adopted Marmot-owned components below are all GroupContext components. LeafNode, KeyPackage, and
GroupInfo components use the same registry and directory when Marmot defines them.

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
- `marmot.group.admin-policy.v1` is required for every Marmot group. Other Marmot core components are optional unless a
  group profile, transport, or feature requires them.
- `marmot.group.blossom.image.v1` is Blossom-specific. Other image-reference models SHOULD use separate components.
- `marmot.transport.nostr.routing.v1` is required for Nostr-routed Marmot groups.
- Nostr relays in `marmot.transport.nostr.routing.v1` are canonical signed group state, not local hints.
- Application profiles MAY require `marmot.group.agent-text-stream.quic.v1` by default for agent-stream-ready groups. Its
  `receive` role is final-message fallback compatibility, not a requirement to implement the raw QUIC live-preview data
  plane.
- AppDataUpdate proposals MAY be inline or standalone. Inline is the default path when the committer is authorized;
  standalone MLS proposals are not the default non-admin request path for admin-gated component changes.
- `marmot.group.encrypted-media.v1` owns the group media policy. Individual media attachments remain message metadata
  and are described in [encrypted-media.md](../features/encrypted-media.md).
