# Feature specs

Status: sketch.

Feature specs describe user-visible Marmot behavior that spans several surfaces.

A feature doc should explain the flow, name the protocol surfaces involved, and point to the documents that own exact
bytes. It should avoid copying component schemas, MLS structures, transport event shapes, or foundation rules.

## Relationship to app components

App components stay in [../app-components/](../app-components/).

A feature may require one or more app components. The feature doc explains when the feature reads or changes that state.
The component doc owns the component id, state bytes, update bytes, validation, authorization, removal, and migration.

For example, a group profile feature can point to `marmot.group.profile.v1`. The group profile component still owns the
two UTF-8 fields and their length limits.

## Feature document checklist

Each feature document should define:

- feature name and status;
- user-visible behavior;
- required capabilities, proposal types, app components, message kinds, or transports;
- creation or activation flow;
- update flow;
- authorization;
- interaction with convergence and retained history;
- failure behavior that affects interop;
- migration from MIP-era behavior, if any.

## Versioning

Git history records prose changes. Interop-visible feature versions need names inside the spec.

Use component ids for app component state versions. Use proposal ids for custom MLS proposal versions. Use event kinds
or payload versions for app messages. Use a new feature document name when the high-level flow changes enough that
readers need both versions side by side.

Compatible clarifications can update an existing feature doc in place.
