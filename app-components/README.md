# Marmot App Component Drafts

Status: sketch.

This directory defines Marmot-owned payloads for the MLS
`app_data_dictionary` extension.

Each file defines one component id. Component major versions are represented by
component ids. A breaking v2 gets a new component id and a new file.

## Common Rules

All state and update payloads use TLS Presentation Language encoding unless a
component says otherwise.

Each component document must define:

- component id
- component name
- dictionary location
- state bytes
- update bytes
- validation
- proposal authorization
- commit authorization
- removal rule
- migration rule

## Update Processing

For each Commit, a Marmot client groups AppDataUpdate proposals by component id.
For each component id, the client evaluates the prior state and ordered update
bytes using that component's update rule.

The update rule returns new state bytes or rejects the Commit.

Update rules must be deterministic. They must not read local wall-clock time,
transport state, random numbers, local UI state, or local storage order.

AppDataUpdate proposals may appear inline in a Commit or as standalone MLS
proposals later referenced by a Commit. Inline updates are the default when the
committer is authorized. Standalone proposals are for cases where a member may
request a component change but another member must commit it.

## Default Authorization

Group-level component commits are admin-gated by default.

A component can define a looser rule, but it must do so explicitly. In v1, the
admin set is defined by `marmot.group.admin-policy.v1`.

## Current Components

| Component id | Component |
| --- | --- |
| `0x8001` | [marmot.group.profile.v1](./group-profile-v1.md) |
| `0x8002` | [marmot.group.image.v1](./group-image-v1.md) |
| `0x8003` | [marmot.group.admin-policy.v1](./admin-policy-v1.md) |
| `0x8004` | [marmot.transport.nostr.routing.v1](./nostr-routing-v1.md) |
| `0x8005` | [marmot.group.message-retention.v1](./message-retention-v1.md) |
