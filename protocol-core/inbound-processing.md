# Inbound processing

Status: draft for internal review.

Inbound processing accepts bytes from a transport, turns them into Marmot protocol input, and gives each input a
disposition.

Transport delivery is evidence that bytes exist. It is not evidence that those bytes define the canonical group state.

## Processing shape

```text
transport message
  -> peel or decode transport envelope
  -> retain protocol bytes
  -> classify welcome, commit, proposal, or MLS application message
  -> feed group-state input into convergence
  -> emit accepted, stale, deferred, or invalidated disposition
  -> emit application-visible output when canonical state or delivered payloads change
```

The exact local API is implementation-defined. The protocol-visible result is the disposition.

## Message identity

Each inbound message has a message id used for deduplication. A client MUST deduplicate before applying state changes.

The message id used for deduplication MUST be stable for the carried protocol bytes. It MUST NOT depend on local receive
order, transport source order, subscription id, or database row id.

Duplicate input maps to the `duplicate` category in [../foundation/errors.md](../foundation/errors.md) and MUST NOT be
applied twice. (Protocol-core dispositions named in `PascalCase` below, such as `BeyondAnchor`, are convergence outcome
names; each maps to one of the shared `snake_case` categories in `errors.md`.)

## Classification

After transport peeling, a group message is one of:

- a commit;
- a proposal;
- an MLS application message carrying a Marmot app payload;
- malformed or unsupported input.

A welcome is addressed to one member and creates or joins a group according to the MLS welcome rules and Marmot identity
rules.

Malformed input MUST fail closed. Unsupported input MUST fail closed when the active group policy requires support for
that input (e.g. a welcome requires capabilities the client does not support).

## Deferred input

A client MAY defer an input when it cannot yet be processed but could become processable after more protocol bytes
arrive.

Common deferred cases:

- an MLS application message for a future candidate epoch;
- a child commit whose parent branch is unavailable;
- input received while the group is in `PendingPublish` or `Merging`.

Deferred input MUST be retried when the missing state becomes available or when convergence advances the canonical
branch.

## Stale input

Input that cannot affect the group MUST receive a stale or dropped disposition. This includes:

- duplicate messages (`duplicate`);
- messages for unknown groups (`unknown_group`);
- welcomes addressed to another member (`wrong_recipient`);
- own echoes (`own_echo`);
- commits older than the retained anchor (`BeyondAnchor`, per [retained-history.md](./retained-history.md));
- MLS application messages older than the retained app-payload window (`app_payload_past_epoch_limit` past epochs, see
  [convergence.md](./convergence.md));
- commits that fork from outside the rollback horizon: these are ineligible for branch selection (see
  [convergence.md](./convergence.md), "Eligibility") and, when their source epoch is also older than the retained
  anchor, are reported as `BeyondAnchor`.

The category names in parentheses are the shared outcomes in [../foundation/errors.md](../foundation/errors.md).

Stale input MUST NOT mutate canonical group state.

## Application-visible output

Inbound processing can produce two kinds of output for the application:

- state notifications, when canonical group state changes or a retained decision becomes visible;
- delivered app payloads, when an MLS application message is accepted on the selected branch.

State notifications include events such as:

- group joined;
- epoch advanced;
- member added or removed;
- component state changed;
- branch recovered;
- app payload invalidated because its MLS application message belonged only to a losing branch.

A state notification is not a delivered app payload. It tells the application what changed in the group state.

## Delivered app payloads

An MLS application message is an input to convergence. A delivered app payload is the output handed to the application
after that input is accepted.

A Marmot app payload is delivered only if its MLS application message decrypts on the selected branch and remains inside
the retained app-payload window.

A Marmot app payload whose MLS application message decrypts only on a losing branch MUST be reported as invalidated, not
delivered as accepted application output.
