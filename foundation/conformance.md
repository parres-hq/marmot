# Conformance state equivalence

Status: adopted.

This document defines the protocol-state projection used to compare Marmot clients in deterministic conformance tests.
It defines equality over protocol meaning, not equality over implementation storage.

## Canonical snapshot

A conformance snapshot for one group contains:

- the raw MLS group id;
- the MLS epoch;
- `SHA256` of the TLS-serialized MLS `GroupContext`;
- the exporter commitment defined below;
- every nonblank leaf in leaf-index order, including its leaf index, Marmot account identity, MLS signature public key,
  and advertised capabilities;
- the group-required capabilities;
- every `GroupContext.extensions.app_data_dictionary` entry in ascending component-id order, including the exact
  component value bytes;
- the canonical group lifecycle and current convergence status;
- the current convergence disposition of every scenario input known to the client, keyed by a stable synthetic
  scenario name rather than transport metadata; and
- application-visible outputs, state changes, and invalidations produced for the scenario.

Two clients have equivalent canonical protocol state when every applicable field above is equal. Full scenario
quiescence additionally requires that neither client has an unresolved convergence pass or required publication.

Local queue layout, transport cursors, retry counters, database row ids, storage encoding, pruned secrets, and private
ratchet state are not part of canonical protocol-state equality. A test MAY compare those as separate availability,
resource, or implementation assertions.

This projection is a conformance-test interface. It defines no wire message, group extension, or interoperable
serialization.

## Exporter commitment

The conformance exporter secret is:

```text
MLS-Exporter("marmot", "convergence-conformance-v1", 32)
```

The snapshot contains only this commitment:

```text
SHA256(
  "marmot-convergence-conformance-v1" ||
  0x00 ||
  conformance_exporter_secret
)
```

The domain string before `0x00` is exactly 33 ASCII bytes. The raw exporter secret MUST NOT appear in logs, reports, or
test artifacts. The commitment is limited to synthetic conformance tests and local forensic comparison; production
telemetry MUST NOT export it.
