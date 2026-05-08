# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## Unreleased

### Breaking changes

- **Extension v3 — disappearing messages**: Marmot Group Data Extension bumped from v2 to v3, adding `disappearing_message_secs` field. Kind:445 senders MUST auto-apply a NIP-40 `expiration` tag (computed from the inner rumor's `created_at`) when the group has a nonzero duration. Implementations MUST strip caller-supplied expiration tags when the group does not enable disappearing messages. ([MIP-01](01.md), [MIP-03](03.md))
- **Encoding format**: KeyPackage (kind:443) and Welcome (kind:444) events now require base64 encoding for the `content` field. The `encoding` tag MUST be `["encoding", "base64"]`. Hex encoding was used by early implementations but is no longer supported. Implementations MUST reject events with missing or non-base64 `encoding` tags.
- **KeyPackage migration**: `kind:30443` is now the canonical KeyPackage format. The Marmot rollout plan, including the May 1, 2026, at 00:00:00 UTC cutover guidance, is documented in [docs/migrations/2026-05-01-kind-30443-cutover.md](docs/migrations/2026-05-01-kind-30443-cutover.md).
- **MIP-05 token size**: `EncryptedToken` expanded from 280 to 1084 bytes (`TokenPlaintext` from 220 to 1024 bytes) to accommodate larger FCM tokens and future UnifiedPush support. Platform-specific `token_length` validation replaced with a universal range of 1–1021. Batch recommendation lowered from 100 to 25 tokens per `kind:446` event.

### Changed

- **Encrypted media previews**: [MIP-04](04.md) now documents optional `thumbhash` `imeta` tags alongside `blurhash`, recommends emitting `thumbhash` in new implementations, requires receivers to parse both preview hash fields, and notes that `blurhash` remains only for backward compatibility in this version. ([#64](https://github.com/marmot-protocol/marmot/pull/64))

### Added

- **Threat model T.3.6**: New threat entry for disappearing-message non-compliance — a member's client ignoring local deletion timers. ([threat_model.md](threat_model.md))

### Fixed

- **MIP-01 HKDF hash function and input encoding**: [MIP-01](01.md) now explicitly specifies **HKDF-SHA256** for all image encryption key and upload keypair derivations (v1 and v2), and pins canonical encoding of HKDF inputs: `salt` is the empty octet string (zero bytes, length 0, NOT a null/None value or RFC 5869's HashLen-zeros default), `info` labels are UTF-8 bytes with no terminator or length prefix. Previously the hash was unspecified and `salt=None` was ambiguous across crypto libraries, both producing different PRKs across implementations and breaking interoperability. Aligns with the mandatory MLS ciphersuite `0x0001`. ([#51](https://github.com/marmot-protocol/marmot-security/issues/51))

### Removed

### Deprecated
