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

- **Encoding format**: KeyPackage (kind:443) and Welcome (kind:444) events now require base64 encoding for the `content` field. The `encoding` tag MUST be `["encoding", "base64"]`. Hex encoding was used by early implementations but is no longer supported. Implementations MUST reject events with missing or non-base64 `encoding` tags.

### Changed

### Added

### Fixed

### Removed

### Deprecated
