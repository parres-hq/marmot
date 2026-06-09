# marmot.group.encrypted-media.v1

Status: draft for internal review.

## Registry

- Component id: `0x8008`
- Name: `marmot.group.encrypted-media.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required for new app groups under a media-capable application profile; optional otherwise
- Owning feature: [encrypted-media.md](../features/encrypted-media.md)

## State

The component state is a full media policy replacement. It uses the Marmot binary profile
([../foundation/canonical-encoding.md](../foundation/canonical-encoding.md)); `allowed_locator_kinds` and
`default_blob_endpoints` are `Type items<V>` vectors (a QUIC variable-length byte length followed by the concatenated
items):

```text
struct {
  opaque locator_kind<V>;
} MediaLocatorKindV1;

struct {
  opaque locator_kind<V>;
  opaque base_url<V>;
} BlobStoreEndpointV1;

struct {
  opaque              media_format<V>;
  MediaLocatorKindV1  allowed_locator_kinds<V>;
  BlobStoreEndpointV1 default_blob_endpoints<V>;
} EncryptedMediaPolicyV1;
```

`media_format` MUST be `encrypted-media-v1`.

`allowed_locator_kinds` is the list of locator kinds that media messages MAY use. The initial v1 locator kind is
`blossom-v1`.

`default_blob_endpoints` is the fallback list for upload and fetch. Each endpoint carries the locator kind it serves and
a normalized base URL.

Both lists are ordered, and their order is part of the canonical component state. For `default_blob_endpoints` the
order is the upload/fetch fallback priority, so it is semantically significant and MUST NOT be reordered. Encoders
preserve the producer's order for both lists; unlike `relays` in `marmot.transport.nostr.routing.v1` and `admins` in
`marmot.group.admin-policy.v1`, these lists are NOT sorted. Two policies that differ only in order are different
canonical values.

The default test/reference policy uses:

```text
media_format = "encrypted-media-v1"
allowed_locator_kinds = ["blossom-v1"]
default_blob_endpoints = [{ locator_kind = "blossom-v1", base_url = "https://blossom.primal.net" }]
```

## Update

The update payload is a full replacement `EncryptedMediaPolicyV1`.

Endpoint updates are group-state updates. They are not message metadata and do not rewrite existing media references.

## Validation

A policy state is valid if:

- `media_format` is exactly `encrypted-media-v1`
- every locator kind is non-empty UTF-8, contains no whitespace, and is at most 64 bytes
- `allowed_locator_kinds` is non-empty and contains at most 16 unique entries
- `default_blob_endpoints` is non-empty and contains at most 16 unique entries
- every endpoint locator kind appears in `allowed_locator_kinds`
- every production endpoint is normalized HTTPS
- loopback HTTP endpoints are valid only through explicit dev/test configuration
- endpoints with userinfo, fragments, missing hosts, or non-routable non-loopback hosts are invalid

## Authorization

Any current member MAY send a standalone encrypted-media policy update proposal.

Only a current admin MAY commit an encrypted-media policy update. The admin check is evaluated against the prior epoch
state.

## Removal

This component MUST NOT be removed while it is listed as required in GroupContext `app_components`. Under a media-capable
application profile it is required for new app groups, so removing it from such a group is invalid (see
[../protocol-core/group-setup.md](../protocol-core/group-setup.md)). A group whose profile does not require encrypted
media MAY omit it.

## Migration

This component is new in v2; it carries the Encrypted Media V1 group policy (see [../mip-coverage.md](../mip-coverage.md)).
The media attachment format and key derivation are owned by [../features/encrypted-media.md](../features/encrypted-media.md).
v1 is the first versioned form; a breaking change gets a new component id and file.
