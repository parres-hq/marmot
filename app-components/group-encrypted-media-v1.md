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
- every locator kind is 1..64 bytes and contains only lowercase ASCII letters (`a-z`), digits (`0-9`), and `-`
- `allowed_locator_kinds` is non-empty and contains at most 16 unique entries
- `default_blob_endpoints` is non-empty and contains at most 16 unique entries
- every endpoint locator kind appears in `allowed_locator_kinds`
- every endpoint base URL is a normalized `https` URL, or a normalized `http` URL whose host is loopback
- endpoints with userinfo, fragments, or missing hosts are invalid
- an endpoint whose host is unsafe per [../foundation/host-safety.md](../foundation/host-safety.md) is invalid, with the
  single exception of a loopback host (which carries the `http`-to-loopback dev/test endpoint allowed above); every other
  range in the unsafe-host set — private, CGNAT, link-local, documentation, benchmarking, reserved, multicast, and the
  IPv6 transition prefixes — makes the endpoint invalid

A base URL is normalized when it is byte-equal to its own parse-and-serialize output under the
[WHATWG URL Standard](https://url.spec.whatwg.org/) — the same normalization
[group-avatar-url-v1.md](group-avatar-url-v1.md) defines for avatar URLs.

State bytes MUST be canonical per [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md)
("Canonical decoding"): a decoder rejects state whose bytes differ from the canonical re-encoding of the decoded value
and MUST NOT trim, case-fold, normalize, or deduplicate a value while decoding it. List order and uniqueness are
producer-side rules; a decoder rejects a duplicate entry rather than removing it, and rejects a non-normalized URL or
locator kind rather than repairing it.

Component-state validity is the same for every member. An endpoint with scheme `http` and a loopback host is valid
state, and validators MUST accept it, so commit validity never depends on local configuration.

Whether a client acts on such an endpoint is a separate, local rule: a client MUST NOT upload to or download from a
loopback HTTP endpoint unless it is explicitly configured for development or testing. In a production configuration
those endpoints are unusable, and attachments that rely on them are unfetchable.

## Authorization

Any current member MAY send a standalone encrypted-media policy update proposal.

Only an active admin MAY commit an encrypted-media policy update. The admin check is evaluated against the prior epoch
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
