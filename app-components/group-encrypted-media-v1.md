# marmot.group.encrypted-media.v1

Status: draft for internal review.

## Registry

- Component id: `0x8008`
- Name: `marmot.group.encrypted-media.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: required for newly created app groups

## State

The component state is a full media policy replacement encoded as three component vectors:

```text
struct {
  opaque media_format<V>;
  opaque allowed_locator_kinds<V>;      // vector of opaque locator_kind<V>
  opaque default_blob_endpoints<V>;     // vector of BlobStoreEndpointV1
} EncryptedMediaPolicyV1;

struct {
  opaque locator_kind<V>;
  opaque base_url<V>;
} BlobStoreEndpointV1;
```

`media_format` MUST be `encrypted-media-v1`.

`allowed_locator_kinds` is the ordered set of locator kinds that media messages MAY use. The initial v1 locator kind is
`blossom-v1`.

`default_blob_endpoints` is an ordered fallback list for upload and fetch. Each endpoint carries the locator kind it
serves and a normalized base URL. The default test/reference policy uses:

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

Only a current admin MAY commit an encrypted-media policy update.

The admin check is evaluated against the prior epoch state.

## Removal

New app groups require this component. Removing a required encrypted-media component is invalid.
