# marmot.group.blossom.image.v1

Status: draft for internal review.

## Registry

- Component id: `0x8002`
- Name: `marmot.group.blossom.image.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional

This component is for encrypted group images stored through Blossom. It is not the generic group-image model for every
possible image reference.

A group that wants to reference a plain URL, an IPFS object, an application-owned CDN object, or another blob store
SHOULD use a different component. In particular, [`marmot.group.avatar-url.v1`](group-avatar-url-v1.md) is the
plain-`https` alternative. A group MAY carry both components at once; when both are present, the URL avatar wins for
rendering. [`group-avatar-url-v1.md`](group-avatar-url-v1.md) ("Coexistence and precedence") owns that precedence rule.

## State

```text
struct {
  opaque image_hash<0..32>;
  opaque image_key<0..32>;
  opaque image_nonce<0..12>;
  opaque image_upload_key<0..32>;
  opaque media_type<0..128>;
} MarmotGroupBlossomImageV1;
```

An absent image is encoded as all fields empty.

When an image is present:

- `image_hash` is exactly 32 bytes
- `image_key` is exactly 32 bytes
- `image_nonce` is exactly 12 bytes
- `image_upload_key` is exactly 32 bytes. It is the secret a client uses to authorize the Blossom upload/replace of
  this blob (the Blossom server-side write credential for the image). It is not the content-decryption key; that is
  `image_key`.
- `media_type` is non-empty valid UTF-8, at most 128 bytes, and names the encrypted image media type

The component stores the cryptographic metadata clients need for a Blossom-backed image. It does not define the Blossom
upload or download request flow, server selection, relay behavior, or CDN behavior.

## Update

The update payload is a full replacement state:

```text
MarmotGroupBlossomImageV1 MarmotGroupBlossomImageUpdateV1;
```

Updating the image replaces every field. Clearing the image sends the empty state.

## Validation

A non-empty image state is valid only if all cryptographic fields have their exact required lengths.

Mixed partial states are invalid. For example, a state with `image_hash` set and `image_key` empty is invalid.

## Authorization

Any current member MAY send a standalone image update proposal.

Only a current admin MAY commit an image update.

## Removal

Removal is equivalent to the empty image state for application rendering.

## Migration

This component carries the `image_hash`, `image_key`, `image_nonce`, and `image_upload_key` fields from the MIP-01
`marmot_group_data` extension (see [../mip-coverage.md](../mip-coverage.md)), plus `media_type`. v1 is the first
versioned form; a breaking change gets a new component id and file.
