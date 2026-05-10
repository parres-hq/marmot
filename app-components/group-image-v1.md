# marmot.group.image.v1

Status: sketch.

## Registry

- Component id: `0x8002`
- Name: `marmot.group.image.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional
- Replaces: `marmot_group_data.image_hash`, `image_key`, `image_nonce`,
  `image_upload_key`

## State

```text
struct {
  opaque image_hash<0..32>;
  opaque image_key<0..32>;
  opaque image_nonce<0..12>;
  opaque image_upload_key<0..32>;
  opaque media_type<0..128>;
} MarmotGroupImageV1;
```

An absent image is encoded as all fields empty.

When an image is present:

- `image_hash` is exactly 32 bytes
- `image_key` is exactly 32 bytes
- `image_nonce` is exactly 12 bytes
- `image_upload_key` is exactly 32 bytes
- `media_type` is valid UTF-8 and names the encrypted image media type

The component stores cryptographic metadata for the image. It does not define
transport upload, download, relay, or CDN behavior.

## Update

The update payload is a full replacement state:

```text
MarmotGroupImageV1 MarmotGroupImageUpdateV1;
```

Updating the image replaces every field. Clearing the image sends the empty
state.

## Validation

A non-empty image state is valid only if all cryptographic fields have their
exact required lengths.

Mixed partial states are invalid. For example, a state with `image_hash` set and
`image_key` empty is invalid.

## Authorization

Any current member may send a standalone image update proposal.

Only a current admin may commit an image update.

An inline image update requires the sender to be a current admin because the
proposal sender and committer are the same member.

## Removal

Removal is allowed if this component is not listed as required in the
GroupContext `app_components` component.

Removal is equivalent to the empty image state for application rendering.

## Migration

Migration from `marmot_group_data` copies image fields byte-for-byte if the
length checks pass. If every image field is empty, the component MAY be omitted.
