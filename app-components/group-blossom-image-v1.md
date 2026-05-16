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
should use a different component.

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
- `image_upload_key` is exactly 32 bytes
- `media_type` is valid UTF-8 and names the encrypted image media type

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

Any current member may send a standalone image update proposal.

Only a current admin may commit an image update.

An inline image update requires the sender to be a current admin because the proposal sender and committer are the same
member.

## Removal

Removal is allowed if this component is not listed as required in the GroupContext `app_components` component.

Removal is equivalent to the empty image state for application rendering.
