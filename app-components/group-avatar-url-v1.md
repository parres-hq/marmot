# marmot.group.avatar-url.v1

Status: draft for internal review.

## Registry

- Component id: `0x8007`
- Name: `marmot.group.avatar-url.v1`
- Location: GroupContext `app_data_dictionary`
- Default requirement: optional

This component references a group avatar by plain `https` URL, with optional render hints. It is the lightweight
alternative to [`marmot.group.blossom.image.v1`](group-blossom-image-v1.md), for groups that want to point at an
ordinary web image instead of an encrypted Blossom blob. It is not an encrypted-media surface and carries no key
material.

## State

```text
struct {
  opaque url<0..2048>;
  opaque dim<0..256>;
  opaque thumbhash<0..256>;
} MarmotGroupAvatarUrlV1;
```

An absent avatar is encoded with an empty `url` (all fields empty).

When an avatar is present:

- `url` is valid UTF-8, non-empty, and a normalized `https` URL (see Validation)
- `dim` is optional; when present it is a UTF-8 render hint, by convention `WIDTHxHEIGHT` (e.g. `512x512`). It is
  opaque to the protocol and is not parsed beyond its length bound
- `thumbhash` is optional; when present it is a UTF-8 ThumbHash render hint. This component deliberately uses ThumbHash,
  not BlurHash

## Update

The update payload is a full replacement state:

```text
MarmotGroupAvatarUrlV1 MarmotGroupAvatarUrlUpdateV1;
```

Updating the avatar replaces every field. Clearing the avatar sends the empty state.

## Validation

A non-empty avatar state is valid only if `url` validates and normalizes:

- the encoded `url` is at most 2048 bytes
- the scheme is `https` (clients MUST reject `http` and all other schemes)
- the URL includes a host and no userinfo (no `user:password@`) and no fragment
- the host MUST NOT be `localhost`, a `.localhost` name, or a loopback, private, link-local, unspecified, broadcast,
  documentation, or multicast IP address. Producers SHOULD reject other non-routable hosts as well
- the producer normalizes the URL (scheme/host case, default-port and path normalization) before encoding, and stores
  the normalized form. Decoders re-run validation and compare the decoded bytes

`dim` and `thumbhash` are advisory render hints; an invalid hint MUST NOT invalidate otherwise-valid group state, but a
producer SHOULD only emit hints it can populate. Both are length-bounded at 256 bytes.

## Coexistence and precedence

A group MAY carry both this component and `marmot.group.blossom.image.v1` at the same time. When both are present, the
URL avatar wins: a renderer SHOULD show the `marmot.group.avatar-url.v1` avatar and ignore the Blossom image. Clearing
this component (empty state) falls back to the Blossom image if one is present.

## Authorization

Any current member MAY send a standalone avatar update proposal.

Only a current admin MAY commit an avatar update.

## Removal

Removal is equivalent to the empty avatar state for application rendering.
