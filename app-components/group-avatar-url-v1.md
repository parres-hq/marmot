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
- `dim` is an optional opaque render hint (see Validation). By convention a producer emits UTF-8 `WIDTHxHEIGHT`
  (for example `512x512`), but the bytes are not interpreted at decode
- `thumbhash` is an optional opaque render hint with the same decode rule. By convention a producer emits a UTF-8
  ThumbHash string; this component deliberately uses ThumbHash, not BlurHash

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

The producer normalizes the URL before encoding and stores the normalized form. Normalization is exactly these steps,
in order:

1. lowercase the scheme
2. lowercase the host
3. remove the port if it is the scheme's default (`443` for `https`)
4. apply RFC 3986 dot-segment removal to the path

Normalization changes nothing else: percent-encodings, the query, and all other bytes are left untouched. A URL with a
fragment or userinfo is invalid regardless, per the rules above.

Per [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md) ("Canonical decoding"), normalization is
a producer-side encoding rule. A decoder re-runs validation and normalization on the decoded `url` and MUST reject
state whose stored URL bytes differ from the bytes produced by re-normalizing them. A decoder never repairs a
non-normalized URL into canonical state.

`dim` and `thumbhash` are opaque hints per [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md)
("Canonical decoding"): a decoder validates only their 256-byte length bounds. Interpreting the bytes — as UTF-8 text,
or `dim` as a width-by-height pair — happens at render time. A hint the renderer cannot interpret is treated as absent
and MUST NOT invalidate otherwise-valid group state. A producer SHOULD only emit hints it can populate.

## Coexistence and precedence

A group MAY carry both this component and `marmot.group.blossom.image.v1` at the same time. When both are present, the
URL avatar wins: a renderer SHOULD show the `marmot.group.avatar-url.v1` avatar and ignore the Blossom image. Clearing
this component (empty state) falls back to the Blossom image if one is present.

## Authorization

Any current member MAY send a standalone avatar update proposal.

Only a current admin MAY commit an avatar update.

## Removal

Removal is equivalent to the empty avatar state for application rendering.

## Migration

This component is new in v2 and has no MIP-era predecessor. v1 is the first versioned form; a breaking change gets a new
component id and file.
