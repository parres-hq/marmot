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
- the host MUST NOT be unsafe per [../foundation/host-safety.md](../foundation/host-safety.md): not `localhost` or a
  `.localhost` name, and not an IP literal in the unsafe IPv4 or IPv6 ranges (loopback, private, CGNAT, link-local,
  unspecified, documentation, benchmarking, reserved/broadcast, multicast, ULA, or an IPv6 transition prefix). Unlike
  the encrypted-media endpoint, an avatar URL has no loopback exception — the scheme is `https`-only and loopback is
  unsafe

The producer normalizes the URL before encoding and stores the normalized form. Normalization is defined by the
[WHATWG URL Standard](https://url.spec.whatwg.org/): the producer parses the URL and serializes the parse result as
that standard specifies, and stores the serializer's output bytes.

The WHATWG standard is the normative definition; the effects below are orientation, not an exhaustive list. WHATWG
serialization lowercases the scheme and host, removes the scheme's default port (`443` for `https`), resolves
dot-segments in the path, serializes an empty path as `/`, normalizes percent-encoding, and encodes non-ASCII hosts
with IDNA (punycode). A URL with a fragment or userinfo is invalid regardless, per the rules above.

Per [../foundation/canonical-encoding.md](../foundation/canonical-encoding.md) ("Canonical decoding"), normalization is
a producer-side encoding rule. A decoder re-runs validation and the WHATWG parse-and-serialize on the decoded `url`
and MUST reject state whose stored URL bytes differ from the serializer's output. A decoder never repairs a
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

Only an active admin MAY commit an avatar update.

## Removal

Removal is equivalent to the empty avatar state for application rendering.

## Migration

This component is new in v2 and has no MIP-era predecessor. v1 is the first versioned form; a breaking change gets a new
component id and file.
