# Encrypted Media

Status: draft for internal review.

Encrypted media lets a Marmot app payload refer to one or more encrypted blobs stored outside the MLS message.

This feature is for message-attached files: images, videos, audio, documents, and other binary attachments. Group
profile images are separate and remain owned by their own group image or avatar components.

## Surfaces

- App component: `marmot.group.encrypted-media.v1` owns the group media policy.
- MLS protocol: media key material comes from `MLS-Exporter("marmot", "encrypted-media", 32)`.
- App payload: kind-9 chat messages carry ordered NIP-92-style `imeta` tags.
- Blob storage: locators identify upload/fetch backends. Blossom is the first reference locator kind.

Blob upload and download are outside MLS group state. A failed upload or failed fetch does not change the group epoch.

## Current Version

The current media format is `encrypted-media-v1`.

New media references MUST use `encrypted-media-v1`. Legacy media version strings are not compatibility formats in this
draft and MUST be rejected by V1 clients.

## Message Shape

Media messages are regular Marmot kind-9 chat app events.

- `content` is the message-level caption.
- each attachment is one ordered `imeta` tag.
- a message MAY contain multiple `imeta` tags.
- per-attachment captions are out of scope for v1.

A V1 attachment `imeta` tag contains:

- `v encrypted-media-v1`
- one or more `locator <kind> <value>` fields
- `ciphertext_sha256 <hex>`
- `plaintext_sha256 <hex>`
- `nonce <24-hex-chars>`
- `m <canonical media type>`
- `filename <display filename>`
- optional `dim <width>x<height>` for render hints
- optional `thumbhash <value>` for previews

`blurhash` is invalid in `encrypted-media-v1`.

The source epoch is not an `imeta` field. It is the MLS epoch of the application message that carried the media tag.
Clients need that epoch to select the correct media exporter secret.

## Locator Kinds

`blossom-v1` is the initial locator kind.

For Blossom, `locator blossom-v1 <value>` stores an encrypted blob URL. Clients SHOULD verify that any content hash
encoded in the locator URL matches `ciphertext_sha256`.

The group component's `default_blob_endpoints` list supplies ordered fallback endpoints. A client MAY try explicit
locators first, then construct backend-specific fallback fetch URLs from the default endpoints and `ciphertext_sha256`.

The protocol is not Blossom-specific. Additional locator kinds require component policy support and backend-specific
upload/fetch rules.

## Media Type Canonicalization

The MIME type is canonicalized before it is used in key derivation and as AAD:

1. take the substring before the first `;`, dropping any parameters
2. trim leading and trailing ASCII whitespace
3. lowercase using ASCII case folding only
4. reject the reference if the result is empty or does not contain `/`
5. apply the canonical alias `image/jpg` -> `image/jpeg`

Sender and receiver MUST apply this identical algorithm. Adding an alias or normalization step is a breaking
media-version change.

## Key Derivation

`encrypted-media-v1` uses the group media exporter secret for the message source epoch:

```text
media_secret = MLS-Exporter("marmot", "encrypted-media", 32) at source_epoch
file_key     = HKDF-Expand(media_secret,
                           "encrypted-media-v1" || 0x00 || plaintext_sha256_bytes ||
                           0x00 || media_type || 0x00 || filename ||
                           0x00 || "key",
                           32)
```

HKDF is HKDF-SHA256. `media_secret` is used directly as the HKDF PRK (Expand only, no Extract step). This choice is
fixed and independent of the group's MLS ciphersuite; only the `MLS-Exporter` line is computed with the ciphersuite's
own hash, as MLS defines. The info bytes are exactly the concatenation shown: fields joined by single `0x00` separator
bytes, with no length prefixes.

`media_secret` is key material. Clients MUST NOT publish, transmit, log, or expose it in diagnostics. Clients SHOULD
protect cached source-epoch media secrets at rest with confidentiality controls appropriate to the platform. Clients
SHOULD retain recent epoch media secrets long enough to decrypt delayed media references according to local retention
policy. If a past-epoch media secret is no longer available, media from that epoch cannot be decrypted.

## Encryption

`encrypted-media-v1` uses ChaCha20-Poly1305.

```text
nonce             = random(12)
aad               = "encrypted-media-v1" || 0x00 || plaintext_sha256_bytes || 0x00 || media_type || 0x00 || filename
encrypted_content = ChaCha20-Poly1305.encrypt(file_key, nonce, plaintext, aad)
```

The AAD bytes are exactly the concatenation shown, with the same single `0x00` separators and no length prefixes.

`plaintext_sha256` is the SHA-256 hash of the original plaintext file. `ciphertext_sha256` is the SHA-256 hash of the
encrypted content and is the preferred content id for blob storage.

## Validation

A receiver MUST reject (invalidate) an encrypted media reference ONLY for structural-integrity or host-safety reasons. A
receiver MUST reject a reference if:

- the `imeta` tag cannot be decoded
- the version is absent or not `encrypted-media-v1`
- any legacy media version string is present
- no locator is present
- a locator has an empty kind or an empty value, or its value does not parse as a URL
- a `blossom-v1` locator points at an unsafe host per [../foundation/host-safety.md](../foundation/host-safety.md)
  (loopback, private, CGNAT, link-local, unspecified, documentation, benchmarking, reserved/broadcast, multicast, ULA,
  or an IPv6 transition prefix with an unsafe embedded address), or uses cleartext `http` to a non-loopback host (host
  safety; see below)
- required MIME type, filename, ciphertext hash, plaintext hash, nonce, or version fields are missing
- a single-occurrence field appears more than once in the `imeta` tag. Exactly the `locator` field repeats (one or
  more); every other field — `v`, `ciphertext_sha256`, `plaintext_sha256`, `nonce`, `m`, `filename`, `dim`, and
  `thumbhash` — occurs at most once. A receiver MUST reject a duplicate rather than picking a first or last occurrence,
  because `m`, `filename`, and `plaintext_sha256` feed the `file_key` derivation and the AEAD AAD: a first-wins decoder
  and a last-wins decoder would otherwise derive different keys for the same authenticated tag
- `ciphertext_sha256` or `plaintext_sha256` is not a 32-byte hex SHA-256 value
- `nonce` is not exactly 12 bytes encoded as 24 hex characters
- `blurhash` is present
- the fetched encrypted bytes do not match `ciphertext_sha256`
- decryption fails
- the plaintext SHA-256 does not match `plaintext_sha256`
- the decrypted media type or size violates application policy

A locator kind is NOT a validity condition. A well-formed locator whose kind is not in the group's
`marmot.group.encrypted-media.v1` `allowed_locator_kinds`, or whose kind the receiving client does not support, makes
that locator UNFETCHABLE: the client skips it, and the attachment is unfetchable if no usable locator or fallback
endpoint remains. An out-of-policy or unsupported locator MUST NOT invalidate the media reference and MUST NOT
invalidate or drop the containing message. The rationale is that media content is authenticated by its
`ciphertext_sha256` / `plaintext_sha256` and the AEAD independent of the locator, so an out-of-policy or otherwise wrong
locator cannot forge content; only the structural conditions above protect integrity.

Host safety is the one locator property that DOES invalidate, and it applies only to `blossom-v1` locators — the kind
this client fetches over HTTP. An unsafe-host or cleartext-`http` Blossom locator is a hostile request vector: unlike a
wrong kind, the harm is the fetch request itself (an attempt to make the client reach a private or internal address),
which content hash-authentication cannot neutralize, so such a reference is rejected and its message dropped. A
non-Blossom locator is never fetched by this client, so it is subject only to the structural checks and is otherwise
merely unfetchable per the rule above.

Fetchability is judged at fetch time against the group's current `allowed_locator_kinds` and the receiving client's
current support and configuration, not against the source epoch. Because the locator policy no longer gates delivery,
validation needs no source-epoch policy snapshot. (This supersedes the earlier rule that a locator whose kind is outside
the group policy makes the media reference invalid.)
