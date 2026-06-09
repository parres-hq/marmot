# Encrypted Media

Status: draft for internal review.

Encrypted media lets a Marmot app payload refer to one or more encrypted blobs stored outside the MLS message.

This feature is for message-attached files: images, videos, audio, documents, and other binary attachments. Group
profile images are separate and remain owned by their own group image or avatar components.

## Surfaces

- App component: `marmot.group.encrypted-media.v1` owns the group media policy.
- MLS protocol: media key material comes from `SafeExportSecret(0x8008)`.
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
Clients need that epoch to select the correct `SafeExportSecret(0x8008)`.

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

`encrypted-media-v1` uses the group component secret for the message source epoch:

```text
media_secret = SafeExportSecret(0x8008, source_epoch)
file_key     = HKDF-Expand(media_secret,
                           "encrypted-media-v1" || 0x00 || plaintext_sha256_bytes ||
                           0x00 || media_type || 0x00 || filename ||
                           0x00 || "key",
                           32)
nonce        = random(12)
```

`media_secret` is key material. Clients MUST NOT publish, transmit, log, or expose it in diagnostics. Clients SHOULD
cache source-epoch media secrets only in encrypted local account storage.

## Encryption

`encrypted-media-v1` uses ChaCha20-Poly1305.

```text
aad = "encrypted-media-v1" || 0x00 || plaintext_sha256_bytes || 0x00 || media_type || 0x00 || filename
encrypted_content = ChaCha20-Poly1305.encrypt(file_key, nonce, plaintext, aad)
```

`plaintext_sha256` is the SHA-256 hash of the original plaintext file. `ciphertext_sha256` is the SHA-256 hash of the
encrypted content and is the preferred content id for blob storage.

## Validation

A receiver MUST reject an encrypted media reference if:

- the `imeta` tag cannot be decoded
- the version is absent or not `encrypted-media-v1`
- any legacy media version string is present
- no locator is present
- a locator kind is malformed or not allowed by the group policy
- required MIME type, filename, ciphertext hash, plaintext hash, nonce, or version fields are missing
- `ciphertext_sha256` or `plaintext_sha256` is not a 32-byte hex SHA-256 value
- `nonce` is not exactly 12 bytes encoded as 24 hex characters
- `blurhash` is present
- the fetched encrypted bytes do not match `ciphertext_sha256`
- decryption fails
- the plaintext SHA-256 does not match `plaintext_sha256`
- the decrypted media type or size violates application policy
