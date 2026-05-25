# Encrypted media

Status: draft for internal review.

Encrypted media lets a Marmot app payload refer to an encrypted blob stored outside the MLS message.

This feature is for chat media and other message-attached files. Group profile images are separate. The current
Blossom-backed group image component is `marmot.group.blossom.image.v1`.

## Surfaces

- Foundation: Marmot app payload shape.
- MLS protocol: raw MLS exporter label.
- App payload: media reference event kind and tags.
- Blob storage: upload and fetch backend.

Encrypted media does not currently allocate an app component. The current design intentionally follows the audited
MIP-04 shape and derives media keys from a raw MLS exporter label.

## Behavior

The sender encrypts the file before upload, publishes the encrypted blob to a blob backend, and sends a Marmot app event
that contains the reference and decryption metadata.

The receiver reads the app event, fetches the encrypted blob, derives the media key, decrypts the bytes, and validates
the referenced hash or content id before handing the file to the application.

Blob upload and download are outside MLS group state. A failed upload or failed fetch does not change the group epoch.

## Current version

The current MIP-era media version is `mip04-v2`.

New media references MUST use `mip04-v2`. Version `mip04-v1` used deterministic nonce derivation and MUST NOT be used
for new media.

The media reference is currently carried in NIP-92-style `imeta` tags inside an inner Marmot app event. A `mip04-v2`
reference includes:

- `url`: encrypted blob URL;
- `m`: canonical MIME type;
- `filename`: original display filename;
- `x`: SHA-256 hash of the original plaintext file, hex encoded;
- `n`: random 12-byte encryption nonce, hex encoded as 24 characters;
- `v`: `mip04-v2`;
- optional preview fields such as `dim`, `thumbhash`, and `blurhash`.

## Key derivation

The current feature derives media key material from the registered MIP-04 MLS exporter label.

For `mip04-v2`:

```text
media_secret = MLS-Exporter("marmot", "encrypted-media", 32)
file_key     = HKDF-Expand(media_secret,
                           "mip04-v2" || 0x00 || file_hash ||
                           0x00 || mime_type || 0x00 || filename ||
                           0x00 || "key",
                           32)
nonce        = random(12)
```

The MIME type is canonicalized before it is used in key derivation and as AAD, using these exact steps:

1. take the substring before the first `;`, dropping any parameters;
2. trim leading and trailing ASCII whitespace;
3. lowercase using ASCII case folding only, never Unicode case folding;
4. reject the reference if the result is empty or does not contain `/`;
5. apply the canonical alias `image/jpg` -> `image/jpeg`; `mip04-v2` defines no other aliases.

Sender and receiver MUST apply this identical algorithm. Any divergence changes `file_key` and `aad` and makes
decryption fail, so adding an alias or normalization step is a breaking media-version change, not a compatible tweak.

The media exporter output is key material. Clients MUST NOT publish, transmit, log, or surface it in diagnostics.

## Encryption

`mip04-v2` uses ChaCha20-Poly1305.

```text
aad = "mip04-v2" || 0x00 || file_hash || 0x00 || mime_type || 0x00 || filename
encrypted_content = ChaCha20-Poly1305.encrypt(file_key, nonce, plaintext, aad)
```

The `x` field is the hash of the original plaintext file. Storage systems MAY address the encrypted blob by
`SHA-256(encrypted_content)`.

## Blob-store boundary

Blossom is the current reference blob backend. The encrypted media feature defines encrypted blob behavior and media
metadata, while the blob backend defines upload, fetch, deletion, and URL rules.

A Blossom-specific reference can be one supported reference type. It SHOULD NOT be the only possible media reference
model.

## Validation

A receiver MUST reject an encrypted media reference if:

- the media reference cannot be decoded;
- the version is absent or unsupported;
- the version is `mip04-v1`;
- required URL, MIME type, filename, plaintext hash, nonce, or version fields are missing;
- the `n` field is not exactly a 12-byte nonce encoded as 24 hex characters;
- the fetched encrypted bytes do not match the referenced hash or content id;
- decryption fails;
- the plaintext SHA-256 does not match the `x` field;
- the decrypted media type or size violates the owning message-kind rules.

## Migration notes

MIP-04 SHOULD become this feature doc plus one or more exact app-payload schemas. Blob-backend-specific details SHOULD
live in the payload reference format or a blob-backend subsection.

A migration from raw MLS exporter labels to `SafeExportSecret(ComponentID)` is deferred until the protocol specifies
durable download behavior across app restarts and group epoch changes.
