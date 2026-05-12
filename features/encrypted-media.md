# Encrypted media

Status: sketch.

Encrypted media lets a Marmot app payload refer to an encrypted blob stored outside the MLS message.

This feature is for chat media and other message-attached files. Group profile images are separate. The current
Blossom-backed group image component is `marmot.group.blossom.image.v1`.

## Surfaces

- Foundation: Marmot app payload shape.
- MLS protocol: exporter-derived secret or a future component-scoped safe exporter.
- App payload: media reference event kind and tags.
- Blob storage: upload and fetch backend.

No persistent group app component is required for encrypted media v1.

## Behavior

The sender encrypts the file before upload, publishes the encrypted blob to a blob backend, and sends a Marmot app event
that contains the reference and decryption metadata.

The receiver reads the app event, fetches the encrypted blob, derives the media key, decrypts the bytes, and validates
the referenced hash or content id before handing the file to the application.

Blob upload and download are outside MLS group state. A failed upload or failed fetch does not change the group epoch.

## Blob-store boundary

Blossom is the current blob backend. The encrypted media feature should define the encrypted blob and reference format
in a way that can support another blob backend later.

A Blossom-specific reference can be one supported reference type. It should not be the only possible media reference
model.

## Key derivation

The MIP-era feature derives media key material from the MLS exporter label registered as `"marmot" / "encrypted-media"`,
then uses file metadata to derive the per-file key.

This draft needs to settle whether encrypted media continues to use that raw exporter label or moves to an MLS
component-scoped safe exporter.

## Validation

A receiver MUST reject an encrypted media reference if:

- the media reference cannot be decoded;
- required hash, nonce, or key-derivation fields are missing;
- the fetched encrypted bytes do not match the referenced hash or content id;
- decryption fails;
- the decrypted media type or size violates the owning message-kind rules.

## Migration notes

MIP-04 should become this feature doc plus one or more exact app-payload schemas. Blob-backend-specific details should
live in the payload reference format or a blob-backend subsection.
