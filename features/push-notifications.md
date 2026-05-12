# Push notifications

Status: sketch.

Push notifications let a sender give a recipient a delivery hint outside the normal group-message fetch path.

Push notification support is optional. A group must still work when no client supports push notifications.

## Surfaces

- App payload: notification-related message kinds, if any.
- Transport: Nostr push notification rumor kind `446` for the current Nostr binding.
- State machine: no group-state transition.

No persistent group app component is required for push notifications v1.

## Behavior

A push notification hint may tell a recipient that new encrypted group content is available. It MUST NOT carry message
plaintext, media plaintext, MLS secrets, exporter output, or group-state-changing bytes.

Receiving or missing a push notification does not affect group state. The recipient still fetches and processes the
normal Marmot transport messages.

## Nostr binding

The current MIP-era Nostr binding reserves kind `446` for push notification rumors.

This draft still needs the exact kind `446` shape before this feature can become normative.

## Validation

A client MUST treat malformed push notification data as advisory failure. It must not reject valid group messages
because a related push hint was missing, delayed, duplicated, or malformed.

## Migration notes

MIP-05 should become this feature doc plus a transport-specific Nostr push notification shape.
