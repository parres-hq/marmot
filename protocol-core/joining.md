# Welcomes

Status: draft for internal review.

This document describes the member join flow built around MLS Welcomes.

## Surfaces

- Foundation identity and KeyPackages.
- MLS protocol: Add, Commit, Welcome, KeyPackageRef, and post-join Update.
- Protocol-core publish lifecycle.
- The active transport binding for Welcome delivery.
- The active transport routing state for post-join group traffic.

## Behavior

An inviter adds a new member by committing an MLS Add that uses the invitee's KeyPackage. The resulting group-state
change MUST be published before the inviter sends the Welcome.

For member additions after initial group creation, the inviter MUST wait for the Commit publish obligation to succeed
before sending the Welcome. Sending the Welcome first can activate the new member at an epoch existing members have not
seen yet.

Initial one-member group creation is the exception: there are no existing peers that can be forked by a missing creation
Commit.

## Delivery

The active transport binding owns the Welcome delivery envelope, recipient addressing, and transport-specific metadata.
Protocol core requires that the receiver can recover the serialized MLSMessage whose wire format is `mls_welcome` and
can identify which local KeyPackage was consumed.

The Welcome delivery envelope MUST NOT by itself choose group state. It supplies bytes and delivery evidence. MLS and
Marmot validation decide whether the receiver joins.

## Receiving flow

After unwrapping a Welcome, the receiver:

1. verifies that the Welcome is addressed to its account identity;
2. verifies that the referenced KeyPackage belongs to this account/device;
3. decodes the transport-carried content as an MLSMessage with `mls_welcome` wire format;
4. processes the MLS Welcome;
5. validates every resulting member identity and account identity proof;
6. validates the resulting Marmot group state and required components;
7. stores the group state and routing information;
8. rotates the consumed published KeyPackage when appropriate;
9. deletes consumed `init_key` material according to the KeyPackage lifecycle rules;
10. catches up on outstanding Commits as best it can;
11. performs a self-update as soon as practical.

A new member SHOULD perform the post-join self-update before sending application payloads when feasible, and SHOULD do
so promptly after joining. This carries forward the MIP-02 post-join rotation guidance; the v2 draft keeps it as a
`SHOULD` because a member who never rotates is a forward-secrecy weakness for itself, not a correctness break for the
group. The concrete recommended completion window is operational, not interop-visible, so it lives in
[../implementation-model.md](../implementation-model.md) rather than here.

## Failure behavior

If Welcome processing fails, the receiver MUST NOT rotate away the KeyPackage that was referenced by the failed Welcome.
The inviter MAY retry or choose another KeyPackage.

A receiver rejects the Welcome if:

- transport unwrapping fails;
- the Welcome is not addressed to the local account identity;
- the MLSMessage is not an MLS Welcome;
- the referenced KeyPackage is not local to this account/device;
- any resulting member leaf is missing a valid account identity proof;
- the resulting group state lacks required Marmot state;
- the group requires a capability this client does not support.
