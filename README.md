# Marmot

The Marmot Protocol is a messaging protocol that specifies how to do efficient end-to-end encrypted group messaging using Nostr's decentralized identity & relay network combined with the [MLS Protocol](https://www.rfc-editor.org/rfc/rfc9420.html).

- The goal of MLS is efficient end-to-end encrypted messaging at large scale.
- The goal of Nostr is to give user's agency and control over their identity and content. Reducing or removing the control of large centralized entities as much as possible.
- The goal of Marmot is to make it possible to do interoperable, truly secure (protecting both content & metadata) communication in a way that isn't dependent on centralized third party providers or legacy identity systems like email or phone numbers.

## Context

We assume a good working understanding of how the Nostr protocol works. If you're unsure about how keys, kinds, tags, and relays work, please read up on that first.

We also assume a basic working understanding of how the MLS protocol works. Some good references if you're new to MLS:

- [MLS Architectural Overview](https://www.ietf.org/archive/id/draft-ietf-mls-architecture-13.html)
- [ELI5 video](https://www.youtube.com/watch?v=FESp2LHd42U)

## MIPs (Marmot Implementation Possibilities)

MIPs are the protocol specifications that describe how to set up and run secure messaging with MLS over Nostr. By design, there are very few required MIPs. Most are optional and should only be considered if it's helpful for your project.

You can read the original (and still applicable) [NIP-EE](EE.md) as well. This was the original Nostr NIP that describes the basic messaging protocol. We have improved and simplified the basic protocol description here in [MIP-01](01.md).

## Required MIPs

- [MIP-01 - Basic MLS messaging over Nostr](01.md)
- [MIP-02 - Nostr Group Data Extension](02.md)

## Optional MIPs

- [03.md - Encrypted media](03.md) (Coming soon...)
- [04.md - Read receipts & online indicators](04.md) (Coming soon...)
- [05.md - Multi-device support](05.md) (Coming soon...)
- [06.md - Multi-device encrypted backups](06.md) (Coming soon...)


