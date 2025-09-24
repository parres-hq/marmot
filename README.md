# 🦫 Marmot Protocol

**Secure, decentralized group messaging that protects both content and metadata**

Marmot combines the [MLS Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr's](https://github.com/nostr-protocol/nostr) decentralized network to deliver truly private group messaging without relying on centralized servers or legacy identity systems.

## Why Marmot?

- 🔒 **End-to-End Encrypted**: Messages are encrypted on your device and can only be read by intended recipients
- 🌐 **Decentralized**: No central servers to shut down or compromise
- 🛡️ **Metadata Protection**: Hides who you're talking to, not just what you're saying
- ⚡ **Scalable**: Efficient group messaging for small teams to large communities
- 🔗 **Interoperable**: Works across different clients and implementations
- 🆔 **Identity Freedom**: No phone numbers or email addresses required

Marmot addresses critical limitations in existing messaging systems:

- **Signal**: Excellent E2EE but centralized infrastructure vulnerable to shutdown
- **NIP-04/NIP-17**: Basic encryption but lacks forward secrecy and group messaging
- **Traditional Platforms**: Vulnerable to mass surveillance and censorship

By combining MLS's proven cryptography with Nostr's decentralized architecture, Marmot provides the security of Signal with the censorship resistance of decentralized protocols.

## Security Overview

Marmot maintains strong security guarantees through MLS:

- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Post-Compromise Security**: Key rotation limits impact of future compromises
- **Identity Separation**: MLS signing keys are distinct from Nostr identity keys
- **Regular Key Rotation**: Automatic key updates enhance security over time

## Protocol Specifications

Before implementing Marmot, you should have:

- **Nostr Knowledge**: Understanding of keys, kinds, tags, and relays ([Learn Nostr](https://github.com/nostr-protocol/nostr))
- **MLS Basics**: Familiarity with the MLS protocol concepts ([MLS Overview](https://www.ietf.org/archive/id/draft-ietf-mls-architecture-13.html), [ELI5 Video](https://www.youtube.com/watch?v=FESp2LHd42U))

### Core MIPs (Required)

These specifications **must** be implemented for Marmot compatibility:

| MIP | Description | Status |
|-----|-------------|--------|
| [MIP-00](00.md) | Credentials & Key Packages | ✅ Stable |
| [MIP-01](01.md) | Group Construction & Nostr Group Data Extension | ✅ Stable |
| [MIP-02](02.md) | Welcome Events | ✅ Stable |
| [MIP-03](03.md) | Group Messages | ✅ Stable |

### Optional MIPs

Implement these based on your application's needs:

| MIP | Description | Status |
|-----|-------------|--------|
| [MIP-04](04.md) | Encrypted Media | 🚧 Draft |

### Legacy Documentation

- [NIP-EE](EE.md) - Original Nostr NIP (now superseded by [MIP-00](00.md) and [MIP-01](01.md))

## Contributing

This protocol is actively developed and welcomes contributions:

- 🐛 **Issues**: Report bugs or suggest improvements
- 📖 **Documentation**: Help improve specifications and guides
- 🔧 **Implementation**: Build clients and libraries
- 🧪 **Testing**: Help verify interoperability


