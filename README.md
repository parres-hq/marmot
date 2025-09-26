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
- **MLS Basics**: Familiarity with the MLS protocol concepts ([MLS Overview](https://www.rfc-editor.org/rfc/rfc9750.html), [ELI5 Video](https://www.youtube.com/watch?v=FESp2LHd42U))

### Marmot Implementation Proposals (MIPs)

Required MIPs must be implemented for Marmot compatibility. Implementations may choose which optional MIPs to implement based on their application's needs.

| MIP | Description | Status | Required? |
|-----|-------------|--------|----------|
| [MIP-00](00.md) | Credentials & Key Packages | ✅ Stable | ✅ Yes |
| [MIP-01](01.md) | Group Construction & Marmot Group Data Extension | ✅ Stable | ✅ Yes |
| [MIP-02](02.md) | Welcome Events | ✅ Stable | ✅ Yes |
| [MIP-03](03.md) | Group Messages | ✅ Stable | ✅ Yes |
| [MIP-04](04.md) | Encrypted Media | 🚧 Draft | ❌ No |


## Protocol Implementations

- [MDK - Marmot Development Kit](https://github.com/parres-hq/mdk): Reference implementation in Rust
- [marmot-ts](https://github.com/parres-hq/marmot-ts): TypeScript implementation (still very early, please contribute!)

## Projects using Marmot

- [whitenoise](https://github.com/parres-hq/whitenoise): Rust crate using MDK to build a fully featured messenger client
- [whitenoise_flutter](https://github.com/parres-hq/whitenoise_flutter): Flutter app, using the `whitenoise` crate.

## Contributing

This protocol is actively developed and welcomes contributions:

- 🐛 **Issues**: Report bugs or suggest improvements
- 📖 **Documentation**: Help improve specifications and guides
- 🔧 **Implementation**: Build clients and libraries
- 🧪 **Testing**: Help verify interoperability

## References

- [RFC 9420: Messaging Layer Security](https://datatracker.ietf.org/doc/rfc9420/)
- [MLS Architecture Overview](https://www.rfc-editor.org/rfc/rfc9750.html)
- [MLS Extensions](https://www.ietf.org/archive/id/draft-ietf-mls-extensions-08.txt)
- [Nostr NIPs](https://github.com/nostr-protocol/nips)

### Legacy Documentation

- [NIP-EE](EE.md) - Original Nostr NIP (now superseded by this protocol specification)
