# 🦫 Marmot Protocol

![Marmot Protocol](https://blossom.primal.net/d9f2c5746e6b20e12517a5d775cb5f35c82b531dbe028a3bc8dca6d3bd90b344.png)

**Secure, decentralized group messaging that protects both content and metadata**

Marmot combines the [MLS Protocol](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr's](https://github.com/nostr-protocol/nostr) decentralized network to deliver truly private group messaging without relying on centralized servers or legacy identity systems.

## Why Marmot?

![Why Marmot?](https://blossom.primal.net/433f27edf38b5de813e708cd37be9762b9f85e79e7eb5b6c923dd553b2e40913.png)

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

![Security Overview](https://blossom.primal.net/90acb650fb5cd2617b6bf1b063760883db5322bc0b21f2cd1e34facb6e5054df.png)

Marmot maintains strong security guarantees through MLS:

- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Post-Compromise Security**: Key rotation limits impact of future compromises
- **Identity Separation**: MLS signing keys are distinct from Nostr identity keys
- **Regular Key Rotation**: Automatic key updates enhance security over time

## Protocol Specifications

![Protocol Specifications](https://blossom.primal.net/b6f6f1fa37413fc9722295ff009c3f389076e90147451bb9d2599adcfefa3e87.png)

Before implementing Marmot, you should have:

- **Nostr Knowledge**: Understanding of keys, kinds, tags, and relays ([Learn Nostr](https://github.com/nostr-protocol/nostr))
- **MLS Basics**: Familiarity with the MLS protocol concepts ([MLS Overview](https://www.rfc-editor.org/rfc/rfc9750.html), [ELI5 Video](https://www.youtube.com/watch?v=FESp2LHd42U))

### Experimental

**⚠️ Important: Marmot is currently experimental software.**

While the protocol is based on proven cryptographic foundations (MLS and Nostr), the Marmot specification itself is still under active development. Key considerations:

- **Breaking Changes**: The protocol may undergo breaking changes as we refine the specification
- **Security Review**: The protocol has not yet undergone formal security auditing
- **Implementation Maturity**: Reference implementations are functional but may contain bugs
- **Interoperability**: Cross-client compatibility is a goal but not yet fully tested

**Use in Production**: We recommend against using Marmot for production applications until the protocol reaches stable status. Current implementations are suitable for:
- Research and development
- Proof-of-concept applications
- Contributing to protocol development
- Educational purposes

We welcome feedback, security analysis, and contributions to help mature the protocol toward production readiness.


### Marmot Implementation Proposals (MIPs)

Required MIPs must be implemented for Marmot compatibility. Implementations may choose which optional MIPs to implement based on their application's needs.

| MIP | Description | Status | Required? |
|-----|-------------|--------|----------|
| [MIP-00](00.md) | Credentials & Key Packages | 👀 Review | ✅ Yes |
| [MIP-01](01.md) | Group Construction & Marmot Group Data Extension | 👀 Review | ✅ Yes |
| [MIP-02](02.md) | Welcome Events | 👀 Review | ✅ Yes |
| [MIP-03](03.md) | Group Messages | 👀 Review | ✅ Yes |
| [MIP-04](04.md) | Encrypted Media | 👀 Review | ❌ No |
| [MIP-05](05.md) | Push Notifications | 🚧 Draft | ❌ No |


## Protocol Implementations

![Protocol Implementations](https://blossom.primal.net/c81fbf412dad3bce2a6888d3851f75f346d7e82110d878f85286e6b9ce0f4000.png)

- [MDK - Marmot Development Kit](https://github.com/parres-hq/mdk): Reference implementation in Rust
- [marmot-ts](https://github.com/parres-hq/marmot-ts): TypeScript implementation (still very early, please contribute!)

## Projects using Marmot

![Projects using Marmot](https://blossom.primal.net/0b4067b6108a22caf81c515a6c8f50e431fb57cb7eb00b2596b229c57faa9aed.png)

- [whitenoise](https://github.com/parres-hq/whitenoise): Rust crate using MDK to build a fully featured messenger client
- [whitenoise_flutter](https://github.com/parres-hq/whitenoise_flutter): Flutter app, using the `whitenoise` crate.

## Contributing

![Contributing](https://blossom.primal.net/c977cb817ba22578ef3161d572a790a17fb2a1ef282bbae9276f6977fc0ed2da.png)

This protocol is actively developed and welcomes contributions:

- 🐛 **Issues**: Report bugs or suggest improvements
- 📖 **Documentation**: Help improve specifications and guides
- 🔧 **Implementation**: Build clients and libraries
- 🧪 **Testing**: Help verify interoperability

## References

![References](https://blossom.primal.net/fc164d1599c5a1a6a3a8c9d4479f183acc60548a14bbb62425ace24658f7acfd.png)

- [RFC 9420: Messaging Layer Security](https://datatracker.ietf.org/doc/rfc9420/)
- [MLS Architecture Overview](https://www.rfc-editor.org/rfc/rfc9750.html)
- [MLS Extensions](https://www.ietf.org/archive/id/draft-ietf-mls-extensions-08.txt)
- [Nostr NIPs](https://github.com/nostr-protocol/nips)

### Legacy Documentation

- [NIP-EE](EE.md) - Original Nostr NIP (now superseded by this protocol specification)
