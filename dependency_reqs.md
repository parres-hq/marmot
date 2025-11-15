# Marmot Dependency Management Documentation

## 1. Introduction and Scope

This document outlines the mandatory requirements and best practices for managing the critical library dependencies that the Marmot protocol depends on. While the Marmot team uses specific implementations, this specification is publicly available, and other implementers may choose different dependencies, modify existing ones, or develop their own implementations.

This document:

- Defines **mandatory requirements** for library dependencies and protocols
- Provides **recommended libraries** to guide implementers
- Establishes **security monitoring practices** for ongoing vulnerability management

We focus primarily on the MLS and Nostr protocol implementations as these are the two foundational protocols that Marmot depends on.

## 2. MLS (Messaging Layer Security)

### 2.1 Mandatory Requirements

Any MLS implementation used with Marmot **MUST**:

1. **Specification Compliance**

   - Fully implement [RFC 9420 (MLS Protocol)](https://www.rfc-editor.org/rfc/rfc9420.html)
   - Support the cipher suites required by Marmot (see Section 2.1.1)
   - Correctly implement all security-critical MLS operations including:
     - TreeKEM ratcheting
     - Secret tree derivation
     - Epoch authentication
     - Forward secrecy guarantees

2. **Cryptographic Primitives**

   - Use well-audited, constant-time cryptographic implementations
   - Properly protect cryptographic keys in memory
   - Implement secure key deletion when keys are no longer needed
   - Use cryptographically secure random number generators (CSPRNG)

3. **Security Features**

   - Validate all incoming MLS messages according to RFC 9420
   - Reject malformed or invalid protocol messages
   - Properly handle group state transitions and rollbacks
   - Implement replay protection mechanisms
   - Validate all credentials and signatures

4. **Error Handling**
   - Fail securely when encountering errors
   - Never leak sensitive information through error messages
   - Log security-relevant events for audit purposes

#### 2.1.1 Required Cipher Suites

Implementations **MUST** support the following cipher suites:

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (mandatory to implement per RFC 9420)

### 2.2 Recommended Libraries

The following libraries have been evaluated and are recommended for Marmot implementations:

- **[openmls](https://github.com/openmls/openmls/tree/main/openmls)** (Rust)

  - Mature, well-tested implementation by MLS spec authors
  - Active maintenance and security updates
  - Good documentation and community support
  - Has done a security audit

- **[mls-rs](https://github.com/awslabs/mls-rs)** (Rust)

  - Developed by AWS, with enterprise-grade security focus
  - Comprehensive test coverage
  - Has not been audited

- **[ts-mls](https://github.com/LukaJCB/ts-mls)** (TypeScript)
  - JavaScript/TypeScript ecosystem support
  - Has not been audited

**Note:** This list is not exhaustive. Implementers may use other libraries that meet the mandatory requirements.

### 2.3 Security Monitoring

Implementers **MUST**:

- Subscribe to security advisories for their chosen MLS library
- Monitor the [MLS working group mailing list](https://mailarchive.ietf.org/arch/browse/mls/)
- Review and apply security patches as soon as possible
- Conduct periodic security reviews of dependency updates

Implementers **SHOULD**:

- Use automated dependency vulnerability scanning tools
- Maintain an inventory of all cryptographic dependencies
- Document the specific versions of dependencies in use
- Establish a process for emergency security updates

## 3. Nostr Protocol

### 3.1 Mandatory Requirements

Any Nostr implementation used with Marmot **MUST**:

1. **Core Protocol Compliance**

   - Implement [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) (Basic protocol flow)
   - Support event signing and verification per NIP-01
   - Properly validate event IDs and signatures
   - Handle relay connections and subscriptions

2. **Other Required NIPs**

   - **NIP-09**: Event deletion
   - **NIP-44**: Encrypted Payloads (versioned encryption)
   - **NIP-59**: Gift Wrap (sealed sender)
   - **NIP-65**: Inbox/Outbox relay model

3. **Security Requirements**

   - Validate all event signatures before processing
   - Verify event IDs match the calculated hash
   - Implement rate limiting for relay connections
   - Protect private keys in memory and storage
   - Use secure key generation (secp256k1)

4. **Data Handling**
   - Properly encode/decode binary data (e.g., base64)
   - Handle UTF-8 encoding correctly
   - Validate event timestamps and prevent time-based attacks
   - Implement proper JSON parsing with size limits

### 3.2 Marmot-Specific Nostr Requirements

In addition to general Nostr requirements, Marmot implementations **MUST**:

1. **Event Kinds**

   - Support all Marmot-defined event kinds (see Marmot specification)
   - Properly handle ephemeral vs. replaceable events
   - Implement event deletion where specified

2. **Tag Handling**

   - Correctly parse and validate all Marmot-specific tags
   - Support relay hints in tags
   - Handle tag-based filtering and queries

3. **Relay Interaction**
   - Implement inbox/outbox relay model per NIP-65
   - Support multiple relay connections
   - Handle relay failures gracefully
   - Implement connection retry logic

### 3.3 Recommended Libraries

The following libraries have been evaluated and are recommended for Marmot implementations:

- **[rust-nostr](https://github.com/rust-nostr/nostr)** (Rust)

  - Comprehensive NIP support
  - Active development and maintenance
  - Well-documented API
  - Strong cryptographic foundations

- **[NDK](https://github.com/nostr-dev-kit/ndk)** (TypeScript/JavaScript)

  - Excellent developer experience
  - Wide adoption in the Nostr ecosystem
  - Good relay management features

- **[applesauce](https://github.com/hzrd149/applesauce)** (TypeScript)

  - Lightweight and performant
  - Focus on modern JavaScript patterns

**Note:** This list is not exhaustive. Implementers may use other libraries that meet the mandatory requirements.

### 3.4 Security Monitoring

Implementers **MUST**:

- Monitor security advisories for their chosen Nostr library
- Subscribe to security-related discussions in the [Nostr protocol repository](https://github.com/nostr-protocol/nips)
- Review new NIPs for security implications
- Apply security patches within 30 days of release

Implementers **SHOULD**:

- Use automated dependency scanning tools
- Monitor relay software for vulnerabilities
- Participate in Nostr security discussions
- Conduct regular security audits

## 4. Cryptographic Dependencies

### 4.1 Mandatory Requirements

All cryptographic libraries **MUST**:

1. **Security Standards**

   - Be well-audited by reputable security firms
   - Implement constant-time operations to prevent timing attacks
   - Use secure memory handling (e.g., memory locking, secure zeroing)
   - Follow industry best practices (e.g., FIPS compliance where applicable)

2. **Algorithm Support**

   - Support secp256k1 (for Nostr)
   - Support X25519 and Ed25519 (for MLS)
   - Provide secure random number generation
   - Implement proper key derivation functions (KDF)

3. **Security Properties**
   - Protect against side-channel attacks
   - Implement proper error handling without leaking information
   - Provide secure key storage mechanisms
   - Support key rotation and destruction

### 4.2 Security Monitoring

Implementers **MUST**:

- Monitor CVE databases for cryptographic library vulnerabilities
- Subscribe to security advisories from cryptographic library maintainers
- Review cryptographic algorithms for deprecation notices (e.g., NIST guidelines)
- Maintain an up-to-date inventory of all cryptographic dependencies

## 5. General Dependency Management

### 5.1 Mandatory Practices

All Marmot implementations **MUST**:

1. **Dependency Tracking**

   - Maintain a complete inventory of all dependencies (direct and transitive)
   - Document the versions of all security-critical dependencies
   - Use dependency lock files to ensure reproducible builds
   - Track the provenance of all dependencies

2. **Vulnerability Monitoring**

   - Implement automated vulnerability scanning in CI/CD pipelines
   - Subscribe to security advisories for all critical dependencies
   - Establish a process for triaging and addressing vulnerabilities
   - Define SLAs for applying security patches based on severity

3. **Update Management**

   - Regularly update dependencies (at least quarterly for security patches)
   - Test updates thoroughly before deployment
   - Maintain a rollback plan for problematic updates
   - Document the update history and rationale

4. **Risk Assessment**
   - Evaluate the security posture of new dependencies before adoption
   - Assess the maintenance status and community support
   - Review the security track record of dependency maintainers
   - Consider the attack surface introduced by each dependency

### 5.2 Recommended Practices

Implementers **SHOULD**:

1. **Automation**

   - Use tools like Dependabot, Renovate, or similar for automated dependency updates
   - Implement automated security scanning (e.g., Snyk, OWASP Dependency-Check)
   - Set up alerts for high-severity vulnerabilities
   - Automate testing of dependency updates

2. **Security Review**

   - Conduct periodic security reviews of all dependencies
   - Review changelogs and release notes for security implications
   - Participate in security discussions for critical dependencies
   - Consider contributing to security audits of critical dependencies

3. **Supply Chain Security**

   - Verify dependency signatures and checksums
   - Use private package registries where appropriate
   - Implement Software Bill of Materials (SBOM) generation
   - Monitor for typosquatting and dependency confusion attacks

4. **Documentation**
   - Document the security requirements for each dependency
   - Maintain a dependency security policy
   - Document the incident response process for dependency vulnerabilities
   - Keep security contact information up to date

## 6. Vulnerability Response Process

### 6.1 Severity Classification

Vulnerabilities should be classified using CVSS scores:

- **Critical (9.0-10.0)**: Immediate action required (patch within 7 days)
- **High (7.0-8.9)**: Urgent action required (patch within 30 days)
- **Medium (4.0-6.9)**: Timely action required (patch within 90 days)
- **Low (0.1-3.9)**: Address in normal update cycle

### 6.2 Response Timeline

Implementers **MUST**:

- Acknowledge critical vulnerabilities within 24 hours
- Develop a remediation plan within 48 hours for critical vulnerabilities
- Apply patches or mitigations according to the severity timeline
- Communicate with users about security updates

### 6.3 Disclosure

Implementers **SHOULD**:

- Maintain a security advisory page
- Publish security advisories for vulnerabilities affecting users
- Coordinate with the Marmot team on protocol-level vulnerabilities
- Follow responsible disclosure practices

## 7. Resources and Tools

### 7.1 Vulnerability Databases

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [GitHub Security Advisories](https://github.com/advisories)
- [Rust Security Advisory Database](https://rustsec.org/)
- [npm Security Advisories](https://www.npmjs.com/advisories)

### 7.2 Monitoring Tools

- **Dependabot** (GitHub)
- **Snyk**
- **OWASP Dependency-Check**
- **cargo-audit** (Rust)
- **npm audit** (Node.js)

### 7.3 Standards and Guidelines

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Dependency Management](https://owasp.org/www-project-dependency-check/)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)

## 8. Compliance Checklist

Before deploying a Marmot implementation, verify:

- [ ] MLS implementation meets all mandatory requirements (Section 2.1)
- [ ] Nostr implementation meets all mandatory requirements (Section 3.1)
- [ ] All cryptographic libraries are properly audited (Section 4.1)
- [ ] Dependency inventory is complete and documented (Section 5.1.1)
- [ ] Vulnerability monitoring is configured (Section 5.1.2)
- [ ] Update management process is established (Section 5.1.3)
- [ ] Vulnerability response process is documented (Section 6)
- [ ] Security contact information is published
- [ ] Incident response plan is in place

## 9. Contact and Updates

For questions about dependency requirements or to report security concerns related to the Marmot specification:

- **Repository**: [https://github.com/parres-hq/marmot](https://github.com/parres-hq/marmot)
- **Security Contact**: [security@ipf.dev](mailto:security@ipf.dev)

This document will be updated as the Marmot specification evolves and as new security best practices emerge.
