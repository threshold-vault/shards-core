# Security

## Scope

This package contains the cryptographic core and offline recovery tool for Threshold Vault. It implements Shamir Secret Sharing over GF(256) with AES-256-GCM encryption, using standard Web Crypto API primitives.

## No External Audit

No external security audit has been performed on this code. The implementation follows standard cryptographic construction but has not been reviewed by an independent security firm. Use at your own risk for high-value secrets.

## No Production-Readiness Guarantee

This software is provided as-is. Mindcraft Inc. makes no guarantee of production readiness, suitability for any particular purpose, or fitness for use with high-value secrets without additional due diligence.

## Known Risk Surfaces

The cryptographic algorithm (Shamir Secret Sharing + AES-256-GCM) is sound for the described threat model. However, the following operational risks remain regardless of the algorithm:

**Malware and browser risks:**
- Browser extensions, injected scripts, or compromised browser environments can read DOM content and clipboard data.
- Use a clean, trusted browser profile when handling real secrets.
- Disable or audit browser extensions when performing high-value splits or recoveries.

**Printer and display risks:**
- Printers may retain job history, raster caches, or network logs.
- Screen capture software, secondary displays, or observers may record displayed secrets.
- Physical printouts of shard cards are sensitive material. Handle them accordingly.

**Storage risks:**
- OS recent-document lists, browser history, and clipboard managers may persist shard content.
- Downloaded PDFs of shard cards are sensitive. Do not store them with other shards that meet the threshold.

**Threshold model risks:**
- The threshold model only protects against up to M-1 colluding holders.
- Physical theft of M or more shard cards breaks the model regardless of the cryptography.
- Storing all shards in one location defeats the purpose of the scheme.

## No Server Custody

This package is browser-only. It does not transmit secrets, shard codes, or recovered plaintexts to any server. All cryptographic operations happen locally in the browser or Node.js runtime.

The standalone offline HTML (`offline/threshold-vault-offline-recover.html`) is designed to be used without a network connection and makes no network requests during operation.

## Responsible Disclosure

If you discover a security vulnerability in this code, please report it to:

**info@thresholdvault.com**

Please do not file public GitHub issues for security vulnerabilities. We will respond within 72 hours for confirmed vulnerabilities.

## Cryptographic Primitives

- **Secret sharing:** Shamir Secret Sharing over GF(256) with irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b)
- **Encryption:** AES-256-GCM (256-bit key, 96-bit IV, 128-bit authentication tag)
- **Compression:** gzip (applied before encryption)
- **Key derivation:** none — the AES key is a randomly generated 32-byte value split via Shamir
- **Randomness:** `crypto.getRandomValues` (Web Crypto API)
- **Hashing:** SHA-256 (Web Crypto API, used for check codes and fingerprints)
- **Encoding:** Base58 (Bitcoin alphabet), Base64url
