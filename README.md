# Threshold Vault Core

This is the **Threshold Vault / Shards core and offline recovery package**.

It is **not** the full Threshold Vault commercial application. It does not include payment processing, order management, administration, fulfillment, email delivery, or any other business logic.

## What this package provides

- **Core cryptographic library** (`src/index.ts`): Shamir Secret Sharing over GF(256) with AES-256-GCM encryption. Pure TypeScript, browser-compatible, no runtime dependencies.
- **Offline recovery tool** (`offline/threshold-vault-offline-recover.html`): A self-contained HTML file that lets you recover a secret from shard codes without a network connection or any server. Open it as a local file in any modern browser.
- **Test vectors** (`test-vectors/offline-recovery-vectors.json`): Deterministic test vectors for verifying the implementation.
- **Format documentation** (`docs/format.md`): Technical specification for the compact recovery code format.
- **Offline recovery guide** (`docs/offline-recovery.md`): How to use the offline recovery tool safely.

## What this package does not include

- Payment, billing, or subscription logic
- Order processing or fulfillment
- Admin or customer service tools
- Email delivery or notification systems
- The full Threshold Vault web application

## Purpose

This package lets users **verify and recover shard codes without thresholdvault.com**. If the Threshold Vault service becomes unavailable, the cryptographic algorithm, offline recovery tool, and format specification in this package are sufficient to recover any secret split with Threshold Vault.

## Security warning: test with dummy data first

**Always test your recovery workflow with dummy (non-sensitive) data before you need it for real.**

Do not test your actual recovery procedure for the first time in an emergency. Use the test vectors in `test-vectors/offline-recovery-vectors.json` or create your own dummy split to verify the tool works on your device.

## Using the offline recovery tool

1. Open `offline/threshold-vault-offline-recover.html` in a modern browser (Chrome, Firefox, Safari, Edge).
2. You can open it as a `file://` URL without a web server.
3. Disable your network connection if handling a real high-value secret.
4. Enter the recovery codes from at least M shard cards (where M is the threshold for your scheme).
5. Click "Reconstruct secret".

The tool performs all decoding, decryption, and reconstruction locally in the browser. Nothing is sent over the network.

## Verifying the offline HTML

Verify the SHA-256 hash of the offline HTML before use:

```bash
sha256sum offline/threshold-vault-offline-recover.html
# Compare against: offline/threshold-vault-offline-recover.html.sha256
```

## Running the TypeScript library

Requirements: Node.js 18+, npm or pnpm.

```bash
npm install
npm test          # Run the test suite
npm run build     # Compile TypeScript to dist/
```

## Repository location

The public repository location is intentionally not specified in this package. The human publishing this package will create the repository separately. Once published, the repository URL will be the authoritative location for updates.

## License

MIT License. Copyright 2026 Mindcraft Inc. See `LICENSE` for the full text.

## Security

See `SECURITY.md` for security notes, known risks, and responsible disclosure contact.
