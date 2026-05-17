# Threshold Vault Compact Recovery Code Format

## Purpose

This document defines the compact recovery code format used by Threshold Vault. The compact recovery code is the primary user-facing shard artifact. It is what users copy, print, type, and paste to recover their secret.

One compact recovery code represents one complete, self-contained shard. Any valid threshold set of M or more codes can reconstruct the original secret locally, without a network connection and without Threshold Vault's servers.

## Format Name

- Canonical name: `SHARDS-CODE-1`
- Legacy fallback format: `SHARDS-1` (multiline text blocks, still parser-accepted)

## User-Facing Shape

```text
A-2of3 4ZAG-LXrm-q3Yd-KBVx-5B3h-haTe-7CYh-GqzN-ofwZ-kDSq-eefm-qLX3-jMJE-TM4n-cy2X-YfKr-GQYq-nFbH-YGhn-4rLu-3yRZ-kMvy-JV3Y-d2Bh-PEMo-8UeM-DBza-YWs4-mTg2-S3DY-AALZ-Gkom-JfCL-99m4-Jymz-9BBd-mE6W-TunJ-miGw-7pH2-H8CR-vB3M-yqer-kDy1-sjhY-CpJx-cJf9-Xrgq-yWRB-nDxf-1SPC-bmro-tf5 151s
```

Meaning:

- `A-2of3` — shard label and threshold hint (shard A of a 2-of-3 scheme)
- middle grouped body — the full self-contained shard payload (base58-encoded binary)
- trailing `151s` — 4-character typo-check code

Legacy pipe-separated display:

```text
A-2of3 | 4ZAG-LXrm-...-tf5 | 151s
```

The parser accepts both forms. The canonical form (no pipes) is preferred.

## Recovery Model

- One compact recovery code is one shard — a share of the AES encryption key plus a copy of the encrypted secret.
- Any valid set of M shards (where M is the threshold) can reconstruct the AES key via Lagrange interpolation in GF(256), decrypt the ciphertext, and recover the original plaintext.
- No server is required.
- No separate metadata block is required for normal recovery.
- No separate encrypted package or file is required.
- QR codes, if present, encode the same compact recovery code string as convenience shortcut only.

## Binary Payload Design

The body is base58-encoded binary. The binary layout is:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 byte | Payload version (currently `1`) |
| 1 | 1 byte | Flags byte |
| 2 | 1 byte | Shard index (1-based) |
| 3 | 1 byte | Total shard count N |
| 4 | 1 byte | Required threshold M |
| 5 | 2 bytes | Original secret character length (big-endian uint16) |
| 7 | 8 bytes | Ceremony ID (random, hex-encoded in metadata) |
| 15 | 12 bytes | AES-GCM IV |
| 27 | 32 bytes | Key share (Shamir share of the AES-256 key) |
| 59 | 2 bytes | Ciphertext length (big-endian uint16) |
| 61 | N bytes | AES-256-GCM ciphertext (body + 16-byte authentication tag) |

**Total minimum payload size:** 61 bytes (plus ciphertext).

**Flags byte:**
- Bit 0 (`0x01`): plaintext was gzip-compressed before encryption. Current splits always set this bit.

## Encoding Rules

- **Base encoding:** Base58 using Bitcoin's alphabet
- **Alphabet:** `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
  - Excludes `0`, `O`, `I`, `l` to prevent visual confusion
- **Body grouping:** canonical grouping is 4 characters per group, separated by `-`
- **Code separators:** canonical is a single space between header, body, and check code
- **Header token format:** `<label>-<required>of<total>`
- **Label token:** spreadsheet-style alphabetical (A, B, C, ..., Z, AA, AB, ...)

## Case Policy

- Header label token: **uppercase**
- Body: **mixed-case** base58 (case-significant)
- Check code: **mixed-case** base58 (case-significant)
- Parser: **whitespace-tolerant**, ignores body grouping hyphens and line breaks

Do not normalize case when transcribing recovery codes. The body is case-sensitive.

## Typo-Check Code

The 4-character check code at the end of each compact recovery code is derived as:

1. Encode the raw binary payload as base58
2. Compute `SHA-256(raw-binary-payload)`
3. Take the first 2 bytes of the digest
4. Encode those 2 bytes as base58 (4 characters, left-padded with `1` if needed)

A code with a wrong check code is rejected before any decryption attempt. Errors:

- `Check code does not match. Re-check this recovery code.`
- `These shards belong to different groups.`
- `At least N valid shards are required.`

## Compression

Current Threshold Vault splits always gzip-compress the plaintext before AES-256-GCM encryption. This is indicated by flag bit 0 in the payload.

The compact code never reveals plaintext by inspection. Compression reduces code length for short secrets, seed phrases, and passwords.

## Copy and QR Equivalence

The copy action produces:

```text
A-2of3 4ZAG-LXrm-...-tf5 151s
```

The QR code, if shown, encodes the same string. QR is optional convenience only — it is not required for recovery, and there is no URL-based recovery flow.

## Legacy Support

- `SHARDS-1` multiline blocks remain parser-accepted as fallback input.
- Legacy `SHARDSQR1:` QR payloads remain parser-accepted.
- Share-only fragments (raw base64url key shares) are rejected with a helpful error message.

## Input Length Policy

- Maximum supported plaintext: **256 characters**
- Intended uses: passwords, private keys, 12-word seed phrases, 24-word seed phrases, short notes
- Not supported: long documents, A4 letters, multi-page text

## Measured Code Lengths (2-of-3 scheme)

| Secret | Compact code length |
|--------|---------------------|
| `hello world` (11 chars) | ~199 characters |
| 12-word seed phrase | ~279 characters |
| 50-character secret | ~267 characters |
| 100-character secret | ~294 characters |
| Short 30-word note | ~364 characters |

These lengths are suitable for printed shard cards.

## Security Notes

- The compact recovery code contains encrypted ciphertext plus a Shamir share of the AES key.
- It must be handled as sensitive material — it is one shard of the threshold scheme.
- The code does not reveal the plaintext by inspection alone.
- Recovery happens locally in the browser (or Node.js). Nothing is sent to any server.
- QR codes, if shown, encode the same sensitive material.

## Non-Goals

- No backend recovery flow
- No QR-only recovery dependency
- No separate package file required for recovery
- No Bitcoin; no blockchain; no cryptocurrency-specific encoding
