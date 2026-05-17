# Offline Recovery Guide

## Purpose

The Threshold Vault offline recovery tool lets you recover a secret from shard codes without a network connection and without thresholdvault.com. If the service becomes unavailable, this tool is sufficient to recover any secret split with Threshold Vault.

The standalone HTML file is at: **`offline/threshold-vault-offline-recover.html`**

## How to Use the Offline Recovery Tool

1. Open `offline/threshold-vault-offline-recover.html` in a modern browser (Chrome, Firefox, Safari, Edge).
2. You can open it as a `file://` URL — no web server is needed.
3. For high-value recovery, disconnect from the network before proceeding.
4. Enter the compact recovery codes from at least M shard cards (where M is the threshold for your scheme).
   - Enter each code in a separate input field.
   - Click "+ Add shard" to add more fields if needed.
5. As you type or paste each code, the tool validates it immediately and shows a green checkmark if it is valid.
6. When you have entered at least M valid codes from the same ceremony, the "Reconstruct secret" button activates.
7. Click "Reconstruct secret". The tool reconstructs and displays the secret.

All decoding, decryption, and reconstruction happen locally in the browser. Nothing is sent over the network.

## Security Warning: Test with Dummy Data First

**Always test your recovery workflow with non-sensitive dummy data before you need it for real.**

Use the vectors in `test-vectors/offline-recovery-vectors.json` or create your own test split:

1. Use the Threshold Vault web app (or this library's `splitSecret` function) to split a dummy phrase like `test-recovery-workflow-only`.
2. Practice the offline recovery procedure with those shard codes.
3. Confirm the tool recovers the correct dummy phrase.
4. Only then use the tool with real secrets.

## Verifying the Offline HTML

Before use, verify the SHA-256 hash of the offline recovery tool:

```bash
sha256sum offline/threshold-vault-offline-recover.html
# Compare the output against the hash in:
#   offline/threshold-vault-offline-recover.html.sha256
```

If the hashes do not match, do not use the file. Obtain a fresh copy from the original source.

## Security Precautions

**Never share recovered secrets over email, messaging apps, or cloud storage.** Recovery is a local operation. The secret should be used directly from the recovery screen.

**Malware and browser risks:** Browser extensions, injected scripts, or compromised browser environments can observe the recovery screen. Use a clean browser profile (no extensions) when handling high-value secrets.

**Printer and screen risks:** Some operating systems keep screenshots, screen recordings, or recent-document lists. Be aware of your environment.

**Clipboard risks:** Clipboard managers and OS history may persist copied secrets. Clear clipboard history after use if your environment keeps it.

**Physical risks:** Do not perform high-value recovery in view of cameras, secondary displays, or other people.

## Recommended Safe Workflow

1. Use a trusted, up-to-date device.
2. Use a clean browser profile with extensions disabled.
3. Disconnect from the network if handling a real high-value secret.
4. Open `offline/threshold-vault-offline-recover.html` as a `file://` URL.
5. Enter your shard codes. Verify the green checkmarks.
6. Click "Reconstruct secret".
7. Use the recovered secret immediately (copy to its destination, type it, or note it).
8. Click "Clear all" to wipe the recovery screen.
9. Close the browser tab.
10. Clear your clipboard history if applicable.

## Troubleshooting

**"Check code does not match."**
The recovery code was transcribed incorrectly. Re-check each character carefully. Base58 is case-sensitive — `a` and `A` are different characters. The code excludes `0`, `O`, `I`, and `l` by design.

**"These shards belong to different groups."**
The shard codes you entered came from different ceremonies (different split operations). Ensure all codes are from the same original split.

**"At least N valid shards are required."**
You need to provide at least M (the threshold number) valid shard codes to reconstruct the secret. Check how many shards are required for your scheme — it is shown in the header of each code (e.g., `A-2of3` means 2 of 3 required).

**"Shard set could not be recovered."**
This usually means the shard codes are from different groups, or one or more codes were corrupted beyond what the check code can detect. Verify that all codes are from the same original split and try again.

## Code Format Reference

Each compact recovery code has three parts:
```
<header> <body> <check>
```
Example: `A-2of3 4ZAG-LXrm-... 151s`

- **Header** (`A-2of3`): shard label (`A`) and threshold hint (`2 of 3`)
- **Body**: base58-encoded shard payload (the encrypted secret + key share)
- **Check** (`151s`): 4-character typo-detection code

For the full format specification, see `docs/format.md`.

## Requirements

- Any modern browser (Chrome, Firefox, Safari, Edge) from 2021 or later
- No internet connection required
- No installation required
- Works as a `file://` URL or served from any local server

The tool uses only standard browser APIs: Web Crypto API, CompressionStream, TextEncoder, and TextDecoder. These are available in all modern browsers without any plugins or extensions.
