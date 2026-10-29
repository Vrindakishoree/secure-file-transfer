# Project Report: Secure File Transfer Using Encryption and Digital Signatures

## 1. Objective
Transfer files so that only the intended receiver can read them (confidentiality),
any modification is detected (integrity), and the receiver can prove who sent them (authenticity).

## 2. Design: hybrid encrypt-then-sign
**Why hybrid?** RSA is slow and limited to small messages; AES is fast for bulk data. We use AES for the
file and RSA only to protect the AES key and to sign.

### Sender
1. Generate random AES-256 key `K` and 96-bit nonce.
2. `C = AES-GCM(K, nonce, file, AAD = magic || header)`.
3. `WK = RSA-OAEP-SHA256(receiver_public, K)`.
4. Package = magic | header(JSON: filename, SHA-256, nonce, WK, fingerprints) | C.
5. `S = RSA-PSS-SHA256(sender_private, Package)`; append `S`.

### Receiver
1. Parse and bounds-check the package.
2. **Verify `S`** with the sender's public key. Fail -> reject (nothing decrypted/written).
3. Unwrap `K` with receiver's private key; AES-GCM decrypt (tag check).
4. Compare SHA-256 of plaintext with header hash. Save under `basename(filename)` (prevents path traversal).

## 3. Threat model and results
| Attack | Defence | Test |
|---|---|---|
| Eavesdropping | AES-256-GCM, key wrapped for receiver only | `test_ciphertext_hides_plaintext`, `test_wrong_receiver_rejected` |
| Bit-flip / modification | RSA-PSS over package + GCM tag | `test_tampered_ciphertext_rejected` |
| Truncation | Length fields validated | `test_truncated_rejected` |
| Impersonation | Signature must match sender's known public key | `test_wrong_sender_key_rejected`, `test_resigned_by_attacker_rejected` |
| Path traversal via filename | `Path(name).name` | by design |
| Key theft at rest | Private keys optionally passphrase-encrypted (PKCS#8), file mode 0600 | keygen |

All 9 automated tests pass.

## 4. Algorithm choices
- RSA-3072 (~128-bit security), OAEP and PSS (modern padding; avoids PKCS#1 v1.5 weaknesses).
- AES-256-GCM: authenticated encryption; fresh random key per file so nonce reuse is not a concern.
- SHA-256 everywhere.

## 5. Limitations and future work
Fingerprint-based trust (no PKI/CA); no replay protection; in-memory processing; plain TCP transport;
possible extensions: X.509 certificates, chunked streaming, TLS, key revocation, Ed25519/X25519 option.
