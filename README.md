# Secure File Transfer Using Encryption and Digital Signatures

**Objective:** protect files with encryption (confidentiality) and verify their
integrity and authenticity with digital signatures.

| Goal | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM file encryption; AES key wrapped with receiver's RSA public key (RSA-OAEP / SHA-256) |
| Integrity | GCM authentication tag + SHA-256 hash + signature over the whole package |
| Authenticity / non-repudiation | RSA-PSS (SHA-256) signature by the sender's private key |

## Setup
```bash
pip install -r requirements.txt      # Python 3.9+
python demo.py                       # instant end-to-end demo
python tests/test_crypto.py          # 9 security tests
```

## Command-line usage
```bash
# 1. Each party creates a key pair, then exchanges PUBLIC keys (verify fingerprints out-of-band!)
python sft.py keygen alice --out keys
python sft.py keygen bob   --out keys
python sft.py fingerprint keys/alice_public.pem

# 2. Alice encrypts for Bob and signs with her own key
python sft.py send samples/payroll.txt --my-key keys/alice_private.pem --to keys/bob_public.pem -o payroll.sft

# 3. Bob verifies Alice's signature, then decrypts
python sft.py receive payroll.sft --my-key keys/bob_private.pem --sender keys/alice_public.pem --out received
```
Add `--no-passphrase` if the private keys were created without a passphrase.

### Over the network (two terminals / machines)
```bash
# Bob (receiver) - waits for one file, then verifies + decrypts
python sft.py receive incoming.sft --listen --port 5001 --my-key keys/bob_private.pem --sender keys/alice_public.pem
# Alice (sender)
python sft.py send samples/payroll.txt --my-key keys/alice_private.pem --to keys/bob_public.pem --host 127.0.0.1 --port 5001
```

## Project layout
```
sft.py                  CLI (keygen | fingerprint | send | receive)
demo.py                 scripted Alice -> Bob demo + tamper attack
securetransfer/crypto.py   keys, encrypt+sign, verify+decrypt
securetransfer/network.py  length-prefixed TCP transport
tests/test_crypto.py    unit tests (tamper, wrong key, forgery, truncation...)
docs/REPORT.md          design, threat model, results
```

## Security notes / limitations
- Receiver **verifies the signature before decrypting** and writes nothing on failure.
- Key authenticity depends on you checking public-key **fingerprints** over a trusted channel (no CA/PKI here).
- Whole file is processed in memory (fine for typical files; use chunked AEAD for multi-GB files).
- No replay protection: a valid old package can be re-sent. Add a timestamp/sequence number if needed.
- Transport is plain TCP: contents are protected, but metadata (size, endpoints) is visible. Wrap in TLS for production.
