#!/usr/bin/env python3
"""End-to-end demo: Alice sends a file to Bob, then an attacker tampers with it."""
import tempfile
from pathlib import Path
from securetransfer import *

d = Path(tempfile.mkdtemp())
print("1. Generating key pairs for Alice (sender) and Bob (receiver)...")
generate_keypair("alice", d); generate_keypair("bob", d)
alice, alice_pub = load_private_key(d / "alice_private.pem"), load_public_key(d / "alice_public.pem")
bob, bob_pub = load_private_key(d / "bob_private.pem"), load_public_key(d / "bob_public.pem")
print("   Alice fp:", fingerprint(alice_pub)[:32], "...")

doc = d / "report.txt"; doc.write_text("Confidential: Q3 results. Do not distribute.\n")
print("2. Alice encrypts + signs report.txt for Bob")
protect_file(doc, d / "report.txt.sft", alice, bob_pub)
print("   Ciphertext preview:", (d / "report.txt.sft").read_bytes()[-440:-416].hex(), "...")

print("3. Bob verifies the signature and decrypts")
out = unprotect_file(d / "report.txt.sft", d / "inbox", bob, alice_pub)
print("   [OK] ->", out.read_text().strip())

print("4. Attacker flips one bit in transit")
b = bytearray((d / "report.txt.sft").read_bytes()); b[-420] ^= 1
(d / "tampered.sft").write_bytes(bytes(b))
try:
    unprotect_file(d / "tampered.sft", d / "inbox2", bob, alice_pub)
except SecurityError as e:
    print("   [REJECTED]", e)
