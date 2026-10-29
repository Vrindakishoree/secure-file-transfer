#!/usr/bin/env python3
"""sft - Secure File Transfer command line tool."""
import argparse
import getpass
import sys
from pathlib import Path

from securetransfer import (generate_keypair, load_private_key, load_public_key,
                            fingerprint, protect_file, unprotect_file, SecurityError)
from securetransfer.network import send_package, receive_package


def pw(prompt, confirm=False):
    p = getpass.getpass(prompt)
    if confirm and p != getpass.getpass("Confirm passphrase: "):
        sys.exit("Passphrases do not match.")
    return p or None


def cmd_keygen(a):
    passphrase = None if a.no_passphrase else pw("Passphrase to protect private key (blank = none): ", True)
    priv, pub = generate_keypair(a.name, a.out, passphrase)
    print(f"Private key : {priv}  (KEEP SECRET)\nPublic key  : {pub}  (share this)")
    print("Fingerprint :", fingerprint(load_public_key(pub)))


def cmd_fingerprint(a):
    print(fingerprint(load_public_key(a.pubkey)))


def cmd_send(a):
    sender = load_private_key(a.my_key, pw("Your private key passphrase (blank if none): ") if not a.no_passphrase else None)
    receiver = load_public_key(a.to)
    out = a.output or f"{a.file}.sft"
    h = protect_file(a.file, out, sender, receiver)
    print(f"Encrypted + signed -> {out}\n  SHA-256 : {h['sha256']}\n  sender  : {h['sender_fp'][:23]}...")
    if a.host:
        send_package(out, a.host, a.port)
        print(f"Sent to {a.host}:{a.port}")


def cmd_receive(a):
    if a.listen:
        receive_package(a.package, port=a.port)
    receiver = load_private_key(a.my_key, pw("Your private key passphrase (blank if none): ") if not a.no_passphrase else None)
    sender = load_public_key(a.sender)
    try:
        out = unprotect_file(a.package, a.out, receiver, sender)
    except SecurityError as e:
        sys.exit(f"[REJECTED] {e}")
    print(f"[OK] Signature valid, integrity verified, decrypted -> {out}")


def main():
    p = argparse.ArgumentParser(prog="sft", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate an RSA key pair")
    k.add_argument("name"); k.add_argument("--out", default="keys")
    k.add_argument("--no-passphrase", action="store_true"); k.set_defaults(f=cmd_keygen)

    f = sub.add_parser("fingerprint", help="show a public key fingerprint")
    f.add_argument("pubkey"); f.set_defaults(f=cmd_fingerprint)

    s = sub.add_parser("send", help="encrypt + sign a file (optionally transmit it)")
    s.add_argument("file"); s.add_argument("--my-key", required=True, help="your private key (signs)")
    s.add_argument("--to", required=True, help="receiver's public key (encrypts)")
    s.add_argument("-o", "--output"); s.add_argument("--host"); s.add_argument("--port", type=int, default=5001)
    s.add_argument("--no-passphrase", action="store_true"); s.set_defaults(f=cmd_send)

    r = sub.add_parser("receive", help="verify + decrypt a package (optionally listen on network first)")
    r.add_argument("package"); r.add_argument("--my-key", required=True, help="your private key (decrypts)")
    r.add_argument("--sender", required=True, help="sender's public key (verifies)")
    r.add_argument("--out", default="received"); r.add_argument("--listen", action="store_true")
    r.add_argument("--port", type=int, default=5001)
    r.add_argument("--no-passphrase", action="store_true"); r.set_defaults(f=cmd_receive)

    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
