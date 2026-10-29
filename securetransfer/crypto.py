"""
Core cryptography for secure file transfer.

Scheme (encrypt-then-sign, hybrid):
  1. A random 256-bit AES key and 96-bit nonce are generated per file.
  2. The file is encrypted with AES-256-GCM  -> confidentiality + integrity.
  3. The AES key is wrapped with the RECEIVER's RSA public key (RSA-OAEP, SHA-256).
  4. The whole package (header + ciphertext) is signed with the SENDER's
     RSA private key (RSA-PSS, SHA-256)       -> authenticity + non-repudiation.

Receiver side: verify signature FIRST (reject tampered/forged data before
touching any secret), then unwrap the AES key and decrypt.

Package layout (.sft file):
  MAGIC(4) | header_len(4) | header(JSON) | cipher_len(8) | ciphertext | sig_len(4) | signature
  The signature covers everything before sig_len.
"""
import base64
import hashlib
import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SFT1"
VERSION = 1
RSA_BITS = 3072


class SecurityError(Exception):
    """Raised when a signature, key, or integrity check fails."""


# ------------------------------------------------------------------ keys
def generate_keypair(name, out_dir=".", passphrase=None, bits=RSA_BITS):
    """Create <name>_private.pem and <name>_public.pem. Returns (priv_path, pub_path)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    priv_path, pub_path = out / f"{name}_private.pem", out / f"{name}_public.pem"
    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv_path, pub_path


def load_private_key(path, passphrase=None):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(), passphrase.encode() if passphrase else None)


def load_public_key(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def fingerprint(public_key):
    """SHA-256 fingerprint of a public key (compare out-of-band to trust a key)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# --------------------------------------------------------------- helpers
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)


# ----------------------------------------------------------- protect/send
def protect_file(src, dst, sender_private_key, receiver_public_key):
    """Encrypt `src` for the receiver and sign it as the sender. Writes `dst`."""
    src, dst = Path(src), Path(dst)
    plaintext = src.read_bytes()

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    header = {
        "version": VERSION,
        "filename": src.name,
        "size": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "nonce": b64(nonce),
        "wrapped_key": b64(receiver_public_key.encrypt(aes_key, _OAEP)),
        "sender_fp": fingerprint(sender_private_key.public_key()),
        "receiver_fp": fingerprint(receiver_public_key),
        "algs": "AES-256-GCM/RSA-OAEP-SHA256/RSA-PSS-SHA256",
    }
    header_bytes = json.dumps(header, sort_keys=True).encode()
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, MAGIC + header_bytes)

    body = (MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
            + struct.pack(">Q", len(ciphertext)) + ciphertext)
    signature = sender_private_key.sign(body, _PSS, hashes.SHA256())
    dst.write_bytes(body + struct.pack(">I", len(signature)) + signature)
    return header


def _parse(blob):
    try:
        if blob[:4] != MAGIC:
            raise SecurityError("Not a secure-transfer package (bad magic).")
        pos = 4
        (hlen,) = struct.unpack_from(">I", blob, pos); pos += 4
        header_bytes = blob[pos:pos + hlen]; pos += hlen
        (clen,) = struct.unpack_from(">Q", blob, pos); pos += 8
        ciphertext = blob[pos:pos + clen]; pos += clen
        body_end = pos
        (slen,) = struct.unpack_from(">I", blob, pos); pos += 4
        signature = blob[pos:pos + slen]
        if len(header_bytes) != hlen or len(ciphertext) != clen or len(signature) != slen:
            raise SecurityError("Package is truncated.")
        return blob[:body_end], header_bytes, ciphertext, signature
    except struct.error as e:
        raise SecurityError("Package is malformed.") from e


# --------------------------------------------------------- verify/receive
def unprotect_file(src, out_dir, receiver_private_key, sender_public_key):
    """Verify sender's signature, then decrypt. Returns the output Path.

    Raises SecurityError on any failure; nothing is written in that case.
    """
    blob = Path(src).read_bytes()
    body, header_bytes, ciphertext, signature = _parse(blob)

    # 1) Authenticity + integrity of the whole package
    try:
        sender_public_key.verify(signature, body, _PSS, hashes.SHA256())
    except InvalidSignature as e:
        raise SecurityError("SIGNATURE INVALID: tampered data or wrong sender key.") from e

    header = json.loads(header_bytes)

    # 2) Decrypt
    try:
        aes_key = receiver_private_key.decrypt(unb64(header["wrapped_key"]), _OAEP)
    except ValueError as e:
        raise SecurityError("Cannot unwrap key: this file was not encrypted for you.") from e
    try:
        plaintext = AESGCM(aes_key).decrypt(unb64(header["nonce"]), ciphertext, MAGIC + header_bytes)
    except InvalidTag as e:
        raise SecurityError("Decryption failed: authentication tag mismatch.") from e

    # 3) Defence in depth: check the plaintext hash recorded by the sender
    if hashlib.sha256(plaintext).hexdigest() != header["sha256"]:
        raise SecurityError("Hash mismatch after decryption.")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(header["filename"]).name  # block path traversal
    out_path = out_dir / safe_name
    out_path.write_bytes(plaintext)
    return out_path
