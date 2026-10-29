import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from securetransfer import *


class TestSecureTransfer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        for n in ("alice", "bob", "eve"):
            generate_keypair(n, cls.tmp, bits=2048)  # 2048 = faster tests
        L = lambda n: (load_private_key(cls.tmp / f"{n}_private.pem"), load_public_key(cls.tmp / f"{n}_public.pem"))
        cls.alice, cls.alice_pub = L("alice"); cls.bob, cls.bob_pub = L("bob"); cls.eve, cls.eve_pub = L("eve")
        cls.src = cls.tmp / "secret.txt"; cls.src.write_bytes(os.urandom(100_000) + b"hello")
        cls.pkg = cls.tmp / "secret.sft"
        protect_file(cls.src, cls.pkg, cls.alice, cls.bob_pub)

    def test_roundtrip(self):
        out = unprotect_file(self.pkg, self.tmp / "o1", self.bob, self.alice_pub)
        self.assertEqual(out.read_bytes(), self.src.read_bytes())

    def test_ciphertext_hides_plaintext(self):
        self.assertNotIn(b"hello", self.pkg.read_bytes())

    def test_tampered_ciphertext_rejected(self):
        b = bytearray(self.pkg.read_bytes()); b[1500] ^= 1
        t = self.tmp / "t.sft"; t.write_bytes(bytes(b))
        with self.assertRaises(SecurityError): unprotect_file(t, self.tmp / "o2", self.bob, self.alice_pub)

    def test_truncated_rejected(self):
        t = self.tmp / "tr.sft"; t.write_bytes(self.pkg.read_bytes()[:-50])
        with self.assertRaises(SecurityError): unprotect_file(t, self.tmp / "o3", self.bob, self.alice_pub)

    def test_wrong_sender_key_rejected(self):  # forged identity
        with self.assertRaises(SecurityError): unprotect_file(self.pkg, self.tmp / "o4", self.bob, self.eve_pub)

    def test_wrong_receiver_rejected(self):  # eve intercepts
        with self.assertRaises(SecurityError): unprotect_file(self.pkg, self.tmp / "o5", self.eve, self.alice_pub)

    def test_resigned_by_attacker_rejected(self):
        evil = self.tmp / "evil.sft"; protect_file(self.src, evil, self.eve, self.bob_pub)
        with self.assertRaises(SecurityError): unprotect_file(evil, self.tmp / "o6", self.bob, self.alice_pub)

    def test_no_output_on_failure(self):
        d = self.tmp / "o7"
        try: unprotect_file(self.pkg, d, self.eve, self.alice_pub)
        except SecurityError: pass
        self.assertFalse(d.exists() and any(d.iterdir()))

    def test_fingerprint_stable(self):
        self.assertEqual(fingerprint(self.alice_pub), fingerprint(load_public_key(self.tmp / "alice_public.pem")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
