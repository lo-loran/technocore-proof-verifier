
import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "verify_technocore.py"

spec = importlib.util.spec_from_file_location(
    "verify_technocore", MODULE_PATH
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class VerifyTechnocoreTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # did:key for an Ed25519 public key: multicodec ed01 + key, Base58btc.
        self.did = "did:key:z" + self.base58_encode(b"\xed\x01" + public_key)
        self.room = "test-room"
        self.nonce = 12345678901234567890
        self.content = "Local test message"
        self.seq = 42

        payload = f"{self.room}|{self.nonce}|{self.content}".encode()
        signature = self.private_key.sign(payload)
        signature_text = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        self.posted = {
            "from": self.did,
            "nonce": self.nonce,
            "text": self.content,
            "sig": signature_text,
            "seq": self.seq,
        }
        self.receipt = {
            "room": self.room,
            "posted": dict(self.posted),
            "messages": [dict(self.posted)],
        }
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = Path(self.temp_dir.name) / "receipt.json"
        self.write_receipt()

    @staticmethod
    def base58_encode(data):
        alphabet = verifier.ALPHABET
        zeros = len(data) - len(data.lstrip(b"\x00"))
        number = int.from_bytes(data, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = alphabet[remainder] + encoded
        return "1" * zeros + encoded

    def write_receipt(self):
        self.path.write_text(
            json.dumps(self.receipt),
            encoding="utf-8",
        )

    def test_valid_receipt_passes(self):
        seq, did = verifier.verify(self.path, self.did)
        self.assertEqual(seq, self.seq)
        self.assertEqual(did, self.did)

    def test_wrong_expected_did_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "expected identity"):
            verifier.verify(self.path, "did:key:zWrong")

    def test_tampered_content_is_rejected(self):
        self.receipt["posted"]["text"] = "Tampered message"
        self.receipt["messages"][0]["text"] = "Tampered message"
        self.write_receipt()
        with self.assertRaises(verifier.InvalidSignature):
            verifier.verify(self.path, self.did)

    def test_noncanonical_signature_is_rejected(self):
        self.receipt["posted"]["sig"] += "="
        self.receipt["messages"][0]["sig"] += "="
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "Non-canonical"):
            verifier.verify(self.path, self.did)

    def test_duplicate_sequence_is_rejected(self):
        self.receipt["messages"].append(dict(self.posted))
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            verifier.verify(self.path, self.did)

    def test_inconsistent_message_is_rejected(self):
        self.receipt["messages"][0]["text"] = "Different text"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "disagree on text"):
            verifier.verify(self.path, self.did)

    def test_invalid_room_is_rejected(self):
        self.receipt["room"] = "room|injected"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "Invalid room"):
            verifier.verify(self.path, self.did)

    def test_non_object_json_is_rejected(self):
        self.path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON root"):
            verifier.verify(self.path, self.did)


if __name__ == "__main__":
    unittest.main(verbosity=2)
