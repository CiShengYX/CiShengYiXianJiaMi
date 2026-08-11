import io
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from PIL import Image


PROJECT_PARENT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_PARENT not in sys.path:
    sys.path.insert(0, PROJECT_PARENT)

from CiShengYiXianJiaMi import encrypt_core as core


class EncryptCoreTests(unittest.TestCase):
    def roundtrip(self, payload, password="", filename="example.bin", chunk_size=core.DEFAULT_CHUNK_SIZE, expected_filename=None):
        output = io.BytesIO()
        info = core.encrypt_stream(
            io.BytesIO(payload), output, core.CONTENT_FILE, password, filename,
            "application/octet-stream", len(payload), chunk_size,
        )
        encrypted = output.getvalue()
        decrypted, metadata = core.decrypt_data_with_metadata(encrypted, password)
        self.assertEqual(decrypted, payload)
        self.assertEqual(metadata["filename"], expected_filename or filename)
        self.assertEqual(metadata["version"], 3)
        return encrypted, info

    def test_v3_empty_and_small_roundtrip(self):
        encrypted, info = self.roundtrip(b"", filename="empty.bin")
        self.assertEqual(info["chunk_count"], 1)
        self.assertTrue(encrypted.startswith(b"\x89PNG\r\n\x1a\n"))
        with Image.open(io.BytesIO(encrypted)) as cover:
            cover.load()
            self.assertGreater(cover.width, 0)
            self.assertGreater(cover.height, 0)
        self.roundtrip(b"hello" * 1000, "example-strong-password", "\u6d4b\u8bd5.bin")

    def test_v3_multiple_chunks_roundtrip(self):
        payload = os.urandom(3 * 65536 + 117)
        _, info = self.roundtrip(payload, "password", "multi.bin", 65536)
        self.assertEqual(info["chunk_count"], 4)

    def test_wrong_password_and_tampering_fail(self):
        encrypted, _ = self.roundtrip(os.urandom(200000), "correct", "data.bin", 65536)
        with self.assertRaises(Exception):
            core.decrypt_data(encrypted, "wrong")
        damaged = bytearray(encrypted)
        damaged[-20] ^= 0x80
        with self.assertRaises(Exception):
            core.decrypt_data(bytes(damaged), "correct")
        with self.assertRaises(Exception):
            core.decrypt_data(encrypted[:-1], "correct")

    def test_v1_legacy_decryption(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        payload = b"legacy-data" * 200
        password = "old-password"
        salt = bytes(range(16))
        nonce = bytes(range(12))
        key = core._derive_key(password, salt)
        ciphertext_and_tag = AESGCM(key).encrypt(nonce, payload, None)
        filename = "legacy.bin".encode("utf-8")
        packet = (
            core.MAGIC + bytes([1, core.CONTENT_FILE, 1]) + salt + nonce
            + ciphertext_and_tag[-16:] + struct.pack(">H", len(filename)) + filename
            + struct.pack(">Q", len(ciphertext_and_tag) - 16) + ciphertext_and_tag[:-16]
        )
        encrypted = core._get_clean_cover_png() + packet
        decrypted, metadata = core.decrypt_data_with_metadata(encrypted, password)
        self.assertEqual(decrypted, payload)
        self.assertEqual(metadata["version"], 1)
        self.assertEqual(metadata["filename"], "legacy.bin")

    def test_v2_compatibility_decryption(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        payload = b"v2-compatibility" * 10000
        password = "old-v2-password"
        chunk_size = 65536
        salt = bytes(range(16))
        nonce_prefix = bytes(range(8))
        chunk_count = (len(payload) + chunk_size - 1) // chunk_size
        metadata = json.dumps(
            {"filename": "old-v2.bin", "mime": "application/octet-stream", "size": len(payload), "version": 2},
            ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        header = core._V2_FIXED.pack(
            core.MAGIC, core.COMPAT_VERSION, core.CONTENT_FILE, 1, 0,
            chunk_size, len(payload), chunk_count, salt, nonce_prefix, len(metadata),
        ) + metadata
        aesgcm = AESGCM(core._derive_key_v2(password, salt))
        packet = bytearray(header)
        for index in range(chunk_count):
            plain = payload[index * chunk_size:(index + 1) * chunk_size]
            nonce = nonce_prefix + struct.pack(">I", index)
            aad = header + struct.pack(">I", index)
            packet.extend(struct.pack(">I", len(plain)))
            packet.extend(aesgcm.encrypt(nonce, plain, aad))
        encrypted = core._get_clean_cover_png() + bytes(packet)
        decrypted, parsed = core.decrypt_data_with_metadata(encrypted, password)
        self.assertEqual(decrypted, payload)
        self.assertEqual(parsed["version"], 2)
        self.assertEqual(parsed["filename"], "old-v2.bin")

    def test_metadata_and_png_boundary_are_strict(self):
        encrypted, _ = self.roundtrip(b"payload", filename="folder/name.bin", expected_filename="name.bin")
        _, metadata = core.decrypt_data_with_metadata(encrypted)
        self.assertEqual(metadata["filename"], "name.bin")
        packet_offset = core.png_end_offset(encrypted)
        self.assertEqual(encrypted[packet_offset:packet_offset + 8], core.MAGIC)
        with self.assertRaises(core.CSYXFormatError):
            core.png_end_offset(b"not a png")

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_v3_webcrypto_compatibility(self):
        payload = os.urandom(130000)
        password = "browser-compat-password"
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "compat.png")
            with open(path, "wb") as destination:
                core.encrypt_stream(
                    io.BytesIO(payload), destination, core.CONTENT_FILE, password,
                    "compat.bin", "application/octet-stream", len(payload), 65536,
                )
            script = os.path.join(os.path.dirname(__file__), "verify_v2_browser_compat.mjs")
            completed = subprocess.run(
                [shutil.which("node"), script, path, password, hashlib.sha256(payload).hexdigest()],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("V3 browser compatibility OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
