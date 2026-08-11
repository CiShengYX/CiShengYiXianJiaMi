import os
import shutil
import sys
import tempfile
import unittest

import numpy as np


PROJECT_PARENT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_PARENT not in sys.path:
    sys.path.insert(0, PROJECT_PARENT)

from CiShengYiXianJiaMi import encrypt_core
from CiShengYiXianJiaMi import nodes


class FakeTensor:
    def __init__(self, array):
        self.array = np.asarray(array, dtype=np.float32)

    @property
    def shape(self):
        return self.array.shape

    def __getitem__(self, key):
        return FakeTensor(self.array[key])

    def detach(self):
        return self

    def cpu(self):
        return self

    def numpy(self):
        return self.array


class FolderPathsStub:
    def __init__(self, output_dir, temp_dir, input_dir):
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        self.input_dir = input_dir

    def get_output_directory(self):
        return self.output_dir

    def get_temp_directory(self):
        return self.temp_dir

    def get_input_directory(self):
        return self.input_dir


class NodeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.output_dir = os.path.join(self.workspace.name, "output")
        self.temp_dir = os.path.join(self.workspace.name, "temp")
        self.input_dir = os.path.join(self.workspace.name, "input")
        os.makedirs(self.output_dir)
        os.makedirs(self.temp_dir)
        os.makedirs(self.input_dir)
        self.old_folder_paths = nodes.folder_paths
        nodes.folder_paths = FolderPathsStub(self.output_dir, self.temp_dir, self.input_dir)

    def tearDown(self):
        nodes.folder_paths = self.old_folder_paths
        self.workspace.cleanup()

    def assert_standard_result(self, result, count=1):
        self.assertIn("ui", result)
        self.assertEqual(len(result["ui"]["images"]), count)
        self.assertEqual(len(result["ui"]["csyx_image"]), count)
        for descriptor in result["ui"]["images"]:
            self.assertEqual(descriptor["type"], "output")
            self.assertEqual(descriptor["subfolder"], "")
            self.assertTrue(os.path.isfile(os.path.join(self.output_dir, descriptor["filename"])))
        return result["ui"]["images"]

    def decrypt_descriptor(self, descriptor, password=""):
        path = os.path.join(self.output_dir, descriptor["filename"])
        with open(path, "rb") as handle:
            return encrypt_core.decrypt_data_with_metadata(handle.read(), password)

    def test_image_text_file_and_audio_nodes(self):
        images = FakeTensor(np.random.default_rng(1).random((2, 32, 48, 3), dtype=np.float32))
        image_result = nodes.ImageEncryptNode().encrypt(images, "example-strong-password", "batch")
        descriptors = self.assert_standard_result(image_result, 2)
        for descriptor in descriptors:
            plain, metadata = self.decrypt_descriptor(descriptor, "example-strong-password")
            self.assertTrue(plain.startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertEqual(metadata["content_type"], encrypt_core.CONTENT_IMAGE)

        text_result = nodes.TextEncryptNode().encrypt("hello \u4e16\u754c", "", "note")
        descriptor = self.assert_standard_result(text_result)[0]
        plain, _ = self.decrypt_descriptor(descriptor)
        self.assertEqual(plain.decode("utf-8"), "hello \u4e16\u754c")

        source_path = os.path.join(self.input_dir, "source.dat")
        payload = os.urandom(3 * 1024 * 1024 + 19)
        with open(source_path, "wb") as handle:
            handle.write(payload)
        file_result = nodes.FileEncryptNode().encrypt("source.dat", "pw", "archive")
        descriptor = self.assert_standard_result(file_result)[0]
        plain, metadata = self.decrypt_descriptor(descriptor, "pw")
        self.assertEqual(plain, payload)
        self.assertEqual(metadata["filename"], "source.dat")

        with self.assertRaisesRegex(ValueError, "input"):
            nodes.FileEncryptNode().encrypt(os.path.join(self.workspace.name, "outside.dat"), "pw", "blocked")

        waveform = FakeTensor(np.sin(np.linspace(0, 30, 16000, dtype=np.float32))[None, None, :])
        audio_result = nodes.AudioEncryptNode().encrypt(
            {"waveform": waveform, "sample_rate": 16000}, "", "sound"
        )
        descriptor = self.assert_standard_result(audio_result)[0]
        plain, metadata = self.decrypt_descriptor(descriptor)
        self.assertTrue(plain.startswith(b"RIFF"))
        self.assertEqual(metadata["content_type"], encrypt_core.CONTENT_AUDIO)

    @unittest.skipUnless(shutil.which("ffmpeg"), "环境中没有 FFmpeg")
    def test_short_video_node(self):
        frames = FakeTensor(np.random.default_rng(2).random((4, 32, 48, 3), dtype=np.float32))
        result = nodes.VideoEncryptNode().encrypt(frames, 8.0, None, "", "clip")
        descriptor = self.assert_standard_result(result)[0]
        plain, metadata = self.decrypt_descriptor(descriptor)
        self.assertGreater(len(plain), 100)
        self.assertIn(b"ftyp", plain[:64])
        self.assertEqual(metadata["content_type"], encrypt_core.CONTENT_VIDEO)

    def test_failed_write_leaves_no_registered_file(self):
        class ShortSource:
            def read(self, size=-1):
                return b"x" if size else b""

        with self.assertRaises(OSError):
            nodes._save_encrypted_stream(
                ShortSource(), 100, encrypt_core.CONTENT_FILE, "", "bad.bin",
                "application/octet-stream", "broken", "broken",
            )
        self.assertEqual(os.listdir(self.output_dir), [])

    def test_failed_image_batch_removes_earlier_outputs(self):
        images = FakeTensor(np.zeros((2, 8, 8, 3), dtype=np.float32))
        original = nodes._tensor_frame_to_png
        calls = {"count": 0}

        def fail_second(frame):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("simulated encoder failure")
            return original(frame)

        nodes._tensor_frame_to_png = fail_second
        try:
            with self.assertRaisesRegex(RuntimeError, "simulated"):
                nodes.ImageEncryptNode().encrypt(images, "", "batch-fail")
        finally:
            nodes._tensor_frame_to_png = original
        self.assertEqual(os.listdir(self.output_dir), [])

    def test_frontend_does_not_persist_password_widget(self):
        frontend = os.path.join(os.path.dirname(os.path.dirname(__file__)), "js", "csyx_encrypt_preview.js")
        with open(frontend, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn('item?.name === "密码"', source)
        self.assertIn("password.serialize = false", source)


if __name__ == "__main__":
    unittest.main()
