"""Real encryption over explicit synthetic texts; no host-data collection."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tools import safe_logd as codec

class SafeLogdTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.archive = self.root / 'build-cafebabe.logd'
        self.texts = {name: 'Synthetic UTF-8 诊断\n' + name for name in codec.REQUIRED_FILES}

    def pack(self):
        return codec.pack_diagnostic_texts(self.archive, self.texts)

    def link(self, path, target, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable')

    def test_roundtrip_and_fresh_key_nonce(self):
        key = self.pack()
        first = self.archive.read_bytes()
        self.assertTrue(first.startswith(codec.MAGIC))
        self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)
        self.assertEqual(codec.unpack_diagnostic_texts(self.archive, key), self.texts)
        self.assertNotIn(b'Synthetic UTF-8', first)
        second_path = self.root / 'second.logd'
        second_key = codec.pack_diagnostic_texts(second_path, self.texts)
        self.assertNotEqual(key, second_key)
        start = len(codec.MAGIC)
        self.assertNotEqual(first[start:start+12], second_path.read_bytes()[start:start+12])

    def test_pack_has_no_input_filesystem_discovery(self):
        original_open = Path.open
        def only_destination(path, *args, **kwargs):
            self.assertEqual(path, self.archive)
            self.assertEqual(args, ('xb',))
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', only_destination), \
                patch.object(Path, 'home', side_effect=AssertionError('no HOME lookup')), \
                patch.object(os, 'walk', side_effect=AssertionError('no walking')), \
                patch.object(Path, 'rglob', side_effect=AssertionError('no discovery')):
            self.pack()

    def test_exact_file_set_and_text_types(self):
        for texts in ({}, {**self.texts, '../secret': 'x'}, {**self.texts, '/absolute': 'x'},
                      {**self.texts, 'build.log': b'bytes'},
                      {k: v for k, v in self.texts.items() if k != 'build.log'}):
            with self.subTest(keys=list(texts)), self.assertRaises(ValueError):
                codec.pack_diagnostic_texts(self.archive, texts)
            self.assertFalse(self.archive.exists())

    def test_size_limits_fail_without_truncating(self):
        for constant in ('MAX_FILE_BYTES', 'MAX_TOTAL_BYTES', 'MAX_PAYLOAD_BYTES'):
            with self.subTest(limit=constant), patch.object(codec, constant, 2), \
                    self.assertRaisesRegex(ValueError, 'limit'):
                self.pack()
        self.assertFalse(self.archive.exists())

    def test_existing_output_is_not_overwritten(self):
        self.archive.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError): self.pack()
        self.assertEqual(self.archive.read_bytes(), b'preserve')

    def test_pack_output_symlink_is_not_followed(self):
        target = self.root / 'private'
        target.write_bytes(b'preserve')
        self.link(self.archive, target)
        with self.assertRaises(FileExistsError): self.pack()
        self.assertEqual(target.read_bytes(), b'preserve')

    def test_wrong_or_malformed_keys(self):
        self.pack()
        wrong = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()
        for key in (wrong, None, '', 'x'*44, '?'*44, 'é'*44):
            with self.subTest(key=key), self.assertRaises(ValueError):
                codec.unpack_diagnostic_texts(self.archive, key)

    def test_header_nonce_ciphertext_and_tag_tampering(self):
        key = self.pack()
        original = self.archive.read_bytes()
        for offset in (0, len(codec.MAGIC)-1, len(codec.MAGIC), len(codec.MAGIC)+12, -1):
            damaged = bytearray(original)
            damaged[offset] ^= 1
            self.archive.write_bytes(damaged)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                codec.unpack_diagnostic_texts(self.archive, key)

    def test_truncated_and_oversized_archive(self):
        key = self.pack()
        original = self.archive.read_bytes()
        for data in (b'', original[:10], original[:-1]):
            self.archive.write_bytes(data)
            with self.assertRaises(ValueError): codec.unpack_diagnostic_texts(self.archive, key)
        self.archive.write_bytes(original)
        with patch.object(codec, 'MAX_ARCHIVE_BYTES', 10), self.assertRaisesRegex(ValueError, 'limit'):
            codec.unpack_diagnostic_texts(self.archive, key)

    def test_input_symlink(self):
        key = self.pack()
        link = self.root / 'link.logd'
        self.link(link, self.archive)
        with self.assertRaisesRegex(ValueError, 'symbolic'):
            codec.unpack_diagnostic_texts(link, key)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO unavailable')
    def test_nonregular_input_does_not_block(self):
        os.mkfifo(self.archive)
        key = base64.urlsafe_b64encode(b'k'*32).decode()
        with self.assertRaisesRegex(ValueError, 'regular file'):
            codec.unpack_diagnostic_texts(self.archive, key)

    def test_authenticated_bad_schema_and_traversal(self):
        for doc in ([], {'format': 'old', 'files': self.texts},
                    {'format': codec.FORMAT, 'files': {'../escape': 'x'}},
                    {'format': codec.FORMAT, 'files': self.texts, 'extra': True},
                    b'{"format":"safe-logd-v1","format":"safe-logd-v1","files":{}}'):
            raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
            key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(12)
            self.archive.write_bytes(codec.MAGIC + nonce + AESGCM(key).encrypt(nonce, raw, codec.MAGIC))
            with self.assertRaises(ValueError):
                codec.unpack_diagnostic_texts(self.archive, base64.urlsafe_b64encode(key).decode())

    def test_decrypted_text_limits(self):
        key = self.pack()
        with patch.object(codec, 'MAX_FILE_BYTES', 2), self.assertRaisesRegex(ValueError, 'limit'):
            codec.unpack_diagnostic_texts(self.archive, key)

    def test_extract_existing_or_symlink_directory(self):
        target = self.root / 'existing'
        target.mkdir()
        (target / 'build.log').write_text('preserve')
        link = self.root / 'linked-output'
        self.link(link, target, True)
        for output in (target, link):
            with self.assertRaises(FileExistsError): codec.extract_diagnostic_texts(self.texts, output)
        self.assertEqual((target / 'build.log').read_text(), 'preserve')

    def test_extract_traversal_before_any_writes(self):
        output = self.root / 'out'
        with self.assertRaises(ValueError):
            codec.extract_diagnostic_texts({**self.texts, '../escape': 'bad'}, output)
        self.assertFalse(output.exists())
        self.assertFalse((self.root / 'escape').exists())

    def test_cli_roundtrip(self):
        key = self.pack()
        metadata = self.root / 'build-cafebabe.json'
        metadata.write_text(json.dumps({'format': codec.FORMAT, 'password': key}))
        output = self.root / 'unpacked'
        self.assertEqual(codec.main(['unpack', str(self.archive), str(output), '--metadata', str(metadata)]), 0)
        self.assertEqual({p.name: p.read_text() for p in output.iterdir()}, self.texts)

    def test_cli_symlink_metadata_writes_nothing(self):
        key = self.pack()
        real = self.root / 'real.json'
        real.write_text(json.dumps({'format': codec.FORMAT, 'password': key}))
        link = self.root / 'linked.json'
        self.link(link, real)
        output = self.root / 'unpacked'
        with self.assertRaises(SystemExit) as caught:
            codec.main(['unpack', str(self.archive), str(output), '--metadata', str(link)])
        self.assertEqual(caught.exception.code, 1)
        self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
