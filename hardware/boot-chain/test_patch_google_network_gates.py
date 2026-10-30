import hashlib
import struct
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import patch_google_network_gates as tool


def fixture(name):
    data = bytearray(65536)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, 183)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, len(data), len(data), 4096)
    for offset, original, target in tool.SITES[name]:
        data[offset:offset + 4] = bytes.fromhex(original)
    return bytes(data)


class GoogleGateTests(unittest.TestCase):
    def test_only_six_reviewed_instructions_change_to_existing_successors(self):
        expected = {
            'netbpfload': ['09000014', '09000014', '06000014', '09000014'],
            'libnetd_updatable.so': ['44000014', 'e4000014'],
        }
        for name, words in expected.items():
            original = fixture(name)
            with patch.dict(tool.SOURCE_SHA, {name: hashlib.sha256(original).hexdigest()}):
                result, report = tool.patch_native(name, original)
            self.assertEqual(len(result), len(original))
            self.assertEqual([s['new_hex'] for s in report['sites']], words)
            for (offset, _, _), word in zip(tool.SITES[name], words):
                self.assertEqual(result[offset:offset + 4], bytes.fromhex(word))
            restored = bytearray(result)
            for offset, word, target in tool.SITES[name]:
                restored[offset:offset + 4] = bytes.fromhex(word)
            self.assertEqual(bytes(restored), original)

    def test_unpinned_input_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'pinned original'):
            tool.patch_native('netbpfload', fixture('netbpfload'))

    def test_instruction_or_mapping_mismatch_is_refused(self):
        for change, message in [('instruction', 'instruction mismatch'), ('mapping', 'mapping')]:
            data = bytearray(fixture('netbpfload'))
            if change == 'instruction':
                data[0xa538] ^= 1
            else:
                struct.pack_into('<Q', data, 64 + 16, 4)
            with patch.dict(tool.SOURCE_SHA, {'netbpfload': hashlib.sha256(data).hexdigest()}):
                with self.assertRaisesRegex(ValueError, message):
                    tool.patch_native('netbpfload', bytes(data))

    def test_file_build_preserves_source_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            original = fixture('netbpfload')
            source.write_bytes(original)
            with patch.dict(tool.SOURCE_SHA, {'netbpfload': hashlib.sha256(original).hexdigest()}):
                tool.build(source, 'netbpfload', root / 'output')
                with self.assertRaises(FileExistsError):
                    tool.build(source, 'netbpfload', root / 'output')
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue((root / 'output/report.json').is_file())


if __name__ == '__main__':
    unittest.main()
