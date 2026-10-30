import hashlib
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import build_google_connectivity as tool


class GooglePayloadTests(unittest.TestCase):
    def original(self):
        data = bytearray(tool.PAYLOAD_BYTES)
        for offset, old, new in tool.EDITS:
            data[offset:offset + 4] = bytes.fromhex(old)
        return bytes(data)

    def test_exact_eight_words_and_no_other_changes(self):
        original = self.original()
        with patch.object(tool, 'PAYLOAD_SHA', hashlib.sha256(original).hexdigest()):
            result = tool.patch_payload(original)
        expected = bytearray(original)
        literal_replacements = [(0x60538, '09000014'), (0x60570, '09000014'),
                                (0x605a4, '06000014'), (0x605cc, '09000014'),
                                (0x1cba1d4, '44000014'), (0x1cba2f8, 'e4000014'),
                                (0x2f3600, '00000100'), (0x2f3ba0, '00000100')]
        for offset, new in literal_replacements:
            expected[offset:offset + 4] = bytes.fromhex(new)
            self.assertEqual(result[offset:offset + 4], bytes.fromhex(new))
        self.assertEqual(result, bytes(expected))
        self.assertEqual(len(result), len(original))
        self.assertEqual(sum(a != b for a, b in zip(result, original)), 23)

    def test_unpinned_input_refused(self):
        with self.assertRaisesRegex(ValueError, 'pin'):
            tool.patch_payload(self.original())

    def test_wrong_word_refused_even_with_matching_hash(self):
        original = bytearray(self.original())
        original[tool.EDITS[0][0]] ^= 1
        with patch.object(tool, 'PAYLOAD_SHA', hashlib.sha256(original).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'instruction or field'):
                tool.patch_payload(bytes(original))

    def test_bad_source_refused_before_output_or_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, avb, output = root / 'source', root / 'tool', root / 'output'
            source.write_bytes(b'changed source')
            avb.write_bytes(b'not executed')
            with patch.object(tool, 'runner') as runner:
                with self.assertRaisesRegex(ValueError, 'APEX pin mismatch'):
                    tool.build(source, avb, output)
            runner.assert_not_called()
            self.assertFalse(output.exists())

    def test_symlink_source_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / 'original'
            original.write_bytes(b'owner content')
            source = root / 'source'
            source.symlink_to(original)
            with self.assertRaisesRegex(ValueError, 'regular, non-symlink'):
                tool.build(source, root / 'missing-tool', root / 'output')
            self.assertEqual(original.read_bytes(), b'owner content')


if __name__ == '__main__':
    unittest.main()
