import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import build_vbmeta as b


class VbmetaTests(unittest.TestCase):
    def test_rejects_wrong_size(self):
        with self.assertRaisesRegex(ValueError, '8 MiB'):
            b.transform(b'AVB0')

    def test_rejects_unpinned_input(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            b.transform(bytes(b.IMAGE_SIZE))

    def test_header_and_flags_validation(self):
        data = bytearray(b.IMAGE_SIZE)
        def run(value):
            raw = bytes(value)
            with patch.object(b, 'SOURCE_SHA256', hashlib.sha256(raw).hexdigest()):
                return b.transform(raw)
        with self.assertRaisesRegex(ValueError, 'AVB header'):
            run(data)
        data[:4] = b'AVB0'
        data[123] = 1
        with self.assertRaisesRegex(ValueError, 'flags 0'):
            run(data)

    def test_only_flags_change(self):
        data = bytearray(b.IMAGE_SIZE)
        data[:4] = b'AVB0'
        expected = bytearray(data)
        expected[123] = 3
        with patch.object(b, 'SOURCE_SHA256', hashlib.sha256(data).hexdigest()), patch.object(b, 'OUTPUT_SHA256', hashlib.sha256(expected).hexdigest()):
            self.assertEqual(b.transform(bytes(data)), bytes(expected))

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'source', Path(directory)/'output'
            source.write_bytes(b'source')
            output.write_bytes(b'keep')
            with patch.object(b, 'transform', return_value=b'new'):
                with self.assertRaises(FileExistsError):
                    b.build(source, output)
            self.assertEqual(output.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('TITAN_STOCK_VBMETA'), 'Set TITAN_STOCK_VBMETA for private firmware verification')
    def test_real_stock_input(self):
        source = Path(os.environ['TITAN_STOCK_VBMETA'])
        raw = source.read_bytes()
        result = b.transform(raw)
        self.assertEqual([(i,a,z) for i,(a,z) in enumerate(zip(raw,result)) if a!=z], [(123,0,3)])
        self.assertEqual(hashlib.sha256(result).hexdigest(), b.OUTPUT_SHA256)


if __name__ == '__main__':
    unittest.main()
