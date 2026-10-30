import struct
import tempfile
import unittest
from pathlib import Path

from google_diag_build import build


class RecorderElfTests(unittest.TestCase):
    def test_release_load_segments_are_backed_for_linux_4_14(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'titan-diag'
            build(output, kernel_only=True)
            data = output.read_bytes()
            header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
            loads = []
            for index in range(header[10]):
                segment = struct.unpack_from('<IIQQQQQQ', data, header[5] + index * header[9])
                kind, flags, offset, address, _, filesz, memsz, alignment = segment
                if kind != 1 or not memsz:
                    continue
                loads.append(segment)
                self.assertEqual(alignment, 4096)
                self.assertEqual(offset % alignment, address % alignment)
                if address % 4096:
                    self.assertLess(offset // 4096 * 4096, len(data),
                                    'Linux 4.14 BSS zeroing touches a mapping wholly beyond EOF')
                self.assertLessEqual(offset + filesz, len(data))
                self.assertFalse(flags & 1 and flags & 2, 'Writable executable segment')
            self.assertTrue(loads)
            self.assertTrue(any(s[1] & 1 and s[3] <= header[4] < s[3] + s[6] for s in loads))
            for first in loads:
                for second in loads:
                    if first is second or not first[1] & 1 or not second[1] & 2:
                        continue
                    self.assertTrue((first[3] + first[6] + 4095) // 4096 * 4096 <= second[3] // 4096 * 4096
                                    or (second[3] + second[6] + 4095) // 4096 * 4096 <= first[3] // 4096 * 4096,
                                    'Writable mapping overlaps executable page')


if __name__ == '__main__':
    unittest.main()
