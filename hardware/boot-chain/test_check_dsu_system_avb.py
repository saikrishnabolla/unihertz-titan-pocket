from pathlib import Path
import struct
import tempfile
import unittest

from check_dsu_system_avb import check, PROPERTIES, ROLLBACK_INDEX


class SystemAvbTests(unittest.TestCase):
    def fixture(self, path, name=b'system', properties=None, flags=0):
        fs = 4096
        total = 32768
        props = PROPERTIES if properties is None else properties
        descriptors = []
        tree = struct.pack('>QQIQQQIIIQQ32sIIII60s', 1, 240, 1, fs, fs, 4096,
                           4096, 4096, 0, 0, 0, b'sha256', 6, 32, 32, 0, bytes(60))
        descriptors.append((tree + name + bytes(64)).ljust(256, b'\0'))
        for key, value in props.items():
            key, value = key.encode(), value.encode()
            length = (32 + len(key) + len(value) + 2 + 7) // 8 * 8
            descriptors.append((struct.pack('>QQQQ', 0, length - 16, len(key), len(value))
                                + key + b'\0' + value + b'\0').ljust(length, b'\0'))
        data = b''.join(descriptors)
        header = bytearray(256)
        struct.pack_into('>4sIIQQI', header, 0, b'AVB0', 1, 0, 0, len(data), 1)
        struct.pack_into('>QQQII', header, 96, 0, len(data), ROLLBACK_INDEX, flags, 0)
        vbmeta = header + data
        with path.open('wb') as stream:
            stream.truncate(total)
            stream.seek(8192)
            stream.write(vbmeta)
            stream.seek(total - 64)
            stream.write(struct.pack('>4sIIQQQ28s', b'AVBf', 1, 0, fs, 8192, len(vbmeta), bytes(28)))
        return fs, total

    def test_expected_structure(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'system.img'
            sizes = self.fixture(path)
            self.assertEqual(check(path, *sizes)['properties'], PROPERTIES)

    def test_wrong_partition_properties_or_flags_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'system.img'
            for kwargs in [{'name': b'vendor'}, {'properties': {}}, {'flags': 2}]:
                sizes = self.fixture(path, **kwargs)
                with self.assertRaises(ValueError):
                    check(path, *sizes)


if __name__ == '__main__':
    unittest.main()
