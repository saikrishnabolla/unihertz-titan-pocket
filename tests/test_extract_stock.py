# SPDX-License-Identifier: Apache-2.0
import gzip
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('extract_stock', Path(__file__).parents[1] / 'tools/extract_stock.py')
x = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(x)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sealed_header(tables, descriptors):
    header = bytearray(128)
    struct.pack_into('<I2HI', header, 0, 0x414C5030, 10, 0, 128)
    struct.pack_into('<I', header, 44, len(tables))
    header[48:80] = hashlib.sha256(tables).digest()
    for at, descriptor in zip((80, 92, 104, 116), descriptors):
        struct.pack_into('<3I', header, at, *descriptor)
    header[12:44] = hashlib.sha256(header).digest()
    return bytes(header) + bytes(tables)


class ExtractStockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.output = self.root / 'out'
        self.source = self.root / 'super.raw'
        self.maximum, self.slots = 65536, 2
        self.size = 1048576 + 3 * 4096
        self.policy = {'super_bytes': self.size, 'metadata_max_size': self.maximum,
                       'metadata_slots': self.slots, 'partitions': {}}
        entries, extents = [], []
        self.data = bytearray(self.size)
        for index, name in enumerate(('product', 'vendor', 'system')):
            offset, payload = 1048576 + index * 4096, bytes([65 + index]) * 4096
            self.data[offset:offset+4096] = payload
            self.policy['partitions'][name] = {'offset': offset, 'bytes': 4096, 'sha256': digest(payload)}
            entries.append(struct.pack('<36s4I', name.encode(), 1, index, 1, 1))
            extents.append(struct.pack('<QIQI', 8, 0, offset // 512, 0))
        groups = [struct.pack('<36sIQ', b'default', 0, 0), struct.pack('<36sIQ', b'main', 0, self.size)]
        devices = [struct.pack('<QIIQ36sI', 2048, 1048576, 0, self.size, b'super', 0)]
        self.tables = bytearray(b''.join(entries + extents + groups + devices))
        self.descriptors = [(0, 3, 52), (156, 3, 24), (228, 2, 48), (324, 1, 64)]
        geometry = bytearray(struct.pack('<II32sIII', 0x616C4467, 52, b'\0' * 32, self.maximum, self.slots, 4096))
        geometry[8:40] = hashlib.sha256(geometry).digest()
        for offset in (4096, 8192):
            self.data[offset:offset+52] = geometry
        self.save_metadata()

    def save_metadata(self):
        blob = sealed_header(self.tables, self.descriptors)
        self.policy['metadata_sha256'] = digest(blob)
        for index in range(4):
            offset = 12288 + index * self.maximum
            self.data[offset:offset+len(blob)] = blob
        self.source.write_bytes(self.data)
        self.policy['source_sha256'] = digest(self.data)

    def run_extract(self):
        return x.extract(self.source, self.output, _policy=self.policy)

    def test_raw_and_gzip_produce_exact_only_requested_images(self):
        for compressed in (False, True):
            with self.subTest(gzip=compressed):
                if compressed:
                    self.source.write_bytes(gzip.compress(self.data))
                report = self.run_extract()
                self.assertEqual(set(p.name for p in self.output.iterdir()), {'system.img', 'vendor.img', 'report.json'})
                self.assertEqual(report['source_sha256'], digest(self.data))
                self.assertFalse(report['device_actions'])
                for name in ('system', 'vendor'):
                    self.assertEqual(digest((self.output / (name + '.img')).read_bytes()), self.policy['partitions'][name]['sha256'])
                for path in self.output.iterdir():
                    path.unlink()
                self.output.rmdir()

    def test_existing_output_and_input_symlinks_rejected(self):
        self.output.mkdir()
        (self.output / 'keep').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'new directory'):
            self.run_extract()
        self.assertEqual((self.output / 'keep').read_text(), 'keep')
        self.output = self.root / 'new'
        linked = self.root / 'linked.raw'
        linked.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            x.extract(linked, self.output, _policy=self.policy)
        directory = self.root / 'linked-dir'
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            x.extract(self.source, directory / 'out2', _policy=self.policy)

    def test_output_symlink_and_block_special_sources_rejected(self):
        self.output.symlink_to(self.root / 'absent')
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            self.run_extract()
        self.output.unlink()
        with self.assertRaisesRegex(ValueError, 'regular file'):
            x.extract('/dev/null', self.output, _policy=self.policy)

    def test_changed_payload_rejected_without_outputs(self):
        self.data[self.policy['partitions']['vendor']['offset']] ^= 1
        self.source.write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, 'partition hash'):
            self.run_extract()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.stock-extract-*')), [])

    def test_truncated_and_oversized_expansion_rejected(self):
        for data in (self.data[:-1], self.data + b'x'):
            with self.subTest(bytes=len(data)):
                self.source.write_bytes(gzip.compress(data))
                with self.assertRaises(ValueError):
                    self.run_extract()
                self.assertFalse(self.output.exists())

    def test_metadata_and_backup_geometry_checksum_rejected(self):
        self.data[8192+8] ^= 1
        self.source.write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, 'Geometry copies'):
            self.run_extract()

    def test_unexpected_partition_path_rejected(self):
        self.tables[:36] = struct.pack('<36s', b'../boot')
        self.save_metadata()
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            self.run_extract()

    def test_extent_overflow_overlap_and_wrong_target_rejected(self):
        original = bytes(self.tables)
        for extent in ((2**64-1, 0, 2048, 0), (8, 0, 2048, 1), (8, 1, 0, 0), (8, 0, 2048, 0)):
            with self.subTest(extent=extent):
                self.tables[:] = original
                self.tables[180:204] = struct.pack('<QIQI', *extent)
                self.save_metadata()
                with self.assertRaises(ValueError):
                    self.run_extract()
                self.assertFalse(self.output.exists())

    def test_overlapping_tables_and_missing_partitions_rejected(self):
        self.descriptors[1] = (0, 3, 24)
        self.save_metadata()
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            self.run_extract()

    def test_changed_unrequested_product_partition_rejected(self):
        self.data[self.policy['partitions']['product']['offset']] ^= 1
        self.source.write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, 'SUPER hash differs'):
            self.run_extract()
        self.assertFalse(self.output.exists())

    def test_metadata_pin_cannot_be_changed_by_input(self):
        self.policy['metadata_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'metadata pin'):
            self.run_extract()

    def test_sparse_input_explicitly_rejected(self):
        self.source.write_bytes(b'\x3a\xff\x26\xed')
        with self.assertRaisesRegex(ValueError, 'sparse'):
            self.run_extract()


if __name__ == '__main__':
    unittest.main()
