import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest

from read_erofs_metadata import Image, Invalid, inventory


def xentry(index, name, value):
    data = struct.pack('<BBH', len(name), index, len(value)) + name + value
    return data + b'\0' * (-len(data) % 4)


def xbody(inline=b'', shared=()):
    return struct.pack('<IB7x', 0, len(shared)) + b''.join(struct.pack('<I', i) for i in shared) + inline


def compact(mode=stat.S_IFREG | 0o640, layout=2, size=0, raw=0, attrs=b'', nlink=1):
    xc = (len(attrs) - 12) // 4 + 1 if attrs else 0
    return struct.pack('<HHHHIIIIHHI', layout << 1, xc, mode, nlink,
                       size, 0, raw, 123, 1000, 2000, 0) + attrs


def extended(attrs=b'', mode=stat.S_IFREG | 0o4750):
    xc = (len(attrs) - 12) // 4 + 1 if attrs else 0
    return struct.pack('<HHHHQIIIIQII16x', 5, xc, mode, 0, 1234567890123,
                       0, 321, 100001, 200002, 1234567890, 987654321, 1) + attrs


def fixture(inode=None):
    b = bytearray(16384)
    struct.pack_into('<III', b, 1024, 0xe0f5e1e2, 0, 7)
    b[1036] = 12
    struct.pack_into('<HQQIIII', b, 1038, 40, 1, 17, 123456789, 4, 0, 2)
    if inode is not None:
        b[1280:1280 + len(inode)] = inode
    return b


def dirdata(entries):
    pos = len(entries) * 12
    records, names = [], []
    for name, nid, ft in entries:
        records.append(struct.pack('<QHBB', nid, pos, ft, 0))
        names.append(name)
        pos += len(name)
    return b''.join(records + names)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='erofs-fixture-')
        self.path = Path(self.tmp.name) / 'image'
        self.addCleanup(self.tmp.cleanup)

    def image(self, data):
        self.path.write_bytes(data)
        im = Image(self.path)
        self.addCleanup(im.close)
        return im

    def test_compact_inode(self):
        n = self.image(fixture(compact())).inode(40)
        self.assertEqual((n['uid'], n['gid'], n['mode'], n['mtime_ns'], n['nlink']),
                         (1000, 2000, 0o100640, 17123456789, 1))

    def test_extended_inode(self):
        n = self.image(fixture(extended())).inode(40)
        self.assertEqual((n['uid'], n['gid'], n['size'], n['mtime_ns'], n['mode']),
                         (100001, 200002, 1234567890123, 1234567890987654321, 0o104750))

    def test_inline_all_supported_namespaces(self):
        pairs = [(1, b'hello', b'\0\xff'), (2, b'', b'\x02\0\0\0'),
                 (3, b'', b'ACL'), (4, b'key', b''), (6, b'capability', b'\x01\0\xff')]
        im = self.image(fixture(compact(attrs=xbody(b''.join(xentry(*p) for p in pairs)))))
        attrs = {a['name']: a['value_hex'] for a in im.inode(40)['xattrs']}
        self.assertEqual(attrs, {'user.hello': '00ff', 'system.posix_acl_access': '02000000',
                                'system.posix_acl_default': '41434c', 'trusted.key': '',
                                'security.capability': '0100ff'})

    def test_shared_and_inline(self):
        data = fixture(compact(attrs=xbody(xentry(1, b'a', b'inline'), (3,))))
        entry = xentry(6, b'selinux', b'u:object_r:system_file:s0\0')
        data[8204:8204 + len(entry)] = entry
        attrs = self.image(data).inode(40)['xattrs']
        self.assertEqual([(a['name'], a['storage']) for a in attrs],
                         [('security.selinux', 'shared'), ('user.a', 'inline')])
        self.assertEqual(attrs[0]['value_hex'], b'u:object_r:system_file:s0\0'.hex())

    def test_shared_crosses_block(self):
        data = fixture(compact(attrs=xbody(shared=(1023,))))
        entry = xentry(6, b'selinux', b'context')
        data[12284:12284 + len(entry)] = entry
        self.assertEqual(self.image(data).inode(40)['xattrs'][0]['value_hex'], b'context'.hex())

    def test_flat_plain(self):
        data = fixture(compact(layout=0, size=5, raw=3))
        data[12288:12293] = b'hello'
        im = self.image(data)
        self.assertEqual(im.flat(im.inode(40)), b'hello')

    def test_inline_full_block_plus_tail(self):
        data = fixture(compact(layout=2, size=4100, raw=3))
        data[12288:16384] = b'A' * 4096
        data[1312:1316] = b'tail'
        im = self.image(data)
        self.assertEqual(im.flat(im.inode(40)), b'A' * 4096 + b'tail')

    def tree(self, hardlinks=True):
        entries = [(b'.', 40, 2), (b'..', 40, 2), (b'a', 50, 1)]
        if hardlinks:
            entries.append((b'b', 50, 1))
        entries.append((b'link', 60, 7))
        directory = dirdata(entries)
        data = fixture(compact(mode=stat.S_IFDIR | 0o755, size=len(directory), nlink=2) + directory)
        struct.pack_into('<Q', data, 1040, 3)
        file = compact(nlink=2 if hardlinks else 1)
        data[1600:1600 + len(file)] = file
        link = compact(mode=stat.S_IFLNK | 0o777, size=1) + b'a'
        data[1920:1920 + len(link)] = link
        return data

    def test_full_tree_hardlink_and_symlink(self):
        result = self.image(self.tree()).inventory()
        self.assertEqual(list(result['paths']), ['/', '/a', '/b', '/link'])
        self.assertEqual(result['paths']['/link']['symlink_target_hex'], '61')
        self.assertEqual(result['hardlink_groups'], [{'nid': 50, 'paths': ['/a', '/b']}])

    def test_converter_interface(self):
        self.path.write_bytes(self.tree())
        result = inventory(self.path)
        self.assertEqual(set(result), {'/', '/a', '/b', '/link'})
        self.assertEqual(result['/a'], dict(nid=50, type='file', mode=0o100640,
                         uid=1000, gid=2000, nlink=2, size=0, mtime_ns=17123456789, xattrs={}))
        self.assertEqual(result['/link']['target'], 'a')

    def test_unsupported_superblock_features(self):
        for off, fmt, value in [(1104, 'I', 0x40), (1104, 'I', 0x80),
                                (1115, 'B', 1), (1114, 'B', 12), (1037, 'B', 1),
                                (1110, 'H', 1), (1128, 'B', 1), (1032, 'I', 8)]:
            with self.subTest(offset=off, value=value):
                data = fixture(compact())
                struct.pack_into('<' + fmt, data, off, value)
                with self.assertRaises(Invalid):
                    self.image(data)

    def test_bad_inode_fields(self):
        for off, fmt, value in [(1280, 'H', 16), (1280, 'H', 8), (1284, 'H', stat.S_IFCHR | 0o600),
                                (1286, 'H', 0), (1292, 'I', 1), (1308, 'I', 1)]:
            with self.subTest(offset=off, value=value):
                data = fixture(compact())
                struct.pack_into('<' + fmt, data, off, value)
                with self.assertRaises(Invalid):
                    self.image(data).inode(40)

    def test_bad_extended_time(self):
        data = fixture(extended())
        struct.pack_into('<I', data, 1320, 10**9)
        with self.assertRaises(Invalid):
            self.image(data).inode(40)

    def test_bad_xattrs(self):
        cases = [xbody(xentry(0x80, b'name', b'')), xbody(xentry(5, b'name', b'')),
                 xbody(xentry(1, b'a\0b', b'')), xbody(xentry(1, b'', b'')),
                 xbody(xentry(2, b'bad', b'')), xbody(xentry(1, b'a', b'') * 2),
                 xbody(), xbody(shared=(0xffffffff,)),
                 struct.pack('<IB7x', 0, 2) + struct.pack('<I', 1),
                 xbody(struct.pack('<BBH', 3, 1, 65535))]
        for attrs in cases:
            with self.subTest(attrs=attrs.hex()):
                with self.assertRaises(Invalid):
                    self.image(fixture(compact(attrs=attrs))).inode(40)

    def test_shared_inline_duplicate(self):
        entry = xentry(6, b'selinux', b'context')
        data = fixture(compact(attrs=xbody(entry, (0,))))
        data[8192:8192 + len(entry)] = entry
        with self.assertRaisesRegex(Invalid, 'duplicate'):
            self.image(data).inode(40)

    def test_bad_dir_offsets_names_types(self):
        for off, fmt, value in [(1320, 'H', 11), (1320, 'H', 65535),
                                (1332, 'H', 1), (1322, 'B', 3), (1323, 'B', 1),
                                (1312 + 48, 'B', ord('/'))]:
            with self.subTest(offset=off, value=value):
                data = self.tree()
                struct.pack_into('<' + fmt, data, off, value)
                with self.assertRaises(Invalid):
                    self.image(data).inventory()

    def test_directory_cycle(self):
        data = self.tree()
        struct.pack_into('<Q', data, 1312 + 24, 40)
        data[1312 + 34] = 2
        struct.pack_into('<H', data, 1286, 3)
        with self.assertRaises(Invalid):
            self.image(data).inventory()

    def test_mismatched_hardlinks(self):
        data = self.tree()
        struct.pack_into('<H', data, 1606, 3)
        with self.assertRaisesRegex(Invalid, 'link count'):
            self.image(data).inventory()

    def test_unreachable_inode(self):
        data = self.tree()
        struct.pack_into('<Q', data, 1040, 4)
        with self.assertRaisesRegex(Invalid, 'missing inode'):
            self.image(data).inventory()

    def test_out_of_range_inode(self):
        with self.assertRaises(Invalid):
            self.image(fixture(compact())).inode(999999999)

    def test_inline_crosses_block(self):
        data = fixture(compact(size=4090))
        im = self.image(data)
        with self.assertRaisesRegex(Invalid, 'crosses block'):
            im.flat(im.inode(40))

    def test_external_read_out_of_range(self):
        im = self.image(fixture(compact(layout=0, size=5, raw=4)))
        with self.assertRaises(Invalid):
            im.flat(im.inode(40))

    def test_nonflat_symlink(self):
        with self.assertRaises(Invalid):
            self.image(fixture(compact(mode=stat.S_IFLNK | 0o777, layout=3))).inode(40)

    def test_symlink_is_not_followed(self):
        os.symlink(self.path, Path(self.tmp.name) / 'alias')
        self.path.write_bytes(fixture(compact()))
        with self.assertRaises(OSError):
            Image(Path(self.tmp.name) / 'alias')


if __name__ == '__main__':
    unittest.main(verbosity=2)
