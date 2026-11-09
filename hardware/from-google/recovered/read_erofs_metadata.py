#!/usr/bin/env python3
"""Bounded, read-only EROFS v1 metadata inventory; not a payload validator.

Disk structures follow erofs-utils v1.7.1 include/erofs_fs.h; namespace
expansion and shared IDs follow that release's lib/xattr.c.
"""
import argparse
import json
import os
import stat
import struct
import subprocess
from collections import defaultdict
from pathlib import Path

SOURCE = 'https://raw.githubusercontent.com/erofs/erofs-utils/v1.7.1/include/erofs_fs.h'
PREFIX = {1: b'user.', 2: b'system.posix_acl_access',
          3: b'system.posix_acl_default', 4: b'trusted.', 6: b'security.'}


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


class Image:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(self.fd)
            require(stat.S_ISREG(st.st_mode), 'image must be regular file')
            self.length = st.st_size
            self.limit = self.length
            s = self.read(1024, 128)
            u = lambda fmt, pos: struct.unpack_from('<' + fmt, s, pos)[0]
            require(u('I', 0) == 0xe0f5e1e2, 'bad superblock magic')
            self.bits = s[12]
            require(9 <= self.bits <= 16, 'unsupported block size')
            self.bs = 1 << self.bits
            require(s[13] == 0, 'superblock extensions unsupported')
            self.root = u('H', 14)
            self.inos = u('Q', 16)
            require(0 < self.inos <= 100000, 'inode count limit')
            self.build_sec, self.build_nsec = u('Q', 24), u('I', 32)
            require(self.build_nsec < 10**9, 'bad build nanoseconds')
            self.blocks = u('I', 36)
            self.limit = self.blocks * self.bs
            require(1152 <= self.limit <= self.length, 'bad block count')
            self.meta, self.xbase = u('I', 40) * self.bs, u('I', 44) * self.bs
            require(self.meta < self.limit and self.xbase < self.limit, 'bad metadata base')
            self.compat, self.incompat = u('I', 8), u('I', 80)
            require(not self.compat & ~7, 'unknown compatible metadata feature')
            require(not self.incompat & ~3, 'unsupported incompatible feature')
            require(u('H', 86) == 0 and u('H', 88) == 0, 'device table unsupported')
            require(s[90] == 0 and s[91] == 0 and u('I', 92) == 0,
                    'directory blocks / long xattr prefixes unsupported')
            require(u('Q', 96) == 0 and not any(s[104:]), 'unsupported superblock fields')
            self.cache = {}
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def read(self, offset, size):
        require(0 <= offset <= self.limit and 0 <= size <= 1048576
                and offset + size <= self.limit, 'read outside image / read limit')
        result = os.pread(self.fd, size, offset)
        require(len(result) == size, 'short read')
        return result

    def xentry(self, offset, end, origin):
        require(offset + 4 <= end, 'truncated xattr header')
        nl, index, vl = struct.unpack('<BBH', self.read(offset, 4))
        require(index in PREFIX, 'unsupported xattr namespace / extended prefix')
        size = (4 + nl + vl + 3) & ~3
        require(offset + size <= end, 'xattr exceeds bounds')
        data = self.read(offset + 4, nl + vl)
        name = data[:nl]
        require(b'\0' not in name and (nl > 0 or index in (2, 3)), 'bad xattr name')
        require(index not in (2, 3) or nl == 0, 'ACL name suffix unsupported')
        full = PREFIX[index] + name
        require(len(full) <= 255, 'xattr name too long')
        return {'name': full.decode('utf-8', 'surrogateescape'),
                'name_hex': full.hex(), 'value_hex': data[nl:].hex(),
                'storage': origin, 'entry_offset': offset}, offset + size

    def inode(self, nid):
        if nid in self.cache:
            return self.cache[nid]
        require(len(self.cache) < self.inos, 'too many reachable inodes')
        offset = self.meta + nid * 32
        h = self.read(offset, 32)
        fmt, xc, mode = struct.unpack_from('<HHH', h)
        require(not fmt & ~15, 'unknown inode format bits')
        version, layout = fmt & 1, (fmt >> 1) & 7
        require(layout in (0, 1, 2, 3), 'unsupported inode layout')
        isize = 64 if version else 32
        h = self.read(offset, isize)
        if version:
            require(h[6:8] == b'\0\0' and not any(h[48:]), 'extended inode reserved fields')
            size, raw, ino, uid, gid, sec, nsec, nlink = struct.unpack_from('<QIIIIQII', h, 8)
        else:
            require(not any(h[12:16]) and not any(h[28:32]), 'compact inode reserved fields')
            nlink = struct.unpack_from('<H', h, 6)[0]
            size, raw, ino, uid, gid = (
                struct.unpack_from('<I', h, 8)[0], struct.unpack_from('<I', h, 16)[0],
                struct.unpack_from('<I', h, 20)[0], *struct.unpack_from('<HH', h, 24))
            sec, nsec = self.build_sec, self.build_nsec
        require(nsec < 10**9 and nlink > 0, 'bad inode time/link count')
        typ = {stat.S_IFREG: 'file', stat.S_IFDIR: 'directory', stat.S_IFLNK: 'symlink'}.get(stat.S_IFMT(mode))
        require(typ is not None, 'special / unknown inode type unsupported')
        require(typ == 'file' or layout in (0, 2), 'nonflat directory/symlink')
        xs = 12 + (xc - 1) * 4 if xc else 0
        attrs = []
        if xs:
            require(xs > 12, 'undefined empty xattr body')
            body = self.read(offset + isize, xs)
            shared = body[4]
            require(not any(body[5:12]), 'xattr reserved fields')
            require(12 + shared * 4 <= xs, 'shared IDs exceed xattr body')
            for i in range(shared):
                xid = struct.unpack_from('<I', body, 12 + i * 4)[0]
                attr, _ = self.xentry(self.xbase + xid * 4, self.limit, 'shared')
                attr['shared_id'] = xid
                attrs.append(attr)
            pos, end = offset + isize + 12 + shared * 4, offset + isize + xs
            while pos < end:
                attr, pos = self.xentry(pos, end, 'inline')
                attrs.append(attr)
            names = [a['name_hex'] for a in attrs]
            require(len(names) == len(set(names)), 'duplicate xattr name')
        record = dict(nid=nid, type=typ, mode=mode, mode_octal=f'{mode:06o}', uid=uid,
                      gid=gid, nlink=nlink, size=size, mtime_sec=sec, mtime_nsec=nsec,
                      mtime_ns=sec * 10**9 + nsec, inode_version=version,
                      datalayout=layout, inode_offset=offset, inode_size=isize,
                      xattr_size=xs, xattrs=sorted(attrs, key=lambda a: a['name_hex']))
        self.cache[nid] = record
        record['_raw'] = raw
        return record

    def flat(self, node):
        require(node['datalayout'] in (0, 2), 'compressed data read unsupported')
        size = node['size']
        require(size <= 1048576, 'flat metadata size limit')
        full, tail = divmod(size, self.bs)
        external = full * self.bs if node['datalayout'] == 2 else size
        data = self.read(node['_raw'] * self.bs, external) if external else b''
        if node['datalayout'] == 2 and tail:
            pos = node['inode_offset'] + node['inode_size'] + node['xattr_size']
            require(pos % self.bs + tail <= self.bs, 'inline tail crosses block')
            data += self.read(pos, tail)
        return data

    def directory(self, node):
        data = self.flat(node)
        require(bool(data), 'empty directory')
        entries = []
        for start in range(0, len(data), self.bs):
            block = data[start:start + self.bs]
            require(len(block) >= 12, 'short directory block')
            first = struct.unpack_from('<H', block, 8)[0]
            require(12 <= first <= len(block) and first % 12 == 0, 'bad directory name offset')
            count = first // 12
            ds = [struct.unpack_from('<QHBB', block, i * 12) for i in range(count)]
            for i, (nid, off, ft, reserved) in enumerate(ds):
                end = ds[i + 1][1] if i + 1 < count else len(block)
                require(first <= off < end <= len(block) and not reserved, 'bad dirent offset/reserved')
                name = block[off:end]
                if i + 1 == count:
                    name = name.rstrip(b'\0')
                require(0 < len(name) <= 255 and b'\0' not in name and b'/' not in name,
                        'bad directory name')
                require(ft in (1, 2, 7), 'unknown / special dirent type')
                entries.append((name, nid, ft))
        names = [e[0] for e in entries]
        require(len(names) == len(set(names)), 'duplicate directory name')
        require(names == sorted(names), 'unsorted directory entries')
        return entries

    def inventory(self):
        paths, seen_dirs, groups = {}, set(), defaultdict(list)
        todo = [('/', self.root, self.root, 0)]
        while todo:
            path, nid, parent, depth = todo.pop()
            require(depth <= 128 and len(paths) < 200000 and len(path) <= 4096, 'tree limits')
            n = self.inode(nid)
            paths[path] = {k: v for k, v in n.items() if not k.startswith('_')}
            groups[nid].append(path)
            if n['type'] == 'symlink':
                target = self.flat(n)
                require(0 < len(target) <= 4096 and b'\0' not in target, 'invalid symlink target')
                paths[path]['symlink_target'] = target.decode('utf-8', 'surrogateescape')
                paths[path]['symlink_target_hex'] = target.hex()
            elif n['type'] == 'directory':
                require(nid not in seen_dirs, 'directory hardlink/cycle')
                seen_dirs.add(nid)
                entries = self.directory(n)
                dot = {name: (child, ft) for name, child, ft in entries if name in (b'.', b'..')}
                require(dot == {b'.': (nid, 2), b'..': (parent, 2)}, 'bad dot links')
                children = 0
                for name, child, ft in entries:
                    if name in (b'.', b'..'):
                        continue
                    cn = self.inode(child)
                    require({'file': 1, 'directory': 2, 'symlink': 7}[cn['type']] == ft,
                            'dirent/inode type mismatch')
                    children += cn['type'] == 'directory'
                    text = name.decode('utf-8', 'surrogateescape')
                    todo.append((path.rstrip('/') + '/' + text, child, nid, depth + 1))
                require(n['nlink'] == 2 + children, 'directory link count mismatch')
        require(len(self.cache) == self.inos, 'unreachable / missing inode count')
        for nid, pp in groups.items():
            if self.cache[nid]['type'] != 'directory':
                require(len(pp) == self.cache[nid]['nlink'], 'file link count mismatch')
        return dict(source=SOURCE, image_size=self.length, block_size=self.bs, root_nid=self.root,
                    inode_count=self.inos, feature_compat=self.compat, feature_incompat=self.incompat,
                    paths=dict(sorted(paths.items())), hardlink_groups=[dict(nid=nid, paths=sorted(pp))
                    for nid, pp in sorted(groups.items()) if len(pp) > 1])


def path_records(result):
    """Converter interface: raw IDs, full stat mode, exact xattr value bytes as hex."""
    paths = {}
    for path, node in result['paths'].items():
        record = {key: node[key] for key in
                  ('nid', 'type', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns')}
        record['xattrs'] = {a['name']: a['value_hex'] for a in node['xattrs']}
        if node['type'] == 'symlink':
            record['target'] = node['symlink_target']
        paths[path] = record
    return paths


def inventory(image: Path) -> dict[str, dict]:
    """Read metadata only. Raises Invalid on unsupported or malformed metadata."""
    reader = Image(image)
    try:
        return path_records(reader.inventory())
    finally:
        reader.close()


def crosscheck(result, dump, image):
    import re
    count = 0
    for path, n in result['paths'].items():
        p = subprocess.run([dump, '--path=' + path, image], capture_output=True, text=True,
                           check=True, timeout=10)
        text = p.stdout
        for pattern, value in [(r'NID:\s*(\d+)', n['nid']), (r'Uid:\s*(\d+)', n['uid']),
                               (r'Gid:\s*(\d+)', n['gid']), (r'Links:\s*(\d+)', n['nlink']),
                               (r'Size:\s*(\d+)', n['size'])]:
            m = re.search(pattern, text)
            require(m is not None and int(m[1]) == value, f'dump mismatch {path}: {pattern}')
        m = re.search(r'Access:\s*([0-7]+)/', text)
        require(m is not None and int(m[1], 8) == stat.S_IMODE(n['mode']), f'dump mode mismatch {path}')
        count += 1
    return dict(tool=dump, paths_checked=count, fields=['nid', 'uid', 'gid', 'nlink', 'size', 'mode_permissions'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--dump')
    args = parser.parse_args()
    image = Image(args.image)
    try:
        result = image.inventory()
        if args.dump:
            result['dump_crosscheck'] = crosscheck(result, args.dump, args.image)
        print(json.dumps(result, indent=2, ensure_ascii=True))
    finally:
        image.close()


if __name__ == '__main__':
    main()
