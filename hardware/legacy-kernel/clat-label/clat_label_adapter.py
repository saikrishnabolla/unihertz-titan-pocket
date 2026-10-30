"""Offline Titan-specific CLAT label compatibility adapter; never touches a device.

This only redirects two expected-context pointers to the existing generic BPF
context. It does not alter SELinux policy, BPF loading, permissions or aborts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

SOURCE_SHA256 = '69677de192a63bb6d5409f141c6495a27a4b5e71a50507758246bb893fe67b2f'
SOURCE_BUILD_ID = 'f23735832a2a0ea900d2919001172c9d'
SOURCE_BYTES = 119600
BOOT_SHA256 = 'c3aa2e73c3efbce4b6fe6558558d91826be868d8981f99d04242b4d0cb6876ce'
OLD_CONTEXT = 'u:object_r:fs_bpf_net_shared:s0'
NEW_CONTEXT = 'u:object_r:fs_bpf:s0'
SITES = ((0xbd7c, 0xbd80, 4, 0x91205c84, 0x912d3884),
         (0xbda4, 0xbda8, 20, 0x91205e94, 0x912d3a94))
FATAL_AND_ABORT = {0xbe4c: 0xb0000088, 0xbe50: 0x39471108,
                   0xbe54: 0x7100051f, 0xbe58: 0x54000a00,
                   0xbf98: 0x940022c2}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

class Elf:
    def __init__(self, data):
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01',
                'Expected little-endian ELF64')
        require(struct.unpack_from('<HH', data, 16) == (3, 183),
                'Expected AArch64 shared object')
        phoff = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        require(width == 56 and 0 < count <= 128 and phoff + width * count <= len(data),
                'Invalid program header table')
        self.data = data
        self.headers = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * width)
                        for i in range(count)]
        for kind, flags, offset, va, pa, filesz, memsz, align in self.headers:
            require(offset + filesz <= len(data) and (kind != 1 or filesz <= memsz),
                    'Invalid segment bounds')

    def offset(self, va, size=4, executable=False):
        require(isinstance(va, int) and va >= 0 and isinstance(size, int) and size > 0,
                'Invalid virtual address or size')
        matches = []
        for kind, flags, offset, base, pa, filesz, memsz, align in self.headers:
            if kind == 1 and (not executable or flags & 1) and base <= va and va + size <= base + filesz:
                matches.append(offset + va - base)
        require(len(matches) == 1, 'Expected one file-backed segment mapping')
        return matches[0]

    def word(self, va):
        return struct.unpack_from('<I', self.data, self.offset(va, 4, executable=True))[0]

    def context(self, va):
        result = bytearray()
        for i in range(255):
            value = self.data[self.offset(va + i, 1)]
            if value == 0:
                return result.decode('ascii')
            result.append(value)
        raise ValueError('Context lacks a bounded terminator')

    def build_id(self):
        found = []
        for kind, flags, offset, va, pa, filesz, memsz, align in self.headers:
            if kind != 4:
                continue
            pos, end = offset, offset + filesz
            while pos < end:
                require(pos + 12 <= end, 'Truncated ELF note')
                namesz, descsz, note_type = struct.unpack_from('<III', self.data, pos)
                pos += 12
                name_end = pos + namesz
                desc_start = (name_end + 3) & ~3
                desc_end = desc_start + descsz
                next_note = (desc_end + 3) & ~3
                require(next_note <= end, 'ELF note exceeds segment')
                if note_type == 3 and self.data[pos:name_end] == b'GNU\0':
                    found.append(self.data[desc_start:desc_end].hex())
                pos = next_note
        require(len(found) == 1, 'Expected one GNU Build ID')
        return found[0]

def decode_add64(word):
    require(word & 0xffc00000 == 0x91000000, 'Expected unshifted ADD Xd, Xn, #imm12')
    return word & 31, (word >> 5) & 31, (word >> 10) & 0xfff

def encode_add64(word, immediate):
    decode_add64(word)
    require(isinstance(immediate, int) and 0 <= immediate <= 0xfff,
            'ADD immediate outside 12-bit range')
    return (word & ~(0xfff << 10)) | (immediate << 10)

def resolve_pair(elf, adrp_va, add_va, register):
    word = elf.word(adrp_va)
    require(word & 0x9f000000 == 0x90000000 and word & 31 == register,
            'Expected matching ADRP')
    immediate = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    page = (adrp_va & ~0xfff) + immediate * 4096
    destination, source, add = decode_add64(elf.word(add_va))
    require(destination == source == register, 'ADRP/ADD register mismatch')
    return page + add

def target_contexts(data):
    elf = Elf(data)
    directory = elf.context(resolve_pair(elf, 0xbd7c, 0xbd80, 4))
    maps = elf.context(resolve_pair(elf, 0xbda4, 0xbda8, 20))
    return [directory] + [maps] * 5

def adapt(original):
    require(len(original) == SOURCE_BYTES and sha(original) == SOURCE_SHA256,
            'Input differs from pinned Google library')
    elf = Elf(original)
    require(elf.build_id() == SOURCE_BUILD_ID, 'Wrong source Build ID')
    require(elf.offset(0xbcc8, 4, executable=True) == 0xbcc8, 'Registration mapping differs')
    generic_va = resolve_pair(elf, 0xbd58, 0xbd5c, 4)
    require(generic_va == 0x4b4e and elf.context(generic_va) == NEW_CONTEXT,
            'Existing generic BPF context differs')
    require(target_contexts(original) == [OLD_CONTEXT] * 6,
            'Original six CLAT contexts differ')
    for va, word in FATAL_AND_ABORT.items():
        require(elf.word(va) == word, 'Fatal/abort instruction differs')
    result = bytearray(original)
    edits = []
    allowed = set()
    for adrp_va, add_va, register, old_word, expected_word in SITES:
        offset = elf.offset(add_va, 4, executable=True)
        require(offset == add_va and elf.word(add_va) == old_word,
                'Pinned ADD instruction differs')
        require(resolve_pair(elf, adrp_va, add_va, register) == 0x4817,
                'Original shared context pointer differs')
        word = encode_add64(old_word, generic_va & 0xfff)
        require(word == expected_word, 'Replacement differs from reviewed instruction')
        struct.pack_into('<I', result, offset, word)
        allowed.update(range(offset, offset + 4))
        edits.append({'va': hex(add_va), 'file_offset': offset,
                      'register': 'x' + str(register),
                      'old_hex': struct.pack('<I', old_word).hex(),
                      'new_hex': struct.pack('<I', word).hex(),
                      'old_context_va': '0x4817', 'new_context_va': hex(generic_va)})
    result = bytes(result)
    changed = [i for i, (a, b) in enumerate(zip(original, result)) if a != b]
    require(len(result) == len(original) and changed == [0xbd81, 0xbd82, 0xbda9, 0xbdaa]
            and set(changed) <= allowed, 'Unexpected binary delta')
    after = Elf(result)
    require(target_contexts(result) == [NEW_CONTEXT] * 6, 'Adapted CLAT contexts differ')
    require(all(after.word(va) == word for va, word in FATAL_AND_ABORT.items()),
            'Fatal/abort instruction changed')
    readonly = [(offset, filesz) for kind, flags, offset, va, pa, filesz, memsz, align
                in elf.headers if kind == 1 and not flags & 3]
    require(all(original[o:o+n] == result[o:o+n] for o, n in readonly),
            'Read-only data changed')
    manifest = {
        'status': 'OFFLINE TITAN LABEL COMPATIBILITY CANDIDATE; NOT BOOT TESTED',
        'source_sha256': SOURCE_SHA256, 'result_sha256': sha(result),
        'source_build_id': SOURCE_BUILD_ID,
        'embedded_build_id_unchanged': after.build_id() == SOURCE_BUILD_ID,
        'note': 'Embedded Build ID identifies the source; use result SHA256 to identify this derivative.',
        'source_bytes': len(original), 'changed_byte_offsets': changed, 'edits': edits,
        'all_bytes_outside_two_add_words_unchanged': True,
        'readonly_load_segments_unchanged': True, 'fatal_and_abort_instructions_unchanged': True,
        'six_recorded_context_checks': {'before': [OLD_CONTEXT] * 6,
                                        'after': target_contexts(result)},
        'target_restrictions': {
            'product': 'Titan_pocket', 'kernel_release': '4.14.186-g40b2a1864-dirty',
            'repaired_boot_sha256': BOOT_SHA256,
            'google_build': 'CP3A.260905.010/16176746',
            'reason': 'Only for the observed legacy bpffs labels on this specific Titan baseline.',
            'device_verified_by_this_tool': False,
            'activation_requires_separate_identity_and_recovery_checks': True},
        'limits': ['No policy or kernel modification', 'No permission, ownership, BPF retrieval or abort bypass',
                   'No APEX packaging or signing', 'No installation or device access',
                   'No runtime networking or security proof'],
    }
    return result, manifest

def build(source, output):
    source, output = Path(source), Path(output)
    require(not source.is_symlink() and stat.S_ISREG(source.lstat().st_mode),
            'Source must be a regular non-symlink file')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'Source must be a regular file')
        original = stream.read()
        after = os.fstat(stream.fileno())
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), 'Source changed while reading')
    result, manifest = adapt(original)
    manifest['source_path'] = str(source.resolve())
    output.mkdir(mode=0o700, exist_ok=False)
    candidate = output / 'libservice-connectivity.so'
    with candidate.open('xb') as stream:
        stream.write(result)
    candidate.chmod(0o600)
    require(candidate.read_bytes() == result and sha(source.read_bytes()) == SOURCE_SHA256,
            'Output readback or source preservation failed')
    report = output / 'manifest.json'
    with report.open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    report.chmod(0o600)
    return manifest

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.source, args.output)
    print(json.dumps({k: result[k] for k in ('status', 'source_sha256', 'result_sha256',
                                            'changed_byte_offsets')}, indent=2))
