#!/usr/bin/env python3
"""Assemble a fixed, pinned Titan super image as a local artifact only.

No device-writing or flashing command exists. Production payload identities and
layout are fixed; the internal stream engine supports tiny host-only fixtures.
"""
from __future__ import annotations
import argparse
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from contextlib import ExitStack
import build_metadata as metadata

PREFIX_SHA256 = 'b79a001a076880b6679c02d52e51842850e22841ff16b7bc20d999b7459e2acf'
DEFAULT_RESERVE = 4 * 1024**3
CHUNK = 4 * 1024**2
OVERHEAD = 64 * 1024**2


class AssemblyError(Exception):
    pass


@dataclass(frozen=True)
class Payload:
    name: str
    path: Path
    offset: int
    size: int
    sha256: str


def _open_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise AssemblyError('absolute_normalized_directory_required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_regular(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.name in ('', '.', '..'):
        raise AssemblyError('absolute_normalized_source_required')
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise AssemblyError('source_not_regular')
    return fd


def _identity(fd):
    info = os.fstat(fd)
    return tuple(getattr(info, field) for field in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink'))


def _verify_source(path, fd, identity):
    if _identity(fd) != identity:
        raise AssemblyError('source_changed')
    current = _open_regular(path)
    try:
        if _identity(current) != identity:
            raise AssemblyError('source_path_changed')
    finally:
        os.close(current)


def _free(fd):
    info = os.fstatvfs(fd)
    return info.f_bavail * info.f_frsize


def _require_free(fd, reserve, needed=0):
    available = _free(fd)
    if available < reserve + needed + OVERHEAD:
        raise AssemblyError('disk_reserve_unavailable')
    return available


def _write(fd, data, at):
    done = 0
    while done < len(data):
        count = os.pwrite(fd, data[done:], at+done)
        if count <= 0:
            raise AssemblyError('short_output_write')
        done += count


def _read_exact(fd, length, offset):
    result = bytearray()
    while len(result) < length:
        piece = os.pread(fd, length-len(result), offset+len(result))
        if not piece:
            raise AssemblyError('short_read')
        result.extend(piece)
    return bytes(result)


def _hash_region(fd, offset, size):
    result = hashlib.sha256()
    for at in range(0, size, CHUNK):
        result.update(_read_exact(fd, min(CHUNK, size-at), offset+at))
    return result.hexdigest()


def _zero_region(fd, begin, end, directory, reserve):
    zeros = bytes(min(CHUNK, max(0, end-begin)))
    for at in range(begin, end, CHUNK):
        piece = zeros[:min(CHUNK, end-at)]
        _require_free(directory, reserve, len(piece))
        _write(fd, piece, at)


def _verify_zeros(fd, begin, end):
    for at in range(begin, end, CHUNK):
        if any(_read_exact(fd, min(CHUNK, end-at), at)):
            raise AssemblyError('nonzero_gap_or_tail')


def _publish(directory, source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        operation = libc.renameatx_np; flag = 4  # RENAME_EXCL
    elif sys.platform.startswith('linux'):
        operation = libc.renameat2; flag = 1  # RENAME_NOREPLACE
    else:
        raise AssemblyError('atomic_publish_unsupported')
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(directory, os.fsencode(source), directory, os.fsencode(target), flag):
        if ctypes.get_errno() == errno.EEXIST:
            raise AssemblyError('output_already_exists')
        raise AssemblyError('atomic_publish_failed')


def _new_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path == Path('/'):
        raise AssemblyError('fresh_absolute_output_directory_required')
    parent = _open_directory(path.parent)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)  # Existing file/dir/link always rejected.
        directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(directory)
            raise AssemblyError('output_directory_not_private')
        os.fsync(parent)
        return directory
    finally:
        os.close(parent)


def _validate_plan(prefix, payloads, total_size, reserve):
    if not prefix or reserve < 0 or total_size <= len(prefix):
        raise AssemblyError('invalid_internal_layout')
    last = len(prefix)
    names = set()
    for item in payloads:
        if (item.name not in ('system','vendor') or item.name in names or
                item.size <= 0 or item.offset < last or item.offset+item.size > total_size or
                len(item.sha256) != 64 or any(ch not in '0123456789abcdef' for ch in item.sha256)):
            raise AssemblyError('invalid_internal_layout')
        names.add(item.name); last = item.offset+item.size
    if names != {'system','vendor'}:
        raise AssemblyError('both_payloads_required')


def _assemble(prefix, payloads, total_size, output_directory, reserve, verify_prefix,
              extra_source_check=None):
    """Internal host stream engine; the production caller supplies fixed pins."""
    _validate_plan(prefix, payloads, total_size, reserve)
    with ExitStack() as stack:
        sources = []
        for item in payloads:
            fd = _open_regular(item.path); stack.callback(os.close,fd)
            identity = _identity(fd)
            if identity[2] != item.size:
                raise AssemblyError('payload_size_mismatch')
            sources.append((item,fd,identity))
        verify_prefix(prefix)
        if extra_source_check is not None:extra_source_check()
        directory = _new_directory(output_directory); stack.callback(os.close,directory)
        partial = 'super.img.partial'
        output = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
        stack.callback(os.close,output)
        if not stat.S_ISREG(os.fstat(output).st_mode):
            raise AssemblyError('output_not_regular')
        # Budget for a fully allocated output; sparse tail is not assumed for space.
        free_before = _require_free(directory, reserve, total_size)
        _write(output,prefix,0)
        cursor = len(prefix)
        hashes = {}
        for item,source,identity in sources:
            _zero_region(output,cursor,item.offset,directory,reserve)
            digest = hashlib.sha256()
            for offset in range(0,item.size,CHUNK):
                count = min(CHUNK,item.size-offset)
                _require_free(directory,reserve,count)
                data = _read_exact(source,count,offset)
                digest.update(data)
                _write(output,data,item.offset+offset)
            if digest.hexdigest() != item.sha256:
                raise AssemblyError('payload_hash_mismatch')
            _verify_source(item.path,source,identity)
            hashes[item.name] = digest.hexdigest()
            cursor = item.offset+item.size
        # The final fresh-file hole reads as zero; every inter-payload gap above
        # was explicitly written. Verify both the gaps and tail below.
        os.ftruncate(output,total_size)
        os.fsync(output)
        before_readback = _identity(output)
        persisted_prefix = _read_exact(output,len(prefix),0)
        if persisted_prefix != prefix:
            raise AssemblyError('persisted_metadata_mismatch')
        verify_prefix(persisted_prefix)
        cursor = len(prefix)
        for item,source,identity in sources:
            _verify_zeros(output,cursor,item.offset)
            if _hash_region(output,item.offset,item.size) != item.sha256:
                raise AssemblyError('persisted_payload_hash_mismatch')
            cursor = item.offset+item.size
        _verify_zeros(output,cursor,total_size)
        full_hash = _hash_region(output,0,total_size)
        if _identity(output) != before_readback:
            raise AssemblyError('output_changed_during_verification')
        for item,source,identity in sources:
            _verify_source(item.path,source,identity)
        _require_free(directory,reserve)
        if extra_source_check is not None:extra_source_check()
        bound_directory = _open_directory(output_directory)
        try:
            actual, expected = os.fstat(bound_directory), os.fstat(directory)
            if ((actual.st_dev,actual.st_ino) != (expected.st_dev,expected.st_ino) or
                    actual.st_uid != os.getuid() or stat.S_IMODE(actual.st_mode) != 0o700):
                raise AssemblyError('output_directory_path_changed')
        finally:os.close(bound_directory)
        # Verify path binding before publication. Quiet sources/output directory
        # remain required; filesystem permissions do not exclude this user's tools.
        current = os.stat(partial,dir_fd=directory,follow_symlinks=False)
        identity = _identity(output)
        if (current.st_dev,current.st_ino,current.st_nlink) != (identity[0],identity[1],1):
            raise AssemblyError('partial_path_changed')
        _publish(directory,partial,'super.img')
        os.fsync(directory)
        manifest = dict(version=1,file='super.img',bytes=total_size,sha256=full_hash,
                        prefix_bytes=len(prefix),prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                        payloads=[dict(name=p.name,offset=p.offset,bytes=p.size,sha256=p.sha256)
                                  for p in payloads],
                        streamed_payload_hashes=hashes,persisted_payload_hashes_verified=True,
                        persisted_metadata_verified=True,gaps_and_tail_zero_verified=True,
                        free_bytes_before=free_before,free_bytes_after=_free(directory),
                        reserve_bytes=reserve,flash_approved=False,device_operations=False)
        record = os.open('manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                         0o600,dir_fd=directory)
        with os.fdopen(record,'w') as f:
            json.dump(manifest,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.fsync(directory)
        return manifest


def assemble_super(prefix_path, system_path, vendor_path, output_directory,
                   *, reserve_bytes=DEFAULT_RESERVE):
    if reserve_bytes < DEFAULT_RESERVE:
        raise AssemblyError('production_reserve_below_4GiB')
    fd = _open_regular(prefix_path)
    try:
        identity = _identity(fd)
        if identity[2] != metadata.PREFIX_SIZE:
            raise AssemblyError('prefix_size_mismatch')
        prefix = _read_exact(fd,metadata.PREFIX_SIZE,0)
        if hashlib.sha256(prefix).hexdigest() != PREFIX_SHA256:
            raise AssemblyError('prefix_hash_mismatch')
        _verify_source(prefix_path,fd,identity)
        payloads = [Payload('system',Path(system_path),2048*512,3288334336,metadata.SYSTEM_SHA256),
                    Payload('vendor',Path(vendor_path),6424576*512,536870912,metadata.VENDOR_SHA256)]
        return _assemble(prefix,payloads,metadata.SUPER_SIZE,Path(output_directory),reserve_bytes,
                         metadata.validate_minimal,
                         extra_source_check=lambda:_verify_source(prefix_path,fd,identity))
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--system',type=Path,required=True)
    parser.add_argument('--vendor',type=Path,required=True)
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--reserve-bytes',type=int,default=DEFAULT_RESERVE)
    args = parser.parse_args()
    result = assemble_super(args.prefix,args.system,args.vendor,args.output_directory,
                            reserve_bytes=args.reserve_bytes)
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
