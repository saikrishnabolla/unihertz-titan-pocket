import re
import xml.etree.ElementTree as ET


SHARED_ROUTES = {
    b'/dev/block/by-name/md_udc': (b'/metadata', b'ext4'),
    b'/dev/block/by-name/cache': (b'/cache', b'ext4'),
    b'/dev/block/by-name/protect1': (b'/mnt/vendor/protect_f', b'ext4'),
    b'/dev/block/by-name/protect2': (b'/mnt/vendor/protect_s', b'ext4'),
    b'/dev/block/by-name/nvdata': (b'/mnt/vendor/nvdata', b'ext4'),
    b'/dev/block/by-name/nvcfg': (b'/mnt/vendor/nvcfg', b'ext4'),
    b'/dev/block/by-name/persist': (b'/mnt/vendor/persist', b'ext4'),
}


def _lines(data: bytes) -> list[bytes]:
    if b'\x00' in data or b'\r' in data:
        raise ValueError('NUL and CR are not supported')
    parts = data.split(b'\n')
    return [part + b'\n' for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _active(line: bytes) -> bytes:
    return line.split(b'#', 1)[0].strip(b' \t\n')


def patch_vndk_manifest(data: bytes) -> bytes:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError('Invalid framework manifest XML') from error
    if root.tag != 'manifest' or root.get('type') != 'framework':
        raise ValueError('Expected a framework manifest')
    versions = [element.findtext('version') for element in root.findall('vendor-ndk')]
    if versions != ['31', '32', '33', '34']:
        raise ValueError('Expected the reviewed VNDK31-34 declarations')
    anchor = b'    <vendor-ndk>\n        <version>31</version>\n    </vendor-ndk>\n'
    if data.count(anchor) != 1:
        raise ValueError('Expected one exact VNDK31 insertion anchor')
    position = data.index(anchor)
    addition = b'    <vendor-ndk>\n        <version>30</version>\n    </vendor-ndk>\n'
    return data[:position] + addition + data[position:]


def patch_ueventd(data: bytes) -> bytes:
    lines = _lines(data)
    modern = b'import /vendor/etc/ueventd.rc\n'
    matches = []
    for index, line in enumerate(lines):
        active = _active(line)
        if re.search(rb'/vendor/ueventd\.rc(?:$|[\s\'"\\])', active):
            raise ValueError('legacy vendor import already present or ambiguous')
        if re.search(rb'/vendor/etc/ueventd\.rc(?:$|[\s\'"\\])', active):
            if line != modern:
                raise ValueError('modern vendor import is not exact')
            matches.append(index)
    if len(matches) != 1:
        raise ValueError('expected one modern vendor import')
    lines.insert(matches[0] + 1, b'import /vendor/ueventd.rc\n')
    return b''.join(lines)


def _apd_reference(token: bytes) -> bool:
    token = token.lower().rstrip(b'/')
    return token.rsplit(b'/', 1)[-1] == b'apd' or token in (b'label=apd', b'partlabel=apd')


def patch_fstab(data: bytes) -> bytes:
    lines = _lines(data)
    expected = [b'/dev/block/by-name/apd', b'/mnt/vendor/apd', b'ext4',
                b'noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc',
                b'wait,check,formattable']
    matches = []
    seen_shared = set()
    seen_userdata = False
    shared_mounts = {mount for mount, _ in SHARED_ROUTES.values()}
    for index, line in enumerate(lines):
        fields = _active(line).split()
        if any(_apd_reference(field) for field in fields):
            if (fields != expected or b'#' in line
                    or re.fullmatch(rb'[ \t]*' + rb'[ \t]+'.join(map(re.escape, expected))
                                    + rb'[ \t]*\n?', line) is None):
                raise ValueError('unexpected apd fstab reference or row shape')
            matches.append(index)
            continue
        if not fields:
            continue
        shared = fields[0] in SHARED_ROUTES or (len(fields) > 1 and fields[1] in shared_mounts)
        userdata = fields[0] == b'/dev/block/by-name/userdata' or (len(fields) > 1 and fields[1] == b'/data')
        has_formattable = any(b'formattable' in field.split(b',') for field in fields)
        if not shared and not userdata:
            if has_formattable:
                raise ValueError('unknown formattable fstab route')
            continue
        if (len(fields) != 5
                or re.fullmatch(rb'[ \t]*' + rb'[ \t]+'.join(map(re.escape, fields))
                                + rb'[ \t]*(?:#[^\n]*)?\n?', line) is None):
            raise ValueError('unexpected recognized fstab row shape')
        if userdata:
            if fields[:3] != [b'/dev/block/by-name/userdata', b'/data', b'ext4'] or seen_userdata:
                raise ValueError('unexpected or duplicate userdata route')
            seen_userdata = True
            continue
        source, mount, filesystem, mount_flags, manager_flags = fields
        if SHARED_ROUTES.get(source) != (mount, filesystem) or source in seen_shared:
            raise ValueError('unexpected or duplicate shared physical route')
        flags = manager_flags.split(b',')
        if (flags.count(b'formattable') != 1 or len(flags) < 2 or b'' in flags
                or b'formattable' in mount_flags.split(b',')):
            raise ValueError('expected one shared fs_mgr formattable token')
        seen_shared.add(source)
        flag_span = list(re.finditer(rb'[^ \t\n]+', line.split(b'#', 1)[0]))[4].span()
        new_flags = b','.join(flag for flag in flags if flag != b'formattable')
        lines[index] = line[:flag_span[0]] + new_flags + line[flag_span[1]:]
    if len(matches) != 1:
        raise ValueError('expected one apd fstab row')
    if seen_shared != set(SHARED_ROUTES):
        raise ValueError('expected all seven shared physical fstab routes')
    del lines[matches[0]]
    return b''.join(lines)


def patch_init(data: bytes) -> bytes:
    lines = _lines(data)
    expected = (b'exec /system/bin/tune2fs -O has_journal -u 10010 -r 4096 '
                b'/dev/block/by-name/userdata')
    matches = []
    continued = b''
    for index, line in enumerate(lines):
        active = continued + _active(line)
        was_continued = bool(continued)
        if active.endswith(b'\\'):
            continued = active[:-1] + b' '
            continue
        continued = b''
        if (not re.search(rb'\btune2fs\b', active)
                or not re.search(rb'(?:^|[/=\s\'\"])userdata(?:$|[/\s\'\";])', active)):
            continue
        if was_continued or line.removesuffix(b'\n').lstrip(b' \t') != expected:
            raise ValueError('unexpected raw-userdata tune2fs command')
        matches.append(index)
    if b'tune2fs' in continued:
        raise ValueError('unterminated tune2fs continuation')
    if len(matches) != 1:
        raise ValueError('expected one raw-userdata tune2fs command')
    del lines[matches[0]]
    return b''.join(lines)
