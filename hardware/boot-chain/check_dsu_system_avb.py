"""Check exact SYSTEM AVB layout/settings in addition to cryptographic verification."""
import struct

PROPERTIES = {
    'com.android.build.system.os_version': '17',
    'com.android.build.system.fingerprint': 'google/generic_system/generic:17/CP2A.260605.016/2026102600:user/release-keys',
    'com.android.build.system.security_patch': '2026-10-05',
}
ROLLBACK_INDEX = 1791158400


def check(image, filesystem_bytes, partition_bytes):
    if image.stat().st_size != partition_bytes:
        raise ValueError('Unexpected SYSTEM container size')
    with image.open('rb') as stream:
        stream.seek(-64, 2)
        magic, major, minor, original, offset, size, reserved = struct.unpack('>4sIIQQQ28s', stream.read(64))
        if (magic, major, minor, original, reserved) != (b'AVBf', 1, 0, filesystem_bytes, bytes(28)):
            raise ValueError('Unexpected SYSTEM footer')
        if offset < original or size < 256 or offset + size > partition_bytes - 64:
            raise ValueError('Out-of-bounds SYSTEM vbmeta')
        stream.seek(offset)
        vbmeta = stream.read(size)
    if vbmeta[:12] != struct.pack('>4sII', b'AVB0', 1, 0):
        raise ValueError('Unexpected minimum AVB version')
    auth, auxiliary, algorithm = struct.unpack_from('>QQI', vbmeta, 12)
    descriptor_offset, descriptor_size, rollback, flags, location = struct.unpack_from('>QQQII', vbmeta, 96)
    if (algorithm, rollback, flags, location) != (1, ROLLBACK_INDEX, 0, 0):
        raise ValueError('Unexpected SYSTEM signing settings')
    if 256 + auth + auxiliary != size or descriptor_offset + descriptor_size > auxiliary:
        raise ValueError('Invalid SYSTEM auxiliary bounds')
    cursor = 256 + auth + descriptor_offset
    end = cursor + descriptor_size
    properties = {}
    tree = None
    while cursor < end:
        if end - cursor < 16:
            raise ValueError('Truncated SYSTEM descriptor')
        tag, following = struct.unpack_from('>QQ', vbmeta, cursor)
        length = following + 16
        if length % 8 or length < 16 or cursor + length > end:
            raise ValueError('Invalid SYSTEM descriptor length')
        descriptor = vbmeta[cursor:cursor + length]
        if tag == 0:
            if length < 32:
                raise ValueError('Truncated SYSTEM property')
            key_size, value_size = struct.unpack_from('>QQ', descriptor, 16)
            finish = 32 + key_size + 1 + value_size + 1
            if finish > length or descriptor[32 + key_size] != 0 or descriptor[finish - 1] != 0 or any(descriptor[finish:]):
                raise ValueError('Invalid SYSTEM property encoding')
            key = descriptor[32:32 + key_size].decode('utf-8')
            value = descriptor[33 + key_size:finish - 1].decode('utf-8')
            if key in properties:
                raise ValueError('Duplicate SYSTEM property')
            properties[key] = value
        elif tag == 1 and tree is None:
            if length < 180:
                raise ValueError('Truncated SYSTEM hashtree')
            values = struct.unpack_from('>QQIQQQIIIQQ32sIIII60s', descriptor)
            (_, _, version, data_bytes, tree_offset, tree_size, data_block, hash_block,
             fec_roots, fec_offset, fec_size, hash_algorithm, name_size, salt_size,
             digest_size, tree_flags, reserved) = values
            if (version, data_bytes, tree_offset, data_block, hash_block, fec_roots,
                    fec_offset, fec_size, hash_algorithm.rstrip(b'\0'), name_size,
                    salt_size, digest_size, tree_flags, reserved) != (
                    1, filesystem_bytes, filesystem_bytes, 4096, 4096, 0, 0, 0, b'sha256', 6, 32, 32, 0, bytes(60)):
                raise ValueError('Unexpected SYSTEM hashtree settings')
            if (descriptor[180:186] != b'system' or length != 256 or any(descriptor[250:]) or
                    tree_size <= 0 or tree_offset + tree_size > offset):
                raise ValueError('Invalid SYSTEM tree name, padding or bounds')
            tree = {'tree_offset': tree_offset, 'tree_bytes': tree_size}
        else:
            raise ValueError('Unknown or duplicate SYSTEM descriptor')
        cursor += length
    if tree is None or properties != PROPERTIES:
        raise ValueError('Missing SYSTEM tree or changed build properties')
    return {'partition_name': 'system', 'descriptor_count': 4, 'properties': properties,
            'rollback_index': rollback, 'flags': flags, 'rollback_index_location': location,
            'vbmeta_offset': offset, 'vbmeta_bytes': size, **tree}
