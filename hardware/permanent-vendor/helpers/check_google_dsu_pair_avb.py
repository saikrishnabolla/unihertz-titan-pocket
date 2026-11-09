"""Strict Google pair AVB structure checks; cryptography is checked separately."""
import struct

SYSTEM_PROPERTIES = {
    'com.android.build.system.os_version': '17',
    'com.android.build.system.fingerprint': 'Android/generic_system/generic:17/CP3A.260905.010/16176746:user/release-keys',
    'com.android.build.system.security_patch': '2026-09-05',
}
SYSTEM_ROLLBACK = 1788566400
VENDOR_PROPERTIES = {}
VENDOR_ROLLBACK = 0


def check(image, name, filesystem_bytes, partition_bytes, source_sha):
    properties_expected, rollback_expected = {
        'system': (SYSTEM_PROPERTIES, SYSTEM_ROLLBACK),
        'vendor': (VENDOR_PROPERTIES, VENDOR_ROLLBACK),
    }[name]
    if image.stat().st_size != partition_bytes:
        raise ValueError('Unexpected container size')
    with image.open('rb') as stream:
        stream.seek(-64, 2)
        magic, major, minor, original, offset, size, reserved = struct.unpack('>4sIIQQQ28s', stream.read(64))
        if (magic, major, minor, original, reserved) != (b'AVBf', 1, 0, filesystem_bytes, bytes(28)):
            raise ValueError('Unexpected AVB footer')
        if offset < original or offset % 4096 or size < 256 or offset + size > partition_bytes - 64:
            raise ValueError('Invalid vbmeta bounds')
        stream.seek(offset)
        vbmeta = stream.read(size)
    if vbmeta[:12] != struct.pack('>4sII', b'AVB0', 1, 0):
        raise ValueError('Unexpected AVB version')
    auth, auxiliary, algorithm = struct.unpack_from('>QQI', vbmeta, 12)
    desc_offset, desc_size, rollback, flags, location = struct.unpack_from('>QQQII', vbmeta, 96)
    if (algorithm, rollback, flags, location) != (1, rollback_expected, 0, 0):
        raise ValueError('Unexpected signing settings')
    if (auth != 320 or auxiliary % 64 or 256 + auth + auxiliary != size or
            desc_offset + desc_size > auxiliary or any(vbmeta[176:256])):
        raise ValueError('Invalid vbmeta layout')
    hash_offset, hash_size, sig_offset, sig_size, pub_offset, pub_size, meta_offset, meta_size = struct.unpack_from('>8Q', vbmeta, 32)
    if (hash_offset, hash_size, sig_offset, sig_size, pub_size, meta_size) != (0, 32, 32, 256, 520, 0):
        raise ValueError('Unexpected authentication/key dimensions')
    if pub_offset + pub_size > auxiliary or meta_offset + meta_size > auxiliary:
        raise ValueError('Invalid key bounds')
    if not (pub_offset + pub_size <= desc_offset or desc_offset + desc_size <= pub_offset):
        raise ValueError('Overlapping auxiliary fields')
    cursor = 256 + auth + desc_offset
    end = cursor + desc_size
    properties = {}
    tree = None
    while cursor < end:
        if end - cursor < 16:
            raise ValueError('Truncated descriptor')
        tag, following = struct.unpack_from('>QQ', vbmeta, cursor)
        length = following + 16
        if length < 16 or length % 8 or cursor + length > end:
            raise ValueError('Invalid descriptor length')
        descriptor = vbmeta[cursor:cursor + length]
        if tag == 0:
            if length < 32:
                raise ValueError('Truncated property')
            key_size, value_size = struct.unpack_from('>QQ', descriptor, 16)
            finish = 32 + key_size + 1 + value_size + 1
            if finish > length or descriptor[32 + key_size] or descriptor[finish - 1] or any(descriptor[finish:]):
                raise ValueError('Invalid property encoding')
            key = descriptor[32:32 + key_size].decode('utf-8')
            value = descriptor[33 + key_size:finish - 1].decode('utf-8')
            if key in properties:
                raise ValueError('Duplicate property')
            properties[key] = value
        elif tag == 1 and tree is None:
            if length < 180:
                raise ValueError('Truncated hashtree')
            (_, _, version, data_bytes, tree_offset, tree_size, data_block, hash_block,
             fec_roots, fec_offset, fec_size, hash_algorithm, name_size, salt_size,
             digest_size, tree_flags, reserved) = struct.unpack_from('>QQIQQQIIIQQ32sIIII60s', descriptor)
            if (version, data_bytes, tree_offset, data_block, hash_block, fec_roots,
                    fec_offset, fec_size, hash_algorithm, name_size, salt_size,
                    digest_size, tree_flags, reserved) != (
                    1, filesystem_bytes, filesystem_bytes, 4096, 4096, 0, 0, 0,
                    b'sha256' + bytes(26), len(name), 32, 32, 0, bytes(60)):
                raise ValueError('Unexpected hashtree settings')
            finish = 180 + name_size + salt_size + digest_size
            blocks, expected_tree = filesystem_bytes // 4096, 0
            while blocks > 1:
                blocks = (blocks * 32 + 4095) // 4096
                expected_tree += blocks * 4096
            if (descriptor[180:180 + name_size] != name.encode() or
                    descriptor[180 + name_size:180 + name_size + 32] != bytes.fromhex(source_sha) or
                    length != (finish + 7) // 8 * 8 or any(descriptor[finish:]) or
                    tree_size != expected_tree or tree_offset + tree_size != offset):
                raise ValueError('Invalid tree name, salt, size or bounds')
            tree = {'tree_offset': tree_offset, 'tree_bytes': tree_size}
        else:
            raise ValueError('Unknown or duplicate descriptor')
        cursor += length
    if tree is None or properties != properties_expected:
        raise ValueError('Missing tree or changed properties')
    return {'partition_name': name, 'properties': properties, 'rollback_index': rollback,
            'rollback_index_location': location, 'flags': flags, 'vbmeta_offset': offset,
            'vbmeta_bytes': size, 'descriptor_count': 1 + len(properties), **tree}
