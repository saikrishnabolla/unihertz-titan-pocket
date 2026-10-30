#!/usr/bin/env python3
"""Boundary tests using the pinned local artifacts; no device or network access."""
from pathlib import Path
import json
import struct
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
import build_connectivity_apex as b


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(b.SOURCE) as z:
            cls.original = z.read('apex_payload.img')
        cls.patched = b.patch_payload(cls.original)
        cls.netd = cls.original[b.NETD_OFFSET:b.NETD_OFFSET + b.NETD_SIZE]
        cls.new_netd = cls.patched[b.NETD_OFFSET:b.NETD_OFFSET + b.NETD_SIZE]

    def test_exact_six_byte_delta_and_immutable_input(self):
        self.assertEqual(b.changed_offsets(self.original, self.patched),
                         [3154800, 3154801, 3154802, 3156420, 3156421, 3156422])
        self.assertEqual(b.sha(self.original), b.PAYLOAD_SHA)
        for offset in b.FIELDS.values():
            self.assertEqual(struct.unpack_from('<I', self.patched, offset)[0], 65536)
        b.verify_fs_delta(self.original, self.patched)

    def test_wrong_payload_hash_refused(self):
        data = bytearray(self.original)
        data[1024] ^= 1
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            b.patch_payload(data)

    def test_wrong_source_hash_refused(self):
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            b.pinned(b.SOURCE.read_bytes()[:-1], b.SOURCE_SHA)

    def test_wrong_field_refused(self):
        for offset in b.FIELDS.values():
            data = bytearray(self.original)
            struct.pack_into('<I', data, offset, 3501)
            with self.assertRaisesRegex(ValueError, 'wrong max_api'):
                b.patch_payload(data)

    def test_wrong_length_refused(self):
        with self.assertRaisesRegex(ValueError, 'wrong payload length'):
            b.patch_payload(self.original[:-1])

    def test_second_patch_refused(self):
        with self.assertRaisesRegex(ValueError, 'wrong max_api'):
            b.patch_payload(self.patched)

    def test_other_filesystem_change_refused(self):
        data = bytearray(self.patched)
        data[12345] ^= 1
        with self.assertRaisesRegex(ValueError, 'filesystem differs'):
            b.verify_fs_delta(self.original, data)

    def test_reparse_all_definitions_and_4_14_gates(self):
        result = b.compare_defs(self.netd, self.new_netd)
        self.assertEqual(result['count'], 50)
        self.assertEqual(result['gates']['newly_eligible'], sorted(b.FIELDS))
        self.assertEqual(result['gates']['eligible_before'], ['cgroupsock_inet_create_4_14_t_def',
                         'schedact_ingress_account_4_9_def', 'skfilter_allowlist_xtbpf_4_9_def',
                         'skfilter_denylist_xtbpf_4_9_def', 'skfilter_egress_xtbpf_4_9_def',
                         'skfilter_ingress_xtbpf_4_9_def'])

    def test_other_definition_field_refused(self):
        data = bytearray(self.new_netd)
        data[b.FIELDS['ingress_stats_4_9_t_def'] - b.NETD_OFFSET - 28] ^= 1
        with self.assertRaisesRegex(ValueError, 'another definition field changed'):
            b.compare_defs(self.netd, data)

    def test_other_definition_refused(self):
        data = bytearray(self.new_netd)
        defs = b.elf_defs(data)
        offset = defs['cgroupsock_inet_create_4_14_t_def']['offset']
        data[offset + 32] ^= 1
        with self.assertRaisesRegex(ValueError, 'unapproved program changed'):
            b.compare_defs(self.netd, data)

    def test_bytecode_tamper_refused(self):
        data = bytearray(self.new_netd)
        data[0x147a0] ^= 1
        with self.assertRaisesRegex(ValueError, 'other netd bytes changed'):
            b.compare_defs(self.netd, data)

    def test_bad_elf_refused(self):
        with self.assertRaisesRegex(ValueError, 'expected ELF64'):
            b.elf_defs(b'not an ELF')

    def test_footer_layout_tamper_refused(self):
        data = bytearray(self.original)
        struct.pack_into('>Q', data, len(data) - 44, 123)
        with self.assertRaisesRegex(ValueError, 'footer layout changed'):
            b.embedded_key(data)


class ZipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=b.WORK, prefix='zip-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.output = self.root / 'source.zip', self.root / 'output.zip'
        with zipfile.ZipFile(self.source, 'w') as z:
            z.writestr('apex_payload.img', b'original')
            z.writestr('apex_pubkey', b'oldkey')
            z.writestr('META-INF/CERT.SF', b'exact preserved data')

    def test_aligned_zip_and_preserved_entries(self):
        b.rebuild_zip(self.source, self.output, b'newpayload', b'newkey')
        result = b.verify_zip(self.source, self.output, b'newpayload', b'newkey')
        self.assertEqual(result['payload_offset'], 4096)
        self.assertEqual(len(result['entries']), 3)

    def test_unaligned_payload_refused(self):
        with zipfile.ZipFile(self.output, 'w') as z:
            z.writestr('apex_payload.img', b'newpayload')
            z.writestr('apex_pubkey', b'newkey')
            z.writestr('META-INF/CERT.SF', b'exact preserved data')
        with self.assertRaisesRegex(ValueError, '4096 aligned'):
            b.verify_zip(self.source, self.output, b'newpayload', b'newkey')

    def test_compressed_payload_refused(self):
        with zipfile.ZipFile(self.source, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('apex_payload.img', b'original')
        with self.assertRaisesRegex(ValueError, 'compressed source payload'):
            b.rebuild_zip(self.source, self.output, b'newpayload', b'newkey')

    def test_missing_entry_refused(self):
        with zipfile.ZipFile(self.output, 'w') as z:
            z.writestr('apex_payload.img', b'newpayload')
        with self.assertRaisesRegex(ValueError, 'inventory or order changed'):
            b.verify_zip(self.source, self.output, b'newpayload', b'newkey')

    def test_wrong_key_refused(self):
        b.rebuild_zip(self.source, self.output, b'newpayload', b'newkey')
        with self.assertRaisesRegex(ValueError, 'ZIP entry changed: apex_pubkey'):
            b.verify_zip(self.source, self.output, b'newpayload', b'wrongkey')

    def test_other_entry_tampering_refused(self):
        b.rebuild_zip(self.source, self.output, b'newpayload', b'newkey')
        tampered = self.root / 'tampered.zip'
        with zipfile.ZipFile(self.output) as old, zipfile.ZipFile(tampered, 'w') as new:
            for entry in old.infolist():
                new.writestr(entry, b'tampered' if entry.filename == 'META-INF/CERT.SF'
                             else old.read(entry))
        with self.assertRaisesRegex(ValueError, 'ZIP entry changed: META-INF/CERT.SF'):
            b.verify_zip(self.source, tampered, b'newpayload', b'newkey')

    def test_source_overwrite_refused(self):
        with self.assertRaisesRegex(ValueError, 'refuse overwrite source'):
            b.rebuild_zip(self.source, self.source, b'newpayload', b'newkey')


class RealSignatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=b.WORK, prefix='tamper-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_avb_detects_payload_tampering(self):
        image = self.root / 'tampered.img'
        data = bytearray((b.WORK / 'apex_payload.img').read_bytes())
        data[12345] ^= 1
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'command failed'):
            b.run(['python3', b.AVB, 'verify_image', '--image', image,
                   '--key', b.WORK / 'keys/payload.pem'])

    def test_avb_detects_tree_tampering(self):
        image = self.root / 'tampered.img'
        data = bytearray((b.WORK / 'apex_payload.img').read_bytes())
        data[b.DATA_SIZE + 123] ^= 1
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'command failed'):
            b.run(['python3', b.AVB, 'verify_image', '--image', image,
                   '--key', b.WORK / 'keys/payload.pem'])

    def test_avb_detects_wrong_signing_key(self):
        with self.assertRaisesRegex(ValueError, 'command failed'):
            b.run(['python3', b.AVB, 'verify_image', '--image', b.WORK / 'apex_payload.img',
                   '--key', b.WORK / 'keys/container.pem'])

    def test_apk_v3_detects_payload_tampering(self):
        output = self.root / 'tampered.apex'
        data = bytearray((b.WORK / 'com.android.tethering.apex').read_bytes())
        with zipfile.ZipFile(b.WORK / 'com.android.tethering.apex') as z:
            offset = b.payload_offset(b.WORK / 'com.android.tethering.apex',
                                      z.getinfo('apex_payload.img'))
        data[offset + 12345] ^= 1
        output.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'command failed'):
            b.run(b.SIGNER + ['verify', '--verbose', '--min-sdk-version', '29',
                              '--max-sdk-version', '37', str(output)])


if __name__ == '__main__':
    record = '--record-evidence' in sys.argv
    if record:
        sys.argv.remove('--record-evidence')
    result = unittest.main(verbosity=2, exit=False).result
    if result.wasSuccessful() and record:
        evidence = Path(__file__).resolve().parents[1] / 'evidence/connectivity-apex-build.json'
        report = json.loads(evidence.read_text())
        b.pinned((b.WORK / 'com.android.tethering.apex').read_bytes(), report['output']['sha256'])
        report['tests'] = dict(command=['python3', str(Path(__file__).resolve()), '--record-evidence'],
                              exit=0, passed=result.testsRun, failures=0, errors=0,
                              scope='Pinned-artifact boundary tests and real AVB/APKv3 tamper refusals.')
        evidence.write_text(json.dumps(report, indent=2) + '\n')
    sys.exit(0 if result.wasSuccessful() else 1)
