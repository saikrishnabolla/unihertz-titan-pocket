import os
import pathlib
import struct
import unittest
import tempfile
import hashlib
import json
import stat

import clat_label_adapter as adapter

SOURCE = pathlib.Path(os.environ.get('TITAN_CLAT_SOURCE', 'inputs/libservice-connectivity.so'))
ACTUAL = 'u:object_r:fs_bpf:s0'
RECORDED = (
    '/sys/fs/bpf/net_shared',
    '/sys/fs/bpf/net_shared/prog_clatd_schedcls_egress4_clat_rawip',
    '/sys/fs/bpf/net_shared/prog_clatd_schedcls_ingress6_clat_rawip',
    '/sys/fs/bpf/net_shared/prog_clatd_schedcls_ingress6_clat_ether',
    '/sys/fs/bpf/net_shared/map_clatd_clat_egress4_map',
    '/sys/fs/bpf/net_shared/map_clatd_clat_ingress6_map',
)

def replay_recorded_contexts(data):
    """Independent literal page/mapping oracle from exact llvm disassembly."""
    # PT_LOAD inspection independently established VA == file offset here.
    expectations = []
    for instruction in (0xbd80,) + (0xbda8,) * 5:
        word = struct.unpack_from('<I', data, instruction)[0]
        address = 0x4000 + ((word >> 10) & 0xfff)
        expectations.append(data[address:data.index(b'\0', address)].decode())
    return [(path, context, ACTUAL) for path, context in zip(RECORDED, expectations)
            if context != ACTUAL]

class ReplayTests(unittest.TestCase):
    def test_adapter_clears_all_six_recorded_context_mismatches(self):
        candidate, _ = adapter.adapt(SOURCE.read_bytes())
        self.assertEqual(replay_recorded_contexts(candidate), [])

    def test_original_reproduces_exactly_the_six_recorded_failures(self):
        failures = replay_recorded_contexts(SOURCE.read_bytes())
        self.assertEqual([x[0] for x in failures], list(RECORDED))
        self.assertEqual({x[1] for x in failures}, {'u:object_r:fs_bpf_net_shared:s0'})

    def test_real_binary_elf_mapping_build_id_and_pointer_provenance(self):
        original = SOURCE.read_bytes()
        elf = adapter.Elf(original)
        self.assertEqual(elf.build_id(), 'f23735832a2a0ea900d2919001172c9d')
        for va in (0xbcc8, 0xbd80, 0xbda8, 0xbf98):
            self.assertEqual(elf.offset(va, 4, executable=True), va)
        self.assertEqual(adapter.resolve_pair(elf, 0xbd58, 0xbd5c, 4), 0x4b4e)
        self.assertEqual(adapter.resolve_pair(elf, 0xbd7c, 0xbd80, 4), 0x4817)
        self.assertEqual(adapter.resolve_pair(elf, 0xbda4, 0xbda8, 20), 0x4817)

    def test_exact_two_instruction_replacements_and_no_other_changed_bytes(self):
        original = SOURCE.read_bytes()
        candidate, manifest = adapter.adapt(original)
        self.assertEqual(candidate[0xbd80:0xbd84], bytes.fromhex('84382d91'))
        self.assertEqual(candidate[0xbda8:0xbdac], bytes.fromhex('943a2d91'))
        self.assertEqual([i for i, pair in enumerate(zip(original, candidate)) if pair[0] != pair[1]],
                         [0xbd81, 0xbd82, 0xbda9, 0xbdaa])
        self.assertEqual(len(candidate), 119600)
        self.assertEqual(manifest['changed_byte_offsets'], [0xbd81, 0xbd82, 0xbda9, 0xbdaa])

    def test_readonly_strings_and_all_fatal_abort_and_permission_code_are_preserved(self):
        original = SOURCE.read_bytes()
        candidate, _ = adapter.adapt(original)
        self.assertEqual(candidate[:30208], original[:30208])
        self.assertEqual(candidate[0xbe4c:0xbe5c], original[0xbe4c:0xbe5c])
        self.assertEqual(candidate[0xbf98:0xbf9c], bytes.fromhex('c2220094'))
        self.assertEqual(candidate[0xc308:], original[0xc308:])
        # Root, clat directory and clat executable checks precede the two edits.
        self.assertEqual(candidate[0xbcc8:0xbd80], original[0xbcc8:0xbd80])

    def test_wrong_input_and_corrupted_instruction_are_refused(self):
        original = SOURCE.read_bytes()
        for index in (0, 0xbd80, 0xbda8, 0xbf98):
            with self.subTest(index=index):
                bad = bytearray(original)
                bad[index] ^= 1
                with self.assertRaisesRegex(ValueError, 'pinned'):
                    adapter.adapt(bytes(bad))
        with self.assertRaisesRegex(ValueError, 'pinned'):
            adapter.adapt(original[:-1])

    def test_device_restrictions_and_no_runtime_claim_are_in_manifest(self):
        _, report = adapter.adapt(SOURCE.read_bytes())
        target = report['target_restrictions']
        self.assertEqual(target['product'], 'Titan_pocket')
        self.assertEqual(target['kernel_release'], '4.14.186-g40b2a1864-dirty')
        self.assertEqual(target['repaired_boot_sha256'],
                         'c3aa2e73c3efbce4b6fe6558558d91826be868d8981f99d04242b4d0cb6876ce')
        self.assertFalse(target['device_verified_by_this_tool'])
        self.assertIn('NOT BOOT TESTED', report['status'])

class GuardTests(unittest.TestCase):
    def test_out_of_range_and_non_executable_addresses_are_refused(self):
        elf = adapter.Elf(SOURCE.read_bytes())
        for address in (-1, 119600, 0xffffffffffffffff, 0x1c000):
            with self.subTest(address=address), self.assertRaises(ValueError):
                elf.offset(address, executable=True)
        with self.assertRaises(ValueError):
            elf.offset(0x4817, executable=True)
        with self.assertRaises(ValueError):
            elf.offset(0x4817, size=0)

    def test_wrong_architecture_and_truncated_program_table_are_refused(self):
        original = SOURCE.read_bytes()
        bad = bytearray(original)
        struct.pack_into('<H', bad, 18, 62)
        with self.assertRaisesRegex(ValueError, 'AArch64'):
            adapter.Elf(bad)
        bad = bytearray(original)
        struct.pack_into('<Q', bad, 32, len(bad) - 1)
        with self.assertRaisesRegex(ValueError, 'program header'):
            adapter.Elf(bad)

    def test_ambiguous_executable_mapping_is_refused(self):
        data = bytearray(SOURCE.read_bytes())
        phoff = struct.unpack_from('<Q', data, 32)[0]
        # Replace a later non-LOAD header with a duplicate of the text LOAD.
        data[phoff + 8 * 56:phoff + 9 * 56] = data[phoff + 2 * 56:phoff + 3 * 56]
        elf = adapter.Elf(data)
        with self.assertRaisesRegex(ValueError, 'one file-backed'):
            elf.offset(0xbd80, executable=True)

    def test_malformed_gnu_note_is_refused(self):
        data = bytearray(SOURCE.read_bytes())
        struct.pack_into('<I', data, 624 + 4, 0xffff)
        with self.assertRaisesRegex(ValueError, 'note'):
            adapter.Elf(data).build_id()

    def test_add_immediate_limits_and_opcode_are_checked(self):
        for value in (-1, 0x1000):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '12-bit'):
                adapter.encode_add64(0x91205c84, value)
        for word in (0xd503201f, 0x91605c84, 0x11205c84):
            with self.subTest(word=word), self.assertRaisesRegex(ValueError, 'ADD'):
                adapter.encode_add64(word, 0xb4e)
        self.assertEqual(adapter.encode_add64(0x91205c84, 0xb4e), 0x912d3884)

class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def test_real_build_writes_private_candidate_and_preserves_source(self):
        source = self.root / 'source.so'
        original = SOURCE.read_bytes()
        source.write_bytes(original)
        output = self.root / 'candidate'
        report = adapter.build(source, output)
        self.assertEqual(source.read_bytes(), original)
        candidate = output / 'libservice-connectivity.so'
        self.assertEqual(hashlib.sha256(candidate.read_bytes()).hexdigest(), report['result_sha256'])
        self.assertEqual(replay_recorded_contexts(candidate.read_bytes()), [])
        self.assertEqual(json.loads((output / 'manifest.json').read_text()), report)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((output / 'manifest.json').stat().st_mode), 0o600)

    def test_source_symlink_is_refused_before_output_creation(self):
        link = self.root / 'source.so'
        link.symlink_to(SOURCE)
        output = self.root / 'candidate'
        with self.assertRaisesRegex(ValueError, 'non-symlink'):
            adapter.build(link, output)
        self.assertFalse(output.exists())

    def test_wrong_source_does_not_create_output(self):
        source = self.root / 'wrong.so'
        source.write_bytes(b'not the library')
        output = self.root / 'candidate'
        with self.assertRaisesRegex(ValueError, 'pinned'):
            adapter.build(source, output)
        self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        output = self.root / 'candidate'
        output.mkdir()
        marker = output / 'keep'
        marker.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            adapter.build(SOURCE, output)
        self.assertEqual(marker.read_bytes(), b'preserve')
        self.assertEqual(sorted(x.name for x in output.iterdir()), ['keep'])

if __name__ == '__main__':
    unittest.main()
