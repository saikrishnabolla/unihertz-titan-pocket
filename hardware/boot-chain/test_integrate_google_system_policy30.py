#!/usr/bin/env python3
import hashlib
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import integrate_google_system_policy30 as policy30

MATRIX = b'''<!--
    Input:
        hardware/interfaces/compatibility_matrices/compatibility_matrix.empty.xml
-->
<compatibility-matrix version="9.0" type="framework">
    <sepolicy>
        <kernel-sepolicy-version>30</kernel-sepolicy-version>
        <sepolicy-version>31.0</sepolicy-version>
        <sepolicy-version>32.0</sepolicy-version>
        <sepolicy-version>33.0</sepolicy-version>
        <sepolicy-version>34.0</sepolicy-version>
        <sepolicy-version>202404</sepolicy-version>
        <sepolicy-version>202504</sepolicy-version>
        <sepolicy-version>202604</sepolicy-version>
    </sepolicy>
    <avb>
        <vbmeta-version>1.0</vbmeta-version>
    </avb>
</compatibility-matrix>
'''


class MatrixTests(unittest.TestCase):
    def test_literal_production_contract(self):
        self.assertEqual(policy30.SOURCE_SHA, '915a1ccf82ca0845dc182d922024fa3edd9f807beb97ebd6f3b4d5b9cc822a22')
        self.assertEqual(policy30.SOURCE_BYTES, 3221225472)
        self.assertEqual(policy30.MAPPING_SHA, '22a897761e5c9f5e37d61c908819a00183ce5b52c10cc89608d8226eb892bf24')
        self.assertEqual(policy30.COMPAT_SHA, '162c01e64db8206631160c14aa132a2e5a36f4cf6a5db229df6fdf81825e4a18')
        self.assertEqual(policy30.EXT_POLICY_SHA, 'bcdaa16015d01771f85972ef7a2eb885708294898030d6ab78fbfa30f8090014')
        self.assertEqual(policy30.TEMPLATE_CONTENT,
                         ((142432, '96964df1ab17c132dc077fe55e936169818f6b36ce0584a4115eaf41a426cab3'),
                          (521, 'a48742b9a57d3950efb59952c8fdd815b68d3f8605cc533efae7015cca3d6936')))
        self.assertEqual(policy30.VENDOR_REFERENCE_SHA, 'a3d0d55f547faf10a466861fe63ca1e8485b1c56cd7e5627bd75a1dcbf0c6c6f')

    def test_exact_one_line_and_retained_binary30(self):
        result = policy30.insert_version(MATRIX)
        self.assertEqual(len(result), 745)
        self.assertEqual(hashlib.sha256(result).hexdigest(),
                         'c052c7b6c40542602bdd9605e2467fdb5e164cce54cbae51c9439810008bf905')
        self.assertEqual(result.replace(b'        <sepolicy-version>30.0</sepolicy-version>\n', b''), MATRIX)
        self.assertIn(b'<kernel-sepolicy-version>30</kernel-sepolicy-version>', result)

    def test_matrix_mutations_refused(self):
        for value in (MATRIX + b'\n', MATRIX.replace(b'>30<', b'>31<'),
                      MATRIX.replace(b'<sepolicy>', b'<sepolicy/><sepolicy>'),
                      MATRIX.replace(b'>31.0<', b'>30.0<')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy30.insert_version(value)


def baseline():
    before = {}
    for suffix, (size, digest) in zip(('.cil', '.compat.cil'), policy30.TEMPLATE_CONTENT):
        path = policy30.MAP_DIR + '/31.0' + suffix
        before[path] = policy30.template_pin(path, size, digest)
    item = copy.deepcopy(before[policy30.MAP_DIR + '/31.0.cil'])
    def regular(path, size, digest):
        before[path] = copy.deepcopy(item)
        before[path].update(size=size, sha256=digest, same_inode_paths=[path])
    regular(policy30.MATRIX, 695, policy30.MATRIX_BEFORE_SHA)
    for parent in policy30.PARENTS:
        before[parent] = copy.deepcopy(item)
        before[parent].update(type='directory', same_inode_paths=[parent])
    for part in ('system_ext', 'product'):
        before['/' + part] = {'type': 'symlink', 'symlink_target': '/system/' + part}
        prefix = '/system/' + part + '/etc/selinux/'
        for version in policy30.VERSIONS:
            regular(prefix + 'mapping/' + version + '.cil', 0, policy30.EMPTY_SHA)
            if part == 'system_ext':
                regular(prefix + 'mapping/' + version + '.compat.cil', 0, policy30.EMPTY_SHA)
        regular(prefix + 'mapping/202604.cil', 1, policy30.NEWLINE_SHA)
        regular(prefix + part + '_sepolicy.cil', 275433, policy30.EXT_POLICY_SHA)
    return before


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.before = baseline()
        self.mapping, self.compat = b'; map fixture\n', b'; compat fixture\n'
        self.pins = mock.patch.multiple(policy30,
            MAPPING_SHA=hashlib.sha256(self.mapping).hexdigest(),
            COMPAT_SHA=hashlib.sha256(self.compat).hexdigest())
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def test_exact_delta_and_all_metadata_preserved(self):
        after = policy30.expected_inventory(self.before, self.mapping, self.compat)
        result = policy30.compare(self.before, after, self.mapping, self.compat)
        self.assertEqual(result, {'added': ['/system/etc/selinux/mapping/30.0.cil',
                                           '/system/etc/selinux/mapping/30.0.compat.cil'],
                                  'changed': ['/system/etc/vintf/compatibility_matrix.device.xml'],
                                  'all_unrelated_entries_equal': True})
        self.assertEqual(self.before, baseline())
        for path in policy30.ADDED:
            template = self.before[path.replace('/30.0', '/31.0')]
            self.assertEqual({k: v for k, v in after[path].items() if k not in ('size', 'sha256', 'same_inode_paths')},
                             {k: v for k, v in template.items() if k not in ('size', 'sha256', 'same_inode_paths')})

    def test_every_metadata_field_and_payload_drift_refused(self):
        good = policy30.expected_inventory(self.before, self.mapping, self.compat)
        for path in (*policy30.ADDED, policy30.MATRIX, policy30.MAP_DIR + '/31.0.cil'):
            for field in good[path]:
                bad = copy.deepcopy(good)
                bad[path][field] = 'corrupted'
                with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                    policy30.compare(self.before, bad, self.mapping, self.compat)

    def test_missing_map_extra_payload_and_parent_timestamp_refused(self):
        good = policy30.expected_inventory(self.before, self.mapping, self.compat)
        for change in ('missing', 'extra', 'parent'):
            bad = copy.deepcopy(good)
            if change == 'missing':
                del bad[policy30.ADDED[0]]
            elif change == 'extra':
                bad['/extra'] = {}
            else:
                bad[policy30.PARENTS[0]]['timestamps_debugfs'] = []
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy30.compare(self.before, bad, self.mapping, self.compat)

    def test_source_template_mutations_preexisting_map_and_extension_maps_refused(self):
        path = policy30.MAP_DIR + '/31.0.cil'
        for field, value in (('links', 2), ('type', 'symlink'), ('xattrs', {}), ('generation', 7)):
            bad = copy.deepcopy(self.before)
            bad[path][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy30.expected_inventory(bad, self.mapping, self.compat)
        for extra in (policy30.ADDED[0], '/system/product/etc/selinux/mapping/30.0.cil'):
            bad = copy.deepcopy(self.before)
            bad[extra] = copy.deepcopy(bad[path])
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                policy30.expected_inventory(bad, self.mapping, self.compat)
        bad = copy.deepcopy(self.before)
        bad['/system/product/etc/selinux/mapping/202604.cil']['sha256'] = policy30.EMPTY_SHA
        with self.assertRaises(ValueError):
            policy30.expected_inventory(bad, self.mapping, self.compat)

    def test_actual_newline_maps_accepted_and_wrong_mapping_bytes_refused(self):
        policy30.validate_source_inventory(self.before)
        with self.assertRaises(ValueError):
            policy30.expected_inventory(self.before, b'wrong', self.compat)


@unittest.skipUnless(all(Path(p).exists() for p in ('/usr/sbin/mke2fs', '/usr/sbin/debugfs', '/usr/sbin/e2fsck')),
                     'ext4 tools unavailable')
class Ext4Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='policy30-test-', )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        tree = self.root / 'tree'
        tree.mkdir()
        files = {policy30.MATRIX: MATRIX, '/system/etc/vintf/manifest.xml': b'<manifest/>\n',
                 '/system/bin/init': b'unchanged init',
                 policy30.MAP_DIR + '/31.0.cil': b'; fixture31\n',
                 policy30.MAP_DIR + '/31.0.compat.cil': b'; fixture compat31\n'}
        for part in ('system_ext', 'product'):
            prefix = '/system/' + part + '/etc/selinux/'
            files[prefix + part + '_sepolicy.cil'] = b'x' * 275433
            for version in policy30.VERSIONS:
                files[prefix + 'mapping/' + version + '.cil'] = b''
                if part == 'system_ext':
                    files[prefix + 'mapping/' + version + '.compat.cil'] = b''
            files[prefix + 'mapping/202604.cil'] = b'\n'
        for path, data in files.items():
            target = tree / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for part in ('system_ext', 'product'):
            (tree / part).symlink_to('/system/' + part)
        self.source = self.root / 'source.ext4'
        self.source.write_bytes(b'')
        with self.source.open('r+b') as stream:
            stream.truncate(4 * 1024**2)
        self.run_tool(['/usr/sbin/mke2fs', '-q', '-t', 'ext4', '-O', '^has_journal', '-d', str(tree), str(self.source)])
        content = tuple((len(files[policy30.MAP_DIR + '/31.0' + suffix]),
                         hashlib.sha256(files[policy30.MAP_DIR + '/31.0' + suffix]).hexdigest())
                        for suffix in ('.cil', '.compat.cil'))
        commands = []
        for number, (suffix, (size, digest)) in enumerate(zip(('.cil', '.compat.cil'), content)):
            path = policy30.MAP_DIR + '/31.0' + suffix
            commands.extend(policy30.replacement_commands(path, files[path], policy30.template_pin(path, size, digest),
                                                         self.root, number, replace=True))
        self.run_tool(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(self.source)], '\n'.join(commands) + '\n')
        self.mapping, self.compat = self.root / 'map.cil', self.root / 'compat.cil'
        self.mapping.write_bytes(b'; fixture map30\n')
        self.compat.write_bytes(b'; fixture compat30\n')
        self.output = self.root / 'published'
        stack = self.enterContext(ExitStack())
        stack.enter_context(mock.patch.multiple(policy30, SOURCE_SHA=policy30.sha(self.source),
            SOURCE_BYTES=self.source.stat().st_size, TEMPLATE_CONTENT=content,
            MAPPING_SHA=policy30.sha(self.mapping), COMPAT_SHA=policy30.sha(self.compat),
            EXT_POLICY_SHA=hashlib.sha256(b'x' * 275433).hexdigest()))

    def run_tool(self, args, stdin=None):
        result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def build(self):
        return policy30.build(self.source, self.mapping, self.compat, self.output)

    def test_real_ext4_exact_delta_fsck_and_inputs_unchanged(self):
        original = policy30.sha(self.source)
        report = self.build()
        self.assertEqual(policy30.sha(self.source), original)
        self.assertEqual(report['paths_after'], report['paths_before'] + 2)
        before = json.loads((self.output / 'before/inventory.json').read_text())
        after = json.loads((self.output / 'after/inventory.json').read_text())
        self.assertEqual(set(after) - set(before), set(policy30.ADDED))
        self.assertEqual({p for p in before if before[p] != after[p]}, {policy30.MATRIX})
        self.assertFalse(report['vendor_pin_and_three_identifier_pairs_verified'])
        self.assertTrue((self.output / 'report.json').is_file())
        self.assertEqual(policy30.sha(self.output / 'system.ext4'), report['image_sha256'])
        self.run_tool(['/usr/sbin/e2fsck', '-fn', str(self.output / 'system.ext4')])

    def test_published_image_is_private_despite_caller_umask(self):
        previous = os.umask(0o022)
        try:
            self.build()
        finally:
            os.umask(previous)
        self.assertEqual((self.output.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((self.output / 'system.ext4').stat().st_mode & 0o777), 0o600)

    def test_wrong_pins_existing_output_and_space_refuse_without_staging(self):
        original = set(self.root.iterdir())
        for pin in ('SOURCE_SHA', 'MAPPING_SHA', 'COMPAT_SHA'):
            with self.subTest(pin=pin), mock.patch.object(policy30, pin, '0' * 64), self.assertRaises(ValueError):
                self.build()
            self.assertEqual(set(self.root.iterdir()), original)
        with mock.patch.object(policy30.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(1, 1, 0)), self.assertRaises(ValueError):
            self.build()
        self.assertEqual(set(self.root.iterdir()), original)
        self.output.mkdir()
        (self.output / 'user-file').write_text('keep')
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual((self.output / 'user-file').read_text(), 'keep')

    def test_postcomparison_failure_never_publishes(self):
        with mock.patch.object(policy30, 'compare', side_effect=ValueError('injected comparison failure')), self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())
        partial = list(self.root.glob('.published.partial-*'))
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0].stat().st_mode & 0o777, 0o700)

    def test_report_write_failure_never_publishes(self):
        original = Path.write_text
        def fail_report(path, data, *args, **kwargs):
            if path.name == 'report.json':
                raise OSError('injected report write failure')
            return original(path, data, *args, **kwargs)
        with mock.patch.object(Path, 'write_text', fail_report), self.assertRaises(OSError):
            self.build()
        self.assertFalse(self.output.exists())
        self.assertEqual(len(list(self.root.glob('.published.partial-*'))), 1)

    def test_hash_manifest_failure_after_report_never_publishes(self):
        original = Path.write_text
        def fail_manifest(path, data, *args, **kwargs):
            if path.name == 'sha256.txt':
                raise OSError('injected hash manifest failure')
            return original(path, data, *args, **kwargs)
        with mock.patch.object(Path, 'write_text', fail_manifest), self.assertRaises(OSError):
            self.build()
        self.assertFalse(self.output.exists())
        partial = list(self.root.glob('.published.partial-*'))
        self.assertEqual(len(partial), 1)
        self.assertTrue((partial[0] / 'report.json').is_file())

    def test_source_mutation_on_recheck_never_publishes(self):
        original = policy30.sha
        calls = 0
        def mutate_hash(path):
            nonlocal calls
            if path == self.source:
                calls += 1
                if calls == 2:
                    return '0' * 64
            return original(path)
        with mock.patch.object(policy30, 'sha', side_effect=mutate_hash), self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_output_symlink_refused_without_touching_target(self):
        target = self.root / 'user-target'
        target.mkdir()
        self.output.symlink_to(target, target_is_directory=True)
        original = set(self.root.iterdir())
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(set(self.root.iterdir()), original)
        self.assertEqual(list(target.iterdir()), [])

    def add_vintf_xml(self, data):
        payload = self.root / 'extra.xml'
        payload.write_bytes(data)
        self.run_tool(['/usr/sbin/debugfs', '-w', '-R',
                       f'write "{payload}" /system/etc/vintf/extra.xml', str(self.source)])

    def test_malformed_additional_xml_refused_before_image_copy(self):
        self.add_vintf_xml(b'<manifest>')
        with mock.patch.object(policy30, 'SOURCE_SHA', policy30.sha(self.source)), \
             mock.patch.object(policy30.shutil, 'copyfile', wraps=shutil.copyfile) as copying:
            with self.assertRaises(ET.ParseError):
                self.build()
            copying.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_additional_sepolicy_declaration_refused_before_image_copy(self):
        self.add_vintf_xml(b'<manifest><sepolicy/></manifest>\n')
        with mock.patch.object(policy30, 'SOURCE_SHA', policy30.sha(self.source)), \
             mock.patch.object(policy30.shutil, 'copyfile', wraps=shutil.copyfile) as copying:
            with self.assertRaisesRegex(ValueError, 'additional VINTF'):
                self.build()
            copying.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_resolved_duplicate_inputs_refused_before_hashing(self):
        with mock.patch.object(policy30, 'sha') as hashing:
            with self.assertRaisesRegex(ValueError, 'alias'):
                policy30.build(self.source, self.source, self.compat, self.output)
            hashing.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_leaf_symlink_input_refused(self):
        link = self.root / 'linked-map.cil'
        link.symlink_to(self.mapping)
        with self.assertRaisesRegex(ValueError, 'regular, non-symlink'):
            policy30.build(self.source, link, self.compat, self.output)
        self.assertFalse(self.output.exists())

    def test_symlinked_parent_with_regular_leaf_is_supported(self):
        parent = self.root / 'alias-parent'
        parent.symlink_to(self.root, target_is_directory=True)
        report = policy30.build(parent / self.source.name, self.mapping, self.compat, self.output)
        self.assertEqual(report['paths_after'], report['paths_before'] + 2)
        self.assertTrue((self.output / 'system.ext4').is_file())


if __name__ == '__main__':
    unittest.main()
