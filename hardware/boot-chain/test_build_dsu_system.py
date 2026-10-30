import copy
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from build_dsu_system import compare, finish, full_inventory, regular, replacement_commands, signing_args, unshare, FS_BYTES, TARGET
from check_dsu_system_avb import PROPERTIES
from sign_dsu_product import sha


class SystemDeltaTests(unittest.TestCase):
    def test_unsharing_must_preserve_every_field(self):
        before = {'/': {'mode': '0755'}, TARGET: {'size': 12, 'sha256': 'a'}}
        self.assertEqual(compare(before, copy.deepcopy(before)), {})
        after = copy.deepcopy(before)
        after['/']['mode'] = '0777'
        with self.assertRaises(ValueError):
            compare(before, after)

    def test_only_exact_supplied_apex_replacement_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            apex = Path(temp) / 'apex'
            apex.write_bytes(b'replacement')
            before = {'/': {'mode': '0755'}, TARGET: {'size': 12, 'sha256': 'a', 'uid': 0}}
            after = copy.deepcopy(before)
            after[TARGET].update(size=11, sha256=sha(apex))
            self.assertEqual(compare(before, after, apex), {TARGET: ['size', 'sha256']})
            for field, value in [('uid', 1000), ('size', 9), ('sha256', 'b')]:
                wrong = copy.deepcopy(after)
                wrong[TARGET][field] = value
                with self.assertRaises(ValueError):
                    compare(before, wrong, apex)

    def test_added_deleted_and_missing_fields_fail(self):
        before = {'/': {'mode': '0755'}, TARGET: {'size': 12}}
        for after in [{'/' : before['/']}, {**before, '/extra': {}},
                      {'/': {}, TARGET: before[TARGET]}]:
            with self.assertRaises(ValueError):
                compare(before, after)

    def test_symlinks_and_devices_are_not_images(self):
        with tempfile.TemporaryDirectory() as temp:
            link = Path(temp) / 'link'
            link.symlink_to('/dev/null')
            for path in (link, Path('/dev/null'), Path(temp)):
                with self.assertRaises(ValueError):
                    regular(path)

    def test_signing_contract_preserves_rollback_and_all_properties(self):
        args = signing_args(Path('image'), Path('key'), Path('avbtool'), 'a' * 64)
        self.assertEqual(args[args.index('--rollback_index') + 1], '1791158400')
        props = [args[i + 1] for i, value in enumerate(args) if value == '--prop']
        self.assertEqual(props, [name + ':' + value for name, value in PROPERTIES.items()])
        self.assertIn('--do_not_generate_fec', args)

    def test_unshare_temporarily_disables_then_restores_directory_indexing(self):
        calls = []
        unshare(Path('image'), {'/': {'type': 'directory', 'flags': 0x80000}},
                lambda args, **kwargs: calls.append((list(map(str, args)), kwargs)))
        self.assertEqual(calls, [
            (['/usr/sbin/tune2fs', '-O', '^dir_index', 'image'], {}),
            (['/usr/sbin/e2fsck', '-fy', '-E', 'unshare_blocks,fixes_only', 'image'], {'allowed': (0, 1)}),
            (['/usr/sbin/tune2fs', '-O', 'dir_index', 'image'], {})])
        with self.assertRaises(ValueError):
            unshare(Path('image'), {'/': {'type': 'directory', 'flags': 0x81000}}, lambda *a, **k: None)

    def test_real_ext4_replacement_restores_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'fixture.img'
            original = root / 'original.apex'
            replacement = root / 'replacement.apex'
            original.write_bytes(b'original-apex')
            replacement.write_bytes(b'replacement-apex-bytes')
            with image.open('wb') as stream:
                stream.truncate(8 * 1024**2)
            subprocess.run(['/usr/sbin/mke2fs', '-q', '-F', '-t', 'ext4', str(image)], check=True, capture_output=True)
            script = (f'mkdir /system\nmkdir /system/apex\nwrite {original} {TARGET}\n'
                      f'set_inode_field {TARGET} uid 1000\nset_inode_field {TARGET} gid 1000\n'
                      f'ea_set {TARGET} security.selinux u:object_r:system_file:s0\n')
            subprocess.run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(image)],
                           input=script, capture_output=True, text=True, check=True)
            before = full_inventory(image, root / 'before')
            commands = replacement_commands(before[TARGET], replacement, root)
            result = subprocess.run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(image)],
                                    input='\n'.join(commands) + '\n', capture_output=True, text=True, check=True)
            self.assertNotIn('invalid', result.stderr.lower())
            after = full_inventory(image, root / 'after')
            self.assertEqual(compare(before, after, replacement), {TARGET: ['size', 'sha256']})
            subprocess.run(['/usr/sbin/e2fsck', '-fn', str(image)], check=True, capture_output=True)

    def test_changed_baseline_is_refused_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'before').mkdir()
            (root / 'prepared.json').write_text(json.dumps({'unshared_sha256': 'image-hash',
                                                           'baseline_inventory_sha256': 'baseline-hash'}))
            (root / 'before/inventory.json').write_text('{}')
            with (root / 'system-unshared.img').open('wb') as stream:
                stream.truncate(FS_BYTES)
            for name in ('apex', 'key', 'avbtool'):
                (root / name).write_bytes(b'data')
                (root / name).chmod(0o600)
            hashes = {'apex': 'apex-hash', 'system-unshared.img': 'image-hash', 'inventory.json': 'tampered-hash'}
            output = root / 'output'
            with patch('build_dsu_system.tool_check'), patch('build_dsu_system.sha', side_effect=lambda path: hashes[path.name]):
                with self.assertRaisesRegex(ValueError, 'baseline inventory changed'):
                    finish(root, root / 'apex', 'apex-hash', output, root / 'key', root / 'avbtool')
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
