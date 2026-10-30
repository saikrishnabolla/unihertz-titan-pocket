import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_google_cgroup_fix as fix

ORIGINAL = b'''{
  "Cgroups": [
    {
      "Controller": "blkio",
      "Path": "/dev/blkio",
      "Mode": "0775",
      "UID": "system",
      "GID": "system"
    },
    {
      "Controller": "cpu",
      "Path": "/dev/cpuctl",
      "Mode": "0755",
      "UID": "system",
      "GID": "system"
    },
    {
      "Controller": "cpuset",
      "Path": "/dev/cpuset",
      "Mode": "0755",
      "UID": "system",
      "GID": "system"
    }
  ],
  "Cgroups2": {
    "Path": "/sys/fs/cgroup",
    "Mode": "0775",
    "UID": "system",
    "GID": "system",
    "Controllers": [
      {
        "Controller": "freezer",
        "Path": "."
      },
      {
        "Controller": "memory",
        "Path": ".",
        "NeedsActivation": true,
        "Optional": true
      }
    ]
  }
}
'''


class CgroupFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='google-cgroup-test-', )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_production_pins(self):
        self.assertEqual(fix.SOURCE_SHA, '9de56e44a4dcade6386a225f1366bdab29dc814fb85418563d40b0f154c912fa')
        self.assertEqual(fix.CONFIG_SHA, 'c400e39dca40b6250283e11346b4358f0afaaf3a736e288c5157f88a21e608d4')
        self.assertEqual((fix.SOURCE_BYTES, fix.BLOCK, fix.TARGET),
                         (3221225472, 104137, '/system/etc/cgroups.json'))

    def test_exact_one_boolean_change_and_fixed_length(self):
        self.assertEqual(len(ORIGINAL), 771)
        self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(), fix.CONFIG_SHA)
        after = fix.replacement(ORIGINAL)
        expected = json.loads(ORIGINAL)
        expected['Cgroups'][0]['Optional'] = True
        self.assertEqual(json.loads(after), expected)
        self.assertEqual(len(after), 771)
        self.assertIs(json.loads(after)['Cgroups'][0]['Optional'], True)
        self.assertNotIn('Optional', json.loads(after)['Cgroups'][1])
        self.assertNotIn('Optional', json.loads(after)['Cgroups'][2])
        end = ORIGINAL.index(b'    },') + 5
        self.assertEqual(after[end:], ORIGINAL[end:])

    def test_any_source_config_change_refused(self):
        for data in (ORIGINAL+b'\n', ORIGINAL.replace(b'blkio', b'other'),
                     ORIGINAL.replace(b'"GID": "system"', b'"GID": "system", "Optional": false', 1)):
            with self.assertRaisesRegex(ValueError, 'pinned configuration'):
                fix.replacement(data)

    def test_sparse_copy_preserves_every_byte_and_private_mode(self):
        source = self.root/'source'
        data = bytes(4096) + b'a'*4096 + bytes(8192) + b'z'
        source.write_bytes(data)
        target = self.root/'target'
        previous = os.umask(0o002)
        try:
            fix.sparse_copy(source, target)
        finally:
            os.umask(previous)
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            fix.sparse_copy(source, target)

    def test_whole_image_comparison_rejects_unrelated_change(self):
        before = self.root/'before'; after = self.root/'after'
        before.write_bytes(bytes(4096) + ORIGINAL + bytes(4096-771))
        after.write_bytes(bytes(4096) + fix.replacement(ORIGINAL) + bytes(4096-771))
        with patch.object(fix, 'SOURCE_BYTES', 8192), patch.object(fix, 'BLOCK', 1):
            result = fix.compare_all(before, after, ORIGINAL, fix.replacement(ORIGINAL))
            self.assertEqual(result['compared_bytes'], 8192)
            data = bytearray(after.read_bytes()); data[8] = 1; after.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'outside configuration'):
                fix.compare_all(before, after, ORIGINAL, fix.replacement(ORIGINAL))

    def test_comparison_rejects_changed_tail_and_wrong_replacement(self):
        before=self.root/'before'; after=self.root/'after'
        before.write_bytes(ORIGINAL+bytes(4096-771)); data=bytearray(fix.replacement(ORIGINAL)+bytes(4096-771))
        with patch.object(fix, 'SOURCE_BYTES', 4096), patch.object(fix, 'BLOCK', 0):
            data[1000]=1; after.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'outside configuration'):
                fix.compare_all(before, after, ORIGINAL, fix.replacement(ORIGINAL))
            after.write_bytes(before.read_bytes())
            with self.assertRaisesRegex(ValueError, 'replacement'):
                fix.compare_all(before, after, ORIGINAL, fix.replacement(ORIGINAL))

    def fixture(self):
        source=self.root/'source.ext4'
        with source.open('wb') as stream: stream.truncate(4*1024**2)
        subprocess.run(['/usr/sbin/mke2fs','-q','-t','ext4','-b','4096','-F',str(source)],check=True,capture_output=True)
        payload=self.root/'payload'; payload.write_bytes(ORIGINAL)
        subprocess.run(['/usr/sbin/debugfs','-w','-R',f'write {payload} /cgroups.json',str(source)],check=True,capture_output=True)
        block=int(subprocess.check_output(['/usr/sbin/debugfs','-R','bmap /cgroups.json 0',str(source)],stderr=subprocess.DEVNULL))
        return source, block

    def test_real_ext4_changes_only_payload_and_keeps_source(self):
        source, block=self.fixture(); digest=fix.sha(source)
        with patch.object(fix, 'SOURCE_SHA', digest), patch.object(fix, 'SOURCE_BYTES', source.stat().st_size), \
             patch.object(fix, 'BLOCK', block), patch.object(fix, 'TARGET', '/cgroups.json'):
            result=fix.build(source,self.root/'output')
        self.assertEqual(fix.sha(source),digest)
        self.assertEqual(result['delta']['compared_bytes'],source.stat().st_size)
        output=self.root/'output/system.ext4'
        data=subprocess.check_output(['/usr/sbin/debugfs','-R','cat /cgroups.json',str(output)],stderr=subprocess.DEVNULL)
        self.assertEqual(data,fix.replacement(ORIGINAL))
        self.assertEqual(output.stat().st_mode&0o777,0o600)
        self.assertEqual((self.root/'output').stat().st_mode&0o777,0o700)

    def test_wrong_image_refused_before_output(self):
        source=self.root/'source'; source.write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError,'source image'):
            fix.build(source,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_wrong_block_refused_without_source_changes(self):
        source, block=self.fixture(); digest=fix.sha(source)
        with patch.object(fix, 'SOURCE_SHA', digest), patch.object(fix, 'SOURCE_BYTES', source.stat().st_size), \
             patch.object(fix, 'BLOCK', block+1), patch.object(fix, 'TARGET', '/cgroups.json'):
            with self.assertRaisesRegex(ValueError,'block mapping'):
                fix.build(source,self.root/'output')
        self.assertEqual(fix.sha(source),digest)

    def test_source_symlink_refused(self):
        source, _=self.fixture(); link=self.root/'link'; link.symlink_to(source)
        with self.assertRaisesRegex(ValueError,'regular'):
            fix.build(link,self.root/'output')

    def test_filesystem_hardlink_and_multiblock_payload_refused(self):
        for command in ['ln /cgroups.json /alias\nset_inode_field /cgroups.json links_count 2',
                        'set_inode_field /cgroups.json size 5000']:
            source,_=self.fixture()
            subprocess.run(['/usr/sbin/debugfs','-w','-f','/dev/stdin',str(source)],input=command+'\n',
                           text=True,check=True,capture_output=True)
            with patch.object(fix,'SOURCE_SHA',fix.sha(source)), patch.object(fix,'SOURCE_BYTES',source.stat().st_size), \
                 patch.object(fix,'TARGET','/cgroups.json'):
                with self.assertRaises(ValueError):
                    fix.build(source,self.root/('bad-'+str(len(command))))

    def test_copy_source_mutation_caught_before_publication(self):
        source,block=self.fixture(); copying=fix.sparse_copy
        def mutate(a,b):
            copying(a,b)
            with a.open('r+b') as stream:
                stream.seek(3000*1024); value=stream.read(1); stream.seek(3000*1024)
                stream.write(bytes([value[0]^1]))
        with patch.object(fix,'SOURCE_SHA',fix.sha(source)), patch.object(fix,'SOURCE_BYTES',source.stat().st_size), \
             patch.object(fix,'BLOCK',block), patch.object(fix,'TARGET','/cgroups.json'), \
             patch.object(fix,'sparse_copy',side_effect=mutate):
            with self.assertRaisesRegex(ValueError,'outside configuration'):
                fix.build(source,self.root/'mutated')
        self.assertFalse((self.root/'mutated').exists())

    def test_existing_output_and_public_parent_refused(self):
        source,_=self.fixture(); out=self.root/'exists'; out.mkdir()
        with patch.object(fix,'SOURCE_SHA',fix.sha(source)), patch.object(fix,'SOURCE_BYTES',source.stat().st_size):
            with self.assertRaisesRegex(ValueError,'must not exist'):
                fix.build(source,out)
            parent=self.root/'public'; parent.mkdir(mode=0o755); parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'private'):
                fix.build(source,parent/'output')

    def test_fsck_failure_keeps_output_unpublished(self):
        source,_=self.fixture(); actual=fix.subprocess.run
        def failed(args,**kwargs):
            if args[0]=='/usr/sbin/e2fsck':
                return subprocess.CompletedProcess(args,4,'fixture fsck failure','')
            return actual(args,**kwargs)
        with patch.object(fix,'SOURCE_SHA',fix.sha(source)), patch.object(fix,'SOURCE_BYTES',source.stat().st_size), \
             patch.object(fix.subprocess,'run',side_effect=failed):
            with self.assertRaisesRegex(ValueError,'tool failed'):
                fix.build(source,self.root/'not-published')
        self.assertFalse((self.root/'not-published').exists())
