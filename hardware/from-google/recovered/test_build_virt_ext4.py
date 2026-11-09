import hashlib
from pathlib import Path
import tempfile
import unittest

import build_virt_ext4 as convert
from compare_vendor_trees import inventory


class Ext4ConversionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='virt-convert-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.tree=self.root/'tree';self.tree.mkdir(mode=0o755);self.tree.chmod(0o755)
        (self.tree/'file').write_bytes(b'preserved payload\n')
        (self.tree/'file').chmod(0o640)
        (self.tree/'link').symlink_to('file')
        self.metadata={
            '/':{'nid':1,'mode':0o40755,'uid':1000,'gid':1000,'nlink':2,'size':0,'mtime_ns':0,
                 'xattrs':{'security.selinux':b'u:object_r:system_file:s0\0'.hex()}},
            '/file':{'nid':2,'mode':0o100640,'uid':123,'gid':456,'nlink':1,'size':18,'mtime_ns':0,
                     'xattrs':{'security.selinux':b'u:object_r:system_file:s0\0'.hex(),
                               'security.capability':'0100000200008000000000000000000000000000'}},
            '/link':{'nid':3,'mode':0o120777,'uid':0,'gid':0,'nlink':1,'size':4,'mtime_ns':0,
                     'target':'file','xattrs':{}}
        }

    def test_real_ext4_preserves_content_owners_modes_links_and_security_xattrs(self):
        result=convert.make_ext4(self.tree,self.metadata,self.root/'converted')
        actual=inventory(Path(result['image']),self.root/'readback')
        self.assertEqual(set(actual),{'/','/file','/link'})
        self.assertEqual(actual['/file']['sha256'],hashlib.sha256(b'preserved payload\n').hexdigest())
        self.assertEqual((actual['/file']['uid'],actual['/file']['gid']),(123,456))
        self.assertEqual(actual['/file']['permissions'],'0640')
        self.assertEqual(actual['/file']['xattrs'],self.metadata['/file']['xattrs'])
        self.assertEqual(actual['/']['xattrs'],self.metadata['/']['xattrs'])
        self.assertEqual(actual['/link']['symlink_target'],'file')
        self.assertTrue(result['all_content_and_metadata_verified'])

    def test_existing_output_is_not_overwritten(self):
        out=self.root/'existing';out.mkdir();(out/'keep').write_text('keep')
        with self.assertRaisesRegex(ValueError,'must not exist'):
            convert.make_ext4(self.tree,self.metadata,out)
        self.assertEqual((out/'keep').read_text(),'keep')

    def test_source_output_overlap_refused(self):
        with self.assertRaisesRegex(ValueError,'overlaps'):
            convert.make_ext4(self.tree,self.metadata,self.tree/'converted')
        self.assertFalse((self.tree/'converted').exists())

    def test_wrong_path_set_mode_size_timestamp_and_symlink_refused_before_output(self):
        import copy
        for field,value in [('mode',0o100600),('size',19),('mtime_ns',1)]:
            metadata=copy.deepcopy(self.metadata);metadata['/file'][field]=value
            with self.assertRaises(ValueError):
                convert.make_ext4(self.tree,metadata,self.root/'not-created')
            self.assertFalse((self.root/'not-created').exists())
        metadata=copy.deepcopy(self.metadata);metadata['/link']['target']='elsewhere'
        with self.assertRaisesRegex(ValueError,'symlink'):
            convert.make_ext4(self.tree,metadata,self.root/'not-created')
        metadata=copy.deepcopy(self.metadata);metadata.pop('/link')
        with self.assertRaisesRegex(ValueError,'path set'):
            convert.make_ext4(self.tree,metadata,self.root/'not-created')

    def test_preserves_real_hardlink_groups(self):
        (self.tree/'alias').hardlink_to(self.tree/'file')
        self.metadata['/file']['nlink']=2
        self.metadata['/alias']=dict(self.metadata['/file'])
        result=convert.make_ext4(self.tree,self.metadata,self.root/'hardlinked')
        actual=inventory(Path(result['image']),self.root/'hardlink-readback')
        self.assertEqual(actual['/file']['same_inode_paths'],['/alias','/file'])
        self.assertEqual(actual['/alias']['links'],2)

    def test_lost_hardlink_identity_refused(self):
        (self.tree/'alias').write_bytes(b'preserved payload\n')
        (self.tree/'alias').chmod(0o640)
        self.metadata['/file']['nlink']=2
        self.metadata['/alias']=dict(self.metadata['/file'])
        with self.assertRaisesRegex(ValueError,'hardlink identity'):
            convert.make_ext4(self.tree,self.metadata,self.root/'not-created')

    def test_symlink_mode_comes_from_image_not_host_symlink_permissions(self):
        self.metadata['/link']['mode']=0o120644
        result=convert.make_ext4(self.tree,self.metadata,self.root/'symlink-mode')
        actual=inventory(Path(result['image']),self.root/'symlink-mode-readback')
        self.assertEqual(actual['/link']['permissions'],'0644')
        self.assertEqual(actual['/link']['symlink_target'],'file')
