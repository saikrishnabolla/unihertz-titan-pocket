from pathlib import Path
import copy,hashlib,importlib.util,json,tempfile,unittest
P=Path(__file__).parent;s=importlib.util.spec_from_file_location('builder',P/'build_system.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class Tests(unittest.TestCase):
 def test_append(self):
  raw=b'a=b\n';out=b.patch_properties(raw);self.assertEqual(out,raw+b'qemu.hw.mainkeys=1\n');self.assertEqual(b.patch_properties(out),out)
 def test_missing_newline(self):self.assertEqual(b.patch_properties(b'a=b'),b'a=b\nqemu.hw.mainkeys=1\n')
 def test_untouched_existing(self):self.assertEqual(b.patch_properties(b'qemu.hw.mainkeys=1\n'),b'qemu.hw.mainkeys=1\n')
 def test_conflicts(self):
  for val in ('0','true','false','1 # nope',''):
   with self.assertRaises(ValueError):b.patch_properties(('qemu.hw.mainkeys='+val+'\n').encode())
 def test_duplicates(self):
  for val in ('1','0'):
   with self.assertRaises(ValueError):b.patch_properties(('qemu.hw.mainkeys=1\nqemu.hw.mainkeys='+val+'\n').encode())
 def test_comments(self):self.assertEqual(b.patch_properties(b'# qemu.hw.mainkeys=0\n'),b'# qemu.hw.mainkeys=0\nqemu.hw.mainkeys=1\n')
 def test_actual_properties(self):
  raw=(P/'base-build.prop').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),b.OLD_PROP_SHA);self.assertEqual(b.patch_properties(raw),raw+b'qemu.hw.mainkeys=1\n')
 def test_archive_pin(self):
  b.validate_zip(P/'bootanimation-titan-square-v1.zip')
  with tempfile.NamedTemporaryFile() as f:
   f.write(b'bad');f.flush()
   with self.assertRaises(AssertionError):b.validate_zip(Path(f.name))
 def test_bundle(self):b.verify_bundle()
 def test_source_pin_rejects_mutation(self):
  with tempfile.TemporaryDirectory() as d:
   q=Path(d);(q/'file.py').write_text('changed');(q/'source-manifest.json').write_text(json.dumps({'bundle_files':[{'path':'file.py','sha256':'0'*64}]}));old=b.P;b.P=q
   try:
    with self.assertRaises(AssertionError):b.verify_bundle()
   finally:b.P=old
 def test_scope(self):
  before=json.loads((P/'test-source-tree.json').read_text());raw=(P/'base-build.prop').read_bytes();new=b.patch_properties(raw);after=copy.deepcopy(before)
  after[b.PROP].update(size=len(new),content_sha256=hashlib.sha256(new).hexdigest());after[b.ANIM].update(size=b.ZIP_BYTES,content_sha256=b.ZIP,allocated_512_blocks=99999)
  b.compare(before,after,raw,new)
  mutations=[lambda d:d[b.OVERLAY].update(content_sha256='bad'),lambda d:d[b.JAR].update(content_sha256='bad'),lambda d:d[b.APEX].update(content_sha256='bad'),lambda d:d[b.MEDIA].update(uid=5),lambda d:d[b.PROP].update(permissions='0644'),lambda d:d[b.PROP].update(inode=660),lambda d:d[b.ANIM].update(content_sha256='bad'),lambda d:d[b.ANIM].update(inode=4408),lambda d:d[b.ANIM].update(permissions='0755'),lambda d:d[b.ANIM].update(xattrs=[]),lambda d:d.update({'/extra':{}}),lambda d:d.pop(b.OVERLAY)]
  for mutation in mutations:
   modified=copy.deepcopy(after);mutation(modified)
   with self.assertRaises((AssertionError,KeyError)):b.compare(before,modified,raw,new)
if __name__=='__main__':unittest.main()
