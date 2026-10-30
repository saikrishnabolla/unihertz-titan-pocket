from pathlib import Path
import copy,hashlib,importlib.util,json,tempfile,unittest
P=Path(__file__).parent;s=importlib.util.spec_from_file_location('builder',P/'build_system.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class Tests(unittest.TestCase):
 def test_append(self):
  raw=b'a=b\n';out=b.patch_properties(raw);self.assertEqual(out,raw+b''.join((k+'=true\n').encode() for k in b.PROPERTIES));self.assertEqual(b.patch_properties(out),out)
 def test_missing_newline(self):self.assertTrue(b.patch_properties(b'a=b').startswith(b'a=b\n'))
 def test_true_existing(self):
  raw=(b.PROPERTIES[0]+'=true\n').encode();self.assertEqual(b.patch_properties(raw),raw+(b.PROPERTIES[1]+'=true\n').encode())
 def test_conflict(self):
  for val in ('false','1','TRUE','true # nope',''):
   with self.assertRaises(ValueError):b.patch_properties((b.PROPERTIES[0]+'='+val+'\n').encode())
 def test_duplicate(self):
  for val in ('true','false'):
   with self.assertRaises(ValueError):b.patch_properties((b.PROPERTIES[0]+'=true\n'+b.PROPERTIES[0]+'='+val+'\n').encode())
 def test_comments_untouched(self):self.assertTrue(b.patch_properties(('# '+b.PROPERTIES[0]+'=false\n').encode()).startswith(b'# '))
 def test_archive_pin(self):
  b.validate_zip(P/'bootanimation.zip')
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
  raw=b'a=b\n';new=b.patch_properties(raw);meta={'inode':659,'type':'regular','permissions':'0600','uid':0,'gid':0,'links':1,'xattrs':['label'],'timestamps_debugfs':['same'],'allocated_512_blocks':16,'size':len(raw),'content_sha256':hashlib.sha256(raw).hexdigest()}
  before={b.PROP:meta,b.MEDIA:{'inode':3593,'type':'directory'},b.OVERLAY_PARENT:{'inode':3818,'type':'directory'},b.JAR:{'inode':1234,'content_sha256':b.JARSHA},b.APEX:{'inode':59,'content_sha256':b.APEXSHA},'/keep':{'inode':80,'content_sha256':'same'}}
  after=copy.deepcopy(before);after[b.PROP].update(size=len(new),content_sha256=hashlib.sha256(new).hexdigest());after[b.ANIM]={'inode':1272,'type':'regular','permissions':'0644','uid':0,'gid':0,'links':1,'xattrs':['label'],'timestamps_debugfs':['same'],'size':4251610,'content_sha256':b.ZIP}
  b.compare(before,after,raw,new)
  fp={'sha256':'f'*64,'size':8339};with_fp=copy.deepcopy(after);with_fp[b.OVERLAY]=copy.deepcopy(with_fp[b.ANIM]);with_fp[b.OVERLAY].update(inode=1273,size=8339,content_sha256=fp['sha256']);b.compare(before,with_fp,raw,new,fp)
  for field,value in [('inode',1272),('content_sha256','bad'),('size',8340),('permissions','0755')]:
   broken=copy.deepcopy(with_fp);broken[b.OVERLAY][field]=value
   with self.assertRaises(AssertionError):b.compare(before,broken,raw,new,fp)
  mutations=[lambda d:d['/keep'].update(content_sha256='bad'),lambda d:d[b.JAR].update(content_sha256='bad'),lambda d:d[b.APEX].update(content_sha256='bad'),lambda d:d[b.MEDIA].update(uid=5),lambda d:d[b.PROP].update(permissions='0644'),lambda d:d[b.PROP].update(inode=660),lambda d:d[b.ANIM].update(content_sha256='bad'),lambda d:d[b.ANIM].update(inode=659),lambda d:d.update({'/extra':{}}),lambda d:d.pop('/keep')]
  for mutation in mutations:
   modified=copy.deepcopy(after);mutation(modified)
   with self.assertRaises((AssertionError,KeyError)):b.compare(before,modified,raw,new)
if __name__=='__main__':unittest.main()
