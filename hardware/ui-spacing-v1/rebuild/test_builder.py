from pathlib import Path
import copy,hashlib,importlib.util,json,sys,unittest
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('builder',P/'build_system.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
sys.path.insert(0,str(P/'helpers'));import image_helpers as h
class Checks(unittest.TestCase):
 def setUp(self):
  self.before=json.loads((P/'test-baseline.json').read_text());self.after=copy.deepcopy(self.before)
  for path in b.REMOVED:self.after.pop(path)
  self.after[b.SYS].update(content_sha256=b.SYS_SHA,size=b.SYS_SIZE,allocated_512_blocks=85064)
  self.after[b.TARGET]=copy.deepcopy(self.before[b.FINGERPRINT]);self.after[b.TARGET].update(inode=4047,content_sha256=b.APK,size=b.APK_SIZE)
 def test_exact_scope(self):b.compare(self.before,self.after)
 def test_reuse_second_removed_inode(self):self.after[b.TARGET]['inode']=4048;b.compare(self.before,self.after)
 def test_use_previously_free_inode(self):self.after[b.TARGET]['inode']=4409;b.compare(self.before,self.after)
 def test_retained_inode_reuse_rejected(self):
  for inode in (4044,4406,4407,4408,659):
   self.after[b.TARGET]['inode']=inode
   with self.subTest(inode=inode),self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_added_paths_rejected(self):
  self.after['/system/extra']=copy.deepcopy(self.after[b.TARGET])
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_each_other_deletion_rejected(self):
  for path in self.after.keys()-{b.TARGET}:
   after=copy.deepcopy(self.after);after.pop(path)
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_each_required_removal_mandatory(self):
  for path in b.REMOVED:
   after=copy.deepcopy(self.after);after[path]=self.before[path]
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_every_retained_metadata_field_unchanged(self):
  for path in self.after.keys()-{b.TARGET}:
   for field in self.after[path]:
    if path==b.SYS and field in ('size','content_sha256','allocated_512_blocks'):continue
    after=copy.deepcopy(self.after);after[path][field]='changed'
    with self.subTest(path=path,field=field),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_wrong_systemui_bytes_rejected(self):
  for field in ('content_sha256','size'):
   after=copy.deepcopy(self.after);after[b.SYS][field]='wrong'
   with self.subTest(field=field),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_overlay_metadata_rejected(self):
  for field in ('type','permissions','uid','gid','size','links','symlink_target','content_sha256','xattrs','timestamps_debugfs'):
   after=copy.deepcopy(self.after);after[b.TARGET][field]=[] if field in ('xattrs','timestamps_debugfs') else 'wrong'
   with self.subTest(field=field),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_wrong_overlay_epoch_rejected(self):
  self.after[b.TARGET]['timestamps_debugfs'][0]=self.after[b.TARGET]['timestamps_debugfs'][0].replace('495c0780','495c0781')
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_baseline_already_has_overlay_rejected(self):
  self.before[b.TARGET]=copy.deepcopy(self.after[b.TARGET])
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_wrong_baseline_old_payloads_rejected(self):
  for path in [*b.PINS,b.SYS,*b.REMOVED]:
   before=copy.deepcopy(self.before);before[path]['content_sha256']='0'*64
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(before,self.after)
 def test_exact_raw_inodes_with_reused(self):
  old={i:b'a' for i in (4044,4047,4048,4409)};new={i:(b'a' if i==4409 else b'b') for i in old}
  self.assertEqual(b.check_inode_diff(old,new,4047),[4044,4047,4048])
 def test_exact_raw_inodes_with_new(self):
  old={i:b'a' for i in (4044,4047,4048,4409)};new={i:b'b' for i in old}
  self.assertEqual(b.check_inode_diff(old,new,4409),list(old))
 def test_extra_or_missing_raw_inode_changes_rejected(self):
  old={i:b'a' for i in (4044,4047,4048,4409)}
  for touched in [(4044,4047),(4044,4047,4048,4409),()]:
   new={i:(b'b' if i in touched else b'a') for i in old}
   with self.subTest(touched=touched),self.assertRaises(AssertionError):b.check_inode_diff(old,new,4047)
 def test_only_exact_oat_tombstones_accepted(self):
  live='/4046/040755/0/0/./4096/\n/4045/040755/0/0/../4096/'
  txt=live+'\n/0/000000/0/0/SystemUI.odex/0/\n/0/000000/0/0/SystemUI.vdex/0/'
  self.assertEqual(b.listing_with_removed_oat_slots(h.parse_directory_listing,b.OAT_PARENT,txt),[])
  for path,line in [(b.OAT_PARENT,'/0/000000/0/0/Other.odex/0/'),('/system/other','/0/000000/0/0/SystemUI.odex/0/')]:
   with self.subTest(path=path),self.assertRaises(ValueError):b.listing_with_removed_oat_slots(h.parse_directory_listing,path,live+'\n'+line)
 def test_output_pin_modes(self):
  b.output_pin_mode(True,None);b.output_pin_mode(False,'a'*64)
  for derive,pin in [(False,None),(True,'a'*64),(False,'A'*64),(False,'0'*63)]:
   with self.subTest(derive=derive,pin=pin),self.assertRaises(ValueError):b.output_pin_mode(derive,pin)
 def test_bundle_and_asset_pins(self):
  b.verify_bundle();self.assertEqual(b.sha(P/'assets/SystemUI.apk'),b.SYS_SHA);self.assertEqual(b.sha(P/'assets/TitanPocketLauncherSpacing.apk'),b.APK)
 def test_reused_helper_and_tool_sources_exact(self):
  upstream=json.loads((P/'upstream-source-manifest.json').read_text())
  for entry in upstream['bundle_files']:
   if entry['path'].startswith(('helpers/','tools/')):
    with self.subTest(path=entry['path']):self.assertEqual(b.sha(P/entry['path']),entry['sha256'])
if __name__=='__main__':unittest.main(verbosity=2)
