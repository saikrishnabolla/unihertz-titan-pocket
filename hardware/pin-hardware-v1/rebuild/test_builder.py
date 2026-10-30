from pathlib import Path
import copy,hashlib,importlib.util,json,sys,unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('builder',P/'build_system.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
sys.path.insert(0,str(P/'helpers'));import image_helpers as h
class Checks(unittest.TestCase):
 def setUp(self):
  self.pins=patch.multiple(b,SYS_SHA='1'*64,SYS_SIZE=44000000);self.pins.start();self.addCleanup(self.pins.stop)
  self.before=json.loads((P/'test-baseline.json').read_text());self.after=copy.deepcopy(self.before)
  self.after[b.SYS].update(content_sha256=b.SYS_SHA,size=b.SYS_SIZE,allocated_512_blocks=86000)
 def test_exact_scope(self):b.compare(self.before,self.after)
 def test_added_path_rejected(self):
  self.after['/system/extra']=copy.deepcopy(self.after[b.SYS])
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_each_deletion_rejected(self):
  for path in self.after:
   after=copy.deepcopy(self.after);after.pop(path)
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_every_retained_metadata_field_unchanged(self):
  for path in self.after:
   for field in self.after[path]:
    if path==b.SYS and field in ('size','content_sha256','allocated_512_blocks'):continue
    after=copy.deepcopy(self.after);after[path][field]='changed'
    with self.subTest(path=path,field=field),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_wrong_systemui_payload_rejected(self):
  for field in ('content_sha256','size'):
   after=copy.deepcopy(self.after);after[b.SYS][field]='wrong'
   with self.subTest(field=field),self.assertRaises(AssertionError):b.compare(self.before,after)
 def test_wrong_systemui_inode_rejected(self):
  self.after[b.SYS]['inode']=4047
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_wrong_old_payloads_rejected(self):
  for path in [*b.PINS,b.SYS]:
   before=copy.deepcopy(self.before);before[path]['content_sha256']='0'*64
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(before,self.after)
 def test_old_systemui_size_rejected(self):
  self.before[b.SYS]['size']+=1
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_old_systemui_inode_rejected(self):
  self.before[b.SYS]['inode']=4045
  with self.assertRaises(AssertionError):b.compare(self.before,self.after)
 def test_oat_must_remain_absent(self):
  for path in b.ABSENT_OAT:
   before=copy.deepcopy(self.before);before[path]=copy.deepcopy(before[b.SYS])
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(before,self.after)
 def test_parents_are_directories(self):
  for path in (b.PARENT,b.SYS_PARENT,b.OAT_PARENT):
   before=copy.deepcopy(self.before);before[path]['type']='regular'
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(before,self.after)
 def test_retained_anchor_inodes(self):
  for path in ('/system/build.prop','/system/product/media/bootanimation.zip'):
   before=copy.deepcopy(self.before);before[path]['inode']+=1
   with self.subTest(path=path),self.assertRaises(AssertionError):b.compare(before,self.after)
 def test_exact_raw_inode(self):
  old={i:b'a' for i in (4044,4047,4048)};new={i:(b'b' if i==4044 else b'a') for i in old}
  self.assertEqual(b.check_inode_diff(old,new),[4044])
 def test_extra_missing_raw_changes_rejected(self):
  old={i:b'a' for i in (4044,4047,4048)}
  for touched in ((),(4047,),(4044,4047),(4044,4048)):
   new={i:(b'b' if i in touched else b'a') for i in old}
   with self.subTest(touched=touched),self.assertRaises(AssertionError):b.check_inode_diff(old,new)
 def test_raw_inode_set_change_rejected(self):
  with self.assertRaises(AssertionError):b.check_inode_diff({4044:b'a'},{4044:b'b',4047:b'a'})
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
 def test_unsigned_or_pending_asset_pin_rejected(self):
  for digest,size in ((None,None),('PENDING',44000000),('a'*64,0),('a'*63,44000000)):
   with patch.multiple(b,SYS_SHA=digest,SYS_SIZE=size),self.subTest(digest=digest),self.assertRaises(ValueError):b.validate_candidate_pin()
 def test_bundle_pins(self):b.verify_bundle()
 def test_neutral_helpers_exact(self):
  upstream=json.loads((P/'upstream-source-manifest.json').read_text())
  for e in upstream['bundle_files']:
   if e['path'].startswith(('helpers/','tools/')):
    with self.subTest(path=e['path']):self.assertEqual(b.sha(P/e['path']),e['sha256'])
if __name__=='__main__':unittest.main(verbosity=2)
