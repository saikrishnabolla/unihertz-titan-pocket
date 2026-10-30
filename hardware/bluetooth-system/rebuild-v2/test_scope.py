from copy import deepcopy
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
sys.dont_write_bytecode=True
p=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('builder',p/'build_system.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
r=p/'test-inputs'
for name,pin in json.loads((r/'manifest.json').read_text()).items():assert hashlib.sha256((r/name).read_bytes()).hexdigest()==pin
BEFORE=json.loads((r/'source-tree.json').read_text());AFTER=json.loads((r/'candidate-tree-final.json').read_text())
class Scope(unittest.TestCase):
 def test_existing_reference_scope(self):b.compare(BEFORE,AFTER)
 def test_unrelated_change_rejected(self):
  j=deepcopy(AFTER);j['/system/build.prop']['content_sha256']='0'*64
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
 def test_addition_rejected(self):
  j=deepcopy(AFTER);j['/extra']=deepcopy(j[b.NEW])
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
 def test_extra_removal_rejected(self):
  j=deepcopy(AFTER);del j['/system/build.prop']
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
 def test_lost_label_rejected(self):
  j=deepcopy(AFTER);j[b.NEW]['xattrs']=[]
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
 def test_wrong_apex_rejected(self):
  j=deepcopy(AFTER);j[b.NEW]['content_sha256']='0'*64
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
 def test_changed_apex_directory_metadata_rejected(self):
  j=deepcopy(AFTER);j['/system/apex']['permissions']='0777'
  with self.assertRaises(AssertionError):b.compare(BEFORE,j)
if __name__=='__main__':unittest.main()
