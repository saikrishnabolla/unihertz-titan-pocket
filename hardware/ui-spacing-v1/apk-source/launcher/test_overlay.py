from pathlib import Path
import argparse,hashlib,importlib.util,tempfile,unittest,sys,xml.etree.ElementTree as ET
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('builder',P/'build_overlay.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
parser=argparse.ArgumentParser(add_help=False)
for name in ('aapt2','framework-res','launcher-apk','idmap-library'):parser.add_argument('--'+name,type=Path,required=True)
args,remaining=parser.parse_known_args();sys.argv=[sys.argv[0],*remaining]
INPUTS={name:vars(args)[name.replace('-','_')].resolve() for name in ('aapt2','framework-res','launcher-apk','idmap-library')}
class Checks(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(dir=P);cls.compiled=Path(cls.temp.name)/'compiled';m.build(cls.compiled,INPUTS)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()

 def test_exact_sources(self):m.validate_sources(m.MANIFEST,m.RESOURCES)
 def test_manifest_changes_rejected(self):
  edits=[('com.android.launcher3','android'),('37','36'),('false','true'),('true','false'),('500','501'),('Titan_pocket','other'),('ro.product.vendor.device','ro.product.device'),('org.titanpocket.overlay.launcherspacing','org.other'),('<application','<uses-permission android:name="x" /><application'),('<overlay','<overlay android:targetName="Other"')]
  for a,b in edits:
   with self.subTest(edit=a),self.assertRaises(AssertionError):m.validate_sources(m.MANIFEST.replace(a,b),m.RESOURCES)
 def test_resource_changes_rejected(self):
  for a,b in [('39dp','30dp'),('39dp','40dp'),('dimen','integer'),('all_apps_search_bar_bottom_padding','config_showNavigationBar'),('</resources>','<dimen name="extra">1dp</dimen></resources>')]:
   with self.subTest(edit=a),self.assertRaises(AssertionError):m.validate_sources(m.MANIFEST,m.RESOURCES.replace(a,b))
 def test_compiled_scope(self):
  m.validate_readback((self.compiled/'manifest-readback.txt').read_text(),(self.compiled/'resources-readback.txt').read_text())
 def test_readback_changes_rejected(self):
  x=(self.compiled/'manifest-readback.txt').read_text();r=(self.compiled/'resources-readback.txt').read_text()
  for a,b in [('39.000000dp','40.000000dp'),('dimen/all_apps_search_bar_bottom_padding','bool/extra'),('resource 0x','extra 0x')]:
   with self.subTest(edit=a),self.assertRaises(AssertionError):m.validate_readback(x,r.replace(a,b))
  for a,b in [('hasCode(0x0101000c)=false','hasCode(0x0101000c)=true'),('"com.android.launcher3"','"android"'),('"Titan_pocket"','"other"')]:
   with self.subTest(edit=a),self.assertRaises(AssertionError):m.validate_readback(x.replace(a,b),r)
 def test_existing_output_rejected(self):
  with self.assertRaises(ValueError):m.build(self.compiled,INPUTS)
 def test_symlink_output_rejected(self):
  with tempfile.TemporaryDirectory(dir=P) as d:
   out=Path(d)/'link';out.symlink_to(Path(d)/'absent')
   with self.assertRaises(ValueError):m.build(out,INPUTS)
 def test_public_inputs(self):m.verify_inputs(INPUTS)
 def test_default_idmap_policy_present(self):
  source=(P/'sources/ResourceMapping.cpp').read_text()
  self.assertIn('PolicyFlags::PRODUCT_PARTITION',source)
  self.assertIn('if (!*defines_overlayable)',source)
  self.assertIn('(kDefaultPolicies & fulfilled_policies) != 0',source)
  binary=INPUTS['idmap-library'].read_bytes()
  self.assertIn(b'overlay must be preinstalled',binary)
 def test_reproduces_exact_unsigned_apk(self):
  with tempfile.TemporaryDirectory(dir=P) as d:
   report=m.build(Path(d)/'output',INPUTS)
   self.assertEqual(report['apk_sha256'],'b78c1f325a44b16f2aec3a830eca152a62f0c54c9589f17b1a92df8d260b92b2')
if __name__=='__main__':unittest.main(verbosity=2)
