from pathlib import Path
import argparse,hashlib,importlib.util,tempfile,unittest,sys,zipfile
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('repack',P/'prepare_unsigned_ui.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('patch',P/'patch_dex.py');patch=importlib.util.module_from_spec(spec);spec.loader.exec_module(patch)
p=argparse.ArgumentParser(add_help=False);p.add_argument('--apk',type=Path,required=True);args,other=p.parse_known_args();sys.argv=[sys.argv[0],*other]
class Checks(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory(dir=P);self.d=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def test_unsigned_reproduction(self):
  with zipfile.ZipFile(args.apk) as z:data=z.read('classes2.dex')
  dex=self.d/'classes2.dex';dex.write_bytes(patch.patch(data)[0])
  report=m.build(args.apk,dex,self.d/'SystemUI-unsigned.apk');self.assertEqual(report['unsigned_apk_sha256'],m.EXPECTED)
 def test_wrong_apk_rejected(self):
  wrong=self.d/'wrong.apk';wrong.write_bytes(b'wrong')
  with self.assertRaises(ValueError):m.build(wrong,wrong,self.d/'out.apk')
 def test_wrong_dex_rejected(self):
  wrong=self.d/'wrong.dex';wrong.write_bytes(b'wrong')
  with self.assertRaises(ValueError):m.build(args.apk,wrong,self.d/'out.apk')
if __name__=='__main__':unittest.main(verbosity=2)
