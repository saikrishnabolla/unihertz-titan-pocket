"""Independently verify exact DEX delta, smali equivalence and input rejection."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,unittest,zlib,tempfile,subprocess,sys,zipfile
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('patch',P/'patch_dex.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
REL=Path('com/android/systemui/shade/ui/composable/ShadeSceneKt$$ExternalSyntheticLambda20.smali')
parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--apk',type=Path,required=True);parser.add_argument('--tools',type=Path,required=True);parser.add_argument('--java',type=Path,required=True)
args,remaining=parser.parse_known_args();sys.argv=[sys.argv[0],*remaining]
TOOLS={'java':args.java,'DexTool.java':args.tools/'DexTool.java','jadx-1.5.3-all.jar':args.tools/'jadx-1.5.3-all.jar'}
class Checks(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  assert hashlib.sha256(args.apk.read_bytes()).hexdigest()==m.APK_SHA
  for name,pin in json.loads((P/'tool-pins.json').read_text()).items():assert hashlib.sha256(TOOLS[name].read_bytes()).hexdigest()==pin
  cls.temp=tempfile.TemporaryDirectory(dir=P);cls.work=Path(cls.temp.name)
  with zipfile.ZipFile(args.apk) as z:cls.old=z.read('classes2.dex');helper=z.read('classes.dex')
  cls.new=m.patch(cls.old)[0]
  (cls.work/'new.dex').write_bytes(cls.new);(cls.work/'helper.dex').write_bytes(helper)
  def dex(*values):
   cmd=[str(args.java),'-Xmx512m','-XX:ActiveProcessorCount=2','--class-path',str(TOOLS['jadx-1.5.3-all.jar']),str(TOOLS['DexTool.java']),*map(str,values)]
   subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=60)
  dex('assemble',P/'patched-smali',cls.work/'assembled.dex')
  dex('disassemble',cls.work/'new.dex',cls.work/'raw-patched-readback',m.CLASS)
  dex('disassemble',cls.work/'assembled.dex',cls.work/'assembled-readback',m.CLASS)
  dex('disassemble',cls.work/'helper.dex',cls.work/'layout-helper-smali','Landroidx/compose/foundation/layout/PaddingKt;')
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_exact_reproduction(self):self.assertEqual(m.patch(self.old)[0],self.new)
 def test_candidate_pin(self):self.assertEqual(hashlib.sha256(self.new).hexdigest(),'564b1309510143a442cecfbfc4b5952e804bbdfdeb9fa8d4ca674f653683cb93')
 def test_exact_delta(self):
  delta=[i for i,(a,b) in enumerate(zip(self.old,self.new)) if a!=b]
  self.assertEqual(len(self.old),len(self.new));self.assertEqual([i for i in delta if not 8<=i<32],[4742510,4742520,4742523])
 def test_header_integrity(self):
  self.assertEqual(self.new[12:32],hashlib.sha1(self.new[32:]).digest())
  self.assertEqual(struct.unpack_from('<I',self.new,8)[0],zlib.adler32(self.new[12:])&0xffffffff)
 def test_wrong_inputs_rejected(self):
  bad=[b'',self.old[:-1],self.old+b'\0',self.new,self.old[:388]+b'bad'+self.old[391:]]
  for n,data in enumerate(bad):
   with self.subTest(n=n),self.assertRaises(ValueError):m.patch(data)
 def test_only_two_smali_lines_change(self):
  old=(P/'original-smali'/REL).read_text();new=(P/'patched-smali'/REL).read_text()
  expected=old.replace('    const/16 v20, 0x7','    const/16 v20, 0x5').replace('    const/16 v17, 0x0','    const/high16 v17, 0x41000000    # 8.0f')
  self.assertEqual(new,expected)
  self.assertEqual(old.count('v17'),1);self.assertEqual(old.count('v20'),1)
 def test_raw_dex_disassembly_exact(self):self.assertEqual((self.work/'raw-patched-readback'/REL).read_bytes(),(P/'patched-smali'/REL).read_bytes())
 def test_independent_assembler_readback_exact(self):self.assertEqual((self.work/'assembled-readback'/REL).read_bytes(),(P/'patched-smali'/REL).read_bytes())
 def test_actual_padding_helper_top_default_bit(self):
  helper=(self.work/'layout-helper-smali/androidx/compose/foundation/layout/PaddingKt.smali').read_text()
  self.assertEqual(helper,(P/'layout-helper-smali/androidx/compose/foundation/layout/PaddingKt.smali').read_text())
  block=helper.split('.method public static synthetic padding-qDBjuR0$default',1)[1].split('.end method',1)[0]
  self.assertIn('and-int/lit8 p6, p5, 0x2',block);self.assertIn('move-result p2',block)
  self.assertIn('invoke-static {p0, p1, p2, p3, p4}',block)
 def test_all_recorded_tool_input_pins(self):
  for name,pin in json.loads((P/'tool-pins.json').read_text()).items():
   with self.subTest(tool=name):self.assertEqual(hashlib.sha256(TOOLS[name].read_bytes()).hexdigest(),pin)
  self.assertEqual(hashlib.sha256(args.apk.read_bytes()).hexdigest(),m.APK_SHA)
if __name__=='__main__':unittest.main(verbosity=2)
