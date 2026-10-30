from pathlib import Path
from transform_adapter import transform
import argparse,copy,hashlib,json,os,subprocess,sys,zipfile
P=Path(__file__).resolve().parent
TARGET='Lcom/android/systemui/bouncer/ui/composable/BouncerContentKt$BouncerContentLayout$3$1;'
BASE='73bd53387659f11e981420d2c2b7e709778871819628959fc930785f0683bc77'
DEX='388586d9ab57472714e81e532723ecef296ca25a6cd6d36b7dc07fdbed169d4c'
APK='b20b058f955319ea909d3799c024fa3dd6261d62454bb633e0ed61abca969bf3'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser()
 for n in ('apk','tools','java','output'):parser.add_argument('--'+n,type=Path,required=True)
 a=parser.parse_args();a.apk=a.apk.resolve();a.tools=a.tools.resolve();out=a.output.resolve()
 if sha(a.apk)!=BASE:raise ValueError('Wrong current SystemUI APK')
 for n,pin in {'jadx-1.5.3-all.jar':'05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3','DexTool.java':'c729e81b0352823b07aa3ee48da89d899b5e653f4a7e878d202fd7545845aef8'}.items():
  if sha(a.tools/n)!=pin:raise ValueError('Wrong tool '+n)
 if out.exists() or a.output.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 if a.apk.is_relative_to(out) or a.tools.is_relative_to(out):raise ValueError('Inputs inside output')
 out.mkdir(mode=0o700)
 j=[str(a.java),'-Xmx512m','-XX:ActiveProcessorCount=2','--class-path',str(a.tools/'jadx-1.5.3-all.jar')]
 def call(args,**kw):subprocess.run(list(map(str,args)),check=True,timeout=180,**kw)
 dex=out/'classes.dex'
 with zipfile.ZipFile(a.apk) as z:dex.write_bytes(z.read('classes.dex'))
 call(j+[a.tools/'DexTool.java','disassemble',dex,out/'source-smali',TARGET])
 source=out/'source-smali'/Path(TARGET[1:-1]+'.smali')
 if sha(source)!='8436b30f9bd88d424d825ebb7baf6ec8254dfc0dfba103e61c1d8f8b86426b06':raise ValueError('Unexpected original adapter')
 patch=out/'patch-smali'/Path(TARGET[1:-1]+'.smali')
 patch.parent.mkdir(parents=True)
 transform(source,patch)
 call(j+[a.tools/'DexTool.java','assemble',out/'patch-smali',out/'patch.dex'])
 call(j+[a.tools/'DexTool.java','merge',dex,out/'patch.dex',out/'classes-patched.dex'])
 if sha(out/'classes-patched.dex')!=DEX:raise ValueError('Unexpected candidate DEX')
 call(j+[P/'CompareDex.java',dex,out/'classes-patched.dex',out/'readback.smali'])
 call([sys.executable,P/'test_adapter.py'],env={**os.environ,'TITAN_PIN_TEST_SMALI':str(out/'readback.smali')})
 unsigned=out/'SystemUI-pin-unsigned.apk'
 with zipfile.ZipFile(a.apk) as z:
  with zipfile.ZipFile(unsigned,'w') as w:
   for info in z.infolist():
    n=info.filename
    if n.upper().startswith('META-INF/') and n.upper().endswith(('.SF','.RSA','.DSA','.EC','.MF')):continue
    w.writestr(copy.copy(info),(out/'classes-patched.dex').read_bytes() if n=='classes.dex' else z.read(n))
  with zipfile.ZipFile(unsigned) as w:
   assert [n for n in w.namelist() if w.read(n)!=z.read(n)]==['classes.dex']
 if sha(unsigned)!=APK:raise ValueError('Unexpected unsigned APK')
 (out/'report.json').write_text(json.dumps({'base_sha256':BASE,'unsigned_apk_sha256':APK,'candidate_dex_sha256':DEX,'signed':False,'runtime_verified':False},indent=2)+'\n')
 print(unsigned)
if __name__=='__main__':main()
