"""Compile one unsigned, device-gated Launcher spacing resource overlay."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,subprocess,zipfile,xml.etree.ElementTree as ET
if not __debug__:raise RuntimeError('Checks require normal Python execution')
P=Path(__file__).resolve().parent
PACKAGE='org.titanpocket.overlay.launcherspacing'
TARGET='com.android.launcher3'
RESOURCE='all_apps_search_bar_bottom_padding'
A='http://schemas.android.com/apk/res/android'
MANIFEST=f'''<manifest xmlns:android="{A}" package="{PACKAGE}">
    <uses-sdk android:minSdkVersion="37" android:targetSdkVersion="37" />
    <application android:hasCode="false" />
    <overlay android:targetPackage="{TARGET}" android:isStatic="true" android:priority="500"
        android:requiredSystemPropertyName="ro.product.vendor.device"
        android:requiredSystemPropertyValue="Titan_pocket" />
</manifest>
'''
RESOURCES='<resources>\n    <dimen name="all_apps_search_bar_bottom_padding">39dp</dimen>\n</resources>\n'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def validate_sources(manifest,resources):
 root=ET.fromstring(manifest)
 assert root.tag=='manifest' and root.attrib=={'package':PACKAGE}
 assert [v.tag for v in root]==['uses-sdk','application','overlay']
 expected=[{f'{{{A}}}minSdkVersion':'37',f'{{{A}}}targetSdkVersion':'37'},
           {f'{{{A}}}hasCode':'false'},
           {f'{{{A}}}targetPackage':TARGET,f'{{{A}}}isStatic':'true',f'{{{A}}}priority':'500',
            f'{{{A}}}requiredSystemPropertyName':'ro.product.vendor.device',
            f'{{{A}}}requiredSystemPropertyValue':'Titan_pocket'}]
 for element,attrs in zip(root,expected):assert element.attrib==attrs and not list(element)
 res=ET.fromstring(resources)
 assert res.tag=='resources' and res.attrib=={} and len(res)==1
 entry=res[0]
 assert entry.tag=='dimen' and entry.attrib=={'name':RESOURCE} and entry.text=='39dp' and not list(entry)

def validate_readback(manifest,resources):
 for token in [f'package="{PACKAGE}"','minSdkVersion(0x0101020c)=37','targetSdkVersion(0x01010270)=37',
               'hasCode(0x0101000c)=false',f'targetPackage(0x01010021)="{TARGET}"',
               'isStatic(0x0101055a)=true','priority(0x0101001c)=500',
               'requiredSystemPropertyName(0x01010565)="ro.product.vendor.device"',
               'requiredSystemPropertyValue(0x01010566)="Titan_pocket"']:
  assert token in manifest,token
 assert manifest.count('  E: ')==4
 assert 'targetName' not in manifest and 'uses-permission' not in manifest
 assert resources.count('resource 0x')==1
 assert f'dimen/{RESOURCE}' in resources and resources.count('() 39.000000dp')==1

def verify_inputs(inputs):
    pins=json.loads((P/'input-pins.json').read_text())
    assert set(inputs)==set(pins)
    for name,pin in pins.items():
        path=Path(inputs[name])
        assert path.is_file() and not path.is_symlink() and sha(path)==pin,name
    return pins

def build(output,inputs):
 os.umask(0o077)
 if output.exists() or output.is_symlink() or not output.parent.is_dir():raise ValueError('Invalid output')
 validate_sources(MANIFEST,RESOURCES);pins=verify_inputs(inputs)
 aapt=Path(inputs['aapt2'])
 def run(args):
  r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=60)
  assert r.returncode==0,r.stderr
  return r.stdout
 target=run([aapt,'dump','resources',Path(inputs['launcher-apk'])])
 assert 'resource 0x7f07008a dimen/'+RESOURCE+'\n      () 30.000000dp' in target
 assert run([aapt,'dump','overlayable',Path(inputs['launcher-apk'])]).strip()==''
 output.mkdir(mode=0o700);(output/'res/values').mkdir(parents=True)
 (output/'AndroidManifest.xml').write_text(MANIFEST)
 (output/'res/values/dimens.xml').write_text(RESOURCES)
 run([aapt,'compile','--dir',output/'res','-o',output/'resources.zip'])
 apk=output/'TitanPocketLauncherSpacing-unsigned.apk'
 run([aapt,'link','-I',Path(inputs['framework-res']),'--manifest',output/'AndroidManifest.xml',
      '--auto-add-overlay','-o',apk,output/'resources.zip'])
 with zipfile.ZipFile(apk) as z:
  assert z.namelist()==['AndroidManifest.xml','resources.arsc'] and z.testzip() is None
  assert all(n.startswith(('AndroidManifest.xml','resources.arsc')) for n in z.namelist())
 manifest=run([aapt,'dump','xmltree',apk,'--file','AndroidManifest.xml'])
 resources=run([aapt,'dump','resources',apk])
 validate_readback(manifest,resources)
 (output/'manifest-readback.txt').write_text(manifest)
 (output/'resources-readback.txt').write_text(resources)
 verify_inputs(inputs)
 report={'status':'UNSIGNED OFFLINE APK; NOT INSTALLED OR RUNTIME VERIFIED',
         'apk_sha256':sha(apk),'apk_bytes':apk.stat().st_size,'package':PACKAGE,'target':TARGET,
         'resource':RESOURCE,'before_dp':30,'after_dp':39,'code':False,'static':True,
         'device_gate':'ro.product.vendor.device=Titan_pocket','min_sdk':37,'target_sdk':37,
         'zip_entries_exact':['AndroidManifest.xml','resources.arsc'],'crc_verified':True,
         'target_defines_overlayable_groups':False,'target_name_omitted':True,
         'required_install_location':'/system/product/overlay/TitanPocketLauncherSpacing.apk',
         'data_app_install_sufficient':False,'runtime_idmap_verified':False,
         'source_and_tool_pins':pins,'phone_access':False,'signing':False}
 (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
 return report
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--output',type=Path,required=True)
 for name in ('aapt2','framework-res','launcher-apk','idmap-library'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 inputs={name:vars(args)[name.replace('-','_')].resolve() for name in ('aapt2','framework-res','launcher-apk','idmap-library')}
 print(json.dumps(build(args.output.resolve(),inputs),indent=2))
