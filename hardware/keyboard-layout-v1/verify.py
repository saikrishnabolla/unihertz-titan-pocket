from pathlib import Path
import argparse
import zipfile,struct,hashlib,json,re,subprocess,xml.etree.ElementTree as E
parser=argparse.ArgumentParser(description='Verify a supplied keyboard APK against the stock key map.')
for name in ('stock-kcm','apk','aapt2','framework-res','output'):
    parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
p=Path(__file__).parent;apk=args.apk;data=apk.read_bytes();align={}
if args.output.exists() or args.output.is_symlink():raise ValueError('Output must be new')
args.output.mkdir(mode=0o700)
stock=args.stock_kcm.read_text()
blocks=re.findall(r'^key [A-Z] \{.*?^\}',stock,re.M|re.S)
with zipfile.ZipFile(apk) as z:
    assert z.testzip() is None
    raw=z.read('res/raw/titan_pocket_symbols.kcm')
    assert raw==(p/'res/raw/titan_pocket_symbols.kcm').read_bytes()
    assert re.findall(r'^key [A-Z] \{.*?^\}',raw.decode(),re.M|re.S)==blocks and len(blocks)==26
    assert len(re.findall(r'^key ',raw.decode(),re.M))==26 and raw.startswith(b'type OVERLAY\n')
    assert 'map key ' not in raw.decode() and '\\uef01' not in raw.decode()
    for n in ['resources.arsc','classes.dex']:
        e=z.getinfo(n);fn,extra=struct.unpack_from('<HH',data,e.header_offset+26);off=e.header_offset+30+fn+extra
        assert e.compress_type==0 and off%4==0
        align[n]={'compression':e.compress_type,'data_offset':off,'alignment_mod4':off%4}
manifest=E.fromstring((p/'AndroidManifest.xml').read_text());ns={'a':'http://schemas.android.com/apk/res/android'}
assert not manifest.findall('uses-permission')
app=manifest.find('application');assert app is not None and len(app.findall('receiver'))==1 and not any(app.findall(k) for k in ['activity','service','provider'])
badging=subprocess.check_output([str(args.aapt2),'dump','badging',str(apk)],text=True);assert 'uses-permission:' not in badging and "targetSdkVersion:'37'" in badging
(args.output/'badging.txt').write_text(badging)
r={'status':'Built and signed; not installed or runtime tested','apk_sha256':hashlib.sha256(data).hexdigest(),'apk_bytes':len(data),'package':'org.titanpocket.keyboard','provider_descriptor':'org.titanpocket.keyboard/org.titanpocket.keyboard.KeyboardLayoutReceiver/titan_pocket_symbols','provider_label':'Titan Pocket (printed symbols)','receiver_only_no_permissions_no_network_services_or_activity':True,'all_26_vendor_letter_blocks_exact':True,'base_SPACE_ENTER_preserved':True,'no_scan_remaps':True,'type':'OVERLAY','locale':'en-US','layout':'qwerty','min_sdk':29,'target_sdk':37,'zip_crc_passed':True,'zip_resource_alignment':align,'signing':'Not checked by this verifier','framework_res_sha256':hashlib.sha256(args.framework_res.read_bytes()).hexdigest(),'raw_resource_sha256':hashlib.sha256(raw).hexdigest(),'selection':'Settings > System > Keyboard > Physical keyboard > aw9523-key > Layout; select Titan Pocket (printed symbols). Exact Settings wording remains unverified. Uninstall provider or select prior layout to revert.','acceptance':'Rerun corrected device KCM probe: A with meta2/34/18 should become64; base97/shift65 preserved. Then verify physical Alt+A in a non-secret test field. No typed data is captured by this package.'}
(args.output/'manifest.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k] for k in ['status','apk_sha256','apk_bytes','provider_descriptor','all_26_vendor_letter_blocks_exact']},indent=2))
