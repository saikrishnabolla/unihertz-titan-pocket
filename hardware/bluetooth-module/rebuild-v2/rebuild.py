"""Build a separately signed, preinstalled-only Titan trial APEX. No device access."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess,sys,zipfile
sys.dont_write_bytecode=True
import argparse,shutil
if not __debug__:raise RuntimeError('Python optimization is unsupported')
P=Path(__file__).resolve().parent
sys.path.insert(0,str(P/'helpers'))
from zip_helpers import rebuild_zip,verify_zip
parser=argparse.ArgumentParser(description=__doc__)
for name in ['base-apex','library','payload-key','container-key-pk8','container-cert','tools','java','openssl','output']:
 parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
O=args.output.resolve()
if O.exists() or args.output.is_symlink():raise ValueError('Output already exists')
if not O.parent.is_dir():raise ValueError('Output parent must exist')
source=args.base_apex.resolve();lib=args.library.resolve()
priv=args.payload_key.resolve();pk8=args.container_key_pk8.resolve();cert=args.container_cert.resolve()
D=(args.tools/'debugfs').resolve();E=(args.tools/'e2fsck').resolve()
JAVA=args.java.resolve();OPENSSL=args.openssl.resolve();AVB=P/'tools/avbtool.py'
logs=[];ENV=os.environ.copy()
sha=lambda b:hashlib.sha256(b).hexdigest()
def run(a,stdin=None):
 r=subprocess.run(list(map(str,a)),input=stdin,text=True,capture_output=True,timeout=180,env=ENV)
 logs.append({'command':list(map(str,a)),'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if str(a[0])==str(D) and any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in r.stderr.splitlines()):
  raise RuntimeError('debugfs stderr: '+r.stderr)
 if r.returncode: raise RuntimeError(str(a[0])+': '+r.stderr+r.stdout)
 return r.stdout
manifest=json.loads((P/'source-manifest.json').read_text())
for item in manifest['bundle_files']:
 if sha((P/item['path']).read_bytes())!=item['sha256']:raise ValueError('Bundle source pin differs: '+item['path'])
for name,path in [('debugfs',D),('e2fsck',E),('java',JAVA),('openssl',OPENSSL)]:
 if sha(path.read_bytes())!=manifest['external_tools'][name]['sha256']:raise ValueError('Tool pin differs: '+name)
for path in [source,lib,priv,pk8,cert,D,E,JAVA,OPENSSL]:
 if not path.is_file() or path.is_relative_to(O):raise ValueError('Missing input or input aliases output')
for key in [priv,pk8]:
 if key.stat().st_mode&0o077:raise ValueError('Private key must have mode600 or stricter')
for path in [O,source,lib,priv,pk8,cert]:
 if any(c in str(path) for c in '\\"\n\r'):raise ValueError('Unsupported path spelling')
if shutil.disk_usage(O.parent).free<512*1024**2:raise ValueError('Insufficient free space')
assert sha(source.read_bytes())=='908d224b3402d6fbdffbc88cbd81590a22a0c648a33018634492ea7ff7b2939b'
assert sha(lib.read_bytes())=='c2796dfeb5fd90d7cdd37bd3b3ba62b46fc1ec0a4b903c0d5fd882ef3bba239e'
os.umask(0o077);O.mkdir(mode=0o700)
(O/'tool-bin').mkdir(mode=0o700);(O/'tool-bin/openssl').symlink_to(OPENSSL)
ENV['PATH']=str(O/'tool-bin');ENV.pop('AVB_INVOCATION_LOGFILE',None)
ENV.pop('JAVA_TOOL_OPTIONS',None);ENV.pop('_JAVA_OPTIONS',None);ENV.pop('JDK_JAVA_OPTIONS',None)
# Public identity only: no private key bytes enter Python or the output.
cert_der=subprocess.run([str(OPENSSL),'x509','-in',str(cert),'-outform','DER'],capture_output=True,check=True,env=ENV).stdout
assert sha(cert_der)=='37259573973a3451d3a5cd48c3951575347b0cd95e12ddf639d40d2c68ceca6b'
payload=O/'original-payload.img'

assert sha(source.read_bytes())=='908d224b3402d6fbdffbc88cbd81590a22a0c648a33018634492ea7ff7b2939b'
assert sha(lib.read_bytes())=='c2796dfeb5fd90d7cdd37bd3b3ba62b46fc1ec0a4b903c0d5fd882ef3bba239e'
assert sha(AVB.read_bytes())=='69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'
with zipfile.ZipFile(source) as z: original=z.read('apex_payload.img');original_pub=z.read('apex_pubkey')
assert len(original)<64*1024**2
payload.write_bytes(original)
assert original[-64:-60]==b'AVBf'
fs_size=struct.unpack_from('>Q',original,len(original)-52)[0];assert fs_size==27811840
run([sys.executable,AVB,'verify_image','--image',payload]);run([E,'-fn',payload])
# Exact original instruction and its target are checked again here, independently of preparation.
offset=0xc0d6d4;before=lib.read_bytes();assert struct.unpack_from('<I',before,offset)[0]==0x36000580
oldword=struct.unpack_from('<I',before,offset)[0]
imm=(oldword>>5)&0x3fff
if imm&(1<<13):imm-=1<<14
assert offset+4*imm==0xc0d784
branch=0x14000000|(((0xc0d784-offset)//4)&0x3ffffff);assert branch==0x1400002c
patched=bytearray(before);struct.pack_into('<I',patched,offset,branch)
lib_delta=[i for i,(a,b) in enumerate(zip(before,patched)) if a!=b]
assert lib_delta==[offset,offset+1,offset+3]
(O/'libbluetooth_jni.so').write_bytes(patched)
path='/lib64/libbluetooth_jni.so';stat=run([D,'-R',f'stat {path}',payload]);assert 'Inode: 46 ' in stat and 'Links: 1 ' in stat
logical=offset//4096;physical=int(run([D,'-R',f'bmap {path} {logical}',payload]).strip());assert physical>0
owners=[]
for inode in range(1,49):
 raw=run([D,'-R',f'blocks <{inode}>',payload]);assert re.fullmatch(r'[\d\s]*',raw)
 if physical in set(map(int,raw.split())):owners.append(inode)
assert owners==[46],owners
modified=bytearray(original);changed=[]
for off in lib_delta:
 location=physical*4096+off%4096;assert original[location]==before[off]
 modified[location]=patched[off];changed.append(location)
assert [i for i,(a,b) in enumerate(zip(original[:fs_size],modified[:fs_size])) if a!=b]==changed
candidate=O/'apex-payload.img';candidate.write_bytes(modified)
readback=O/'readback-library.so';run([D,'-R',f'dump {path} \"{readback}\"',candidate]);assert readback.read_bytes()==patched
assert run([D,'-R',f'stat {path}',candidate])==stat
run([E,'-fn',candidate])
# Reuse externally retained trial keys; never generate or copy private keys.
pub=O/'apex_pubkey';tool=[sys.executable,AVB];run(tool+['extract_public_key','--key',priv,'--output',pub]);assert pub.read_bytes()!=original_pub
assert sha(pub.read_bytes())=='0739d53d3852ac200ab4a623ffe13df24018cdb55b6920cdff4be802fc625fd6'
info=run(tool+['info_image','--image',payload]);salt=re.search(r'^\s*Salt:\s*([a-f0-9]{64})\s*$',info,re.M)[1]
run(tool+['erase_footer','--image',candidate]);assert candidate.read_bytes()==bytes(modified[:fs_size])
run(tool+['add_hashtree_footer','--image',candidate,'--partition_size','0','--hash_algorithm','sha256','--salt',salt,'--do_not_generate_fec','--algorithm','SHA256_RSA4096','--key',priv,'--prop','apex.key:com.android.bt'])
final_payload=candidate.read_bytes();assert len(final_payload)==len(original) and final_payload[:fs_size]==bytes(modified[:fs_size])
run(tool+['verify_image','--image',candidate,'--key',priv]);run([E,'-fn',candidate])
unsigned=O/'unsigned.apex';final=O/'com.android.bt.apex';rebuild_zip(source,unsigned,final_payload,pub.read_bytes())
signer=[JAVA,'-XX:ActiveProcessorCount=2','-Xmx256m','-cp',P/'tools/apksig-9.5.0.jar',P/'tools/ApexSignature.java']
run(signer+['sign',pk8,cert,unsigned,final]);run(signer+['verify',final,cert]);zip_result=verify_zip(source,final,final_payload,pub.read_bytes())
assert sha(source.read_bytes())=='908d224b3402d6fbdffbc88cbd81590a22a0c648a33018634492ea7ff7b2939b'
assert sha(lib.read_bytes())=='c2796dfeb5fd90d7cdd37bd3b3ba62b46fc1ec0a4b903c0d5fd882ef3bba239e'
assert sha(final.read_bytes())=='0d943a6d22c27440f568f8d1107b9db5cd085b7c44e7d7593a880f8d06fc05e7', 'Candidate not byte-identical to reference'
manifest={
 'status':'OFFLINE VERIFIED PREINSTALLED-ONLY TITAN TRIAL APEX; NOT INSTALLED OR BOOT TESTED',
 'source_apex_sha256':sha(source.read_bytes()),'candidate_apex_sha256':sha(final.read_bytes()),'candidate_apex_bytes':final.stat().st_size,
 'source_library_sha256':sha(before),'candidate_library_sha256':sha(bytes(patched)),
 'instruction':{'offset_hex':hex(offset),'original_hex':hex(oldword),'replacement_hex':hex(branch),'target_hex':'0xc0d784','kind':'TBZ support-result branch replaced by unconditional B to same skip target'},
 'library_changed_offsets':lib_delta,'payload_filesystem_changed_offsets':changed,'payload_changed_block':physical,'payload_block_owners':owners,
 'all_other_payload_filesystem_bytes_unchanged':True,'all_sibling_zip_entry_contents_unchanged':True,'zip_metadata_note':'ZIP entry contents preserved except payload/public key; ZIP metadata normalized during repacking.','zip':zip_result,
 'signing':'Reused established Bluetooth trial payload key and container certificate; distinct from stock module and SYSTEM signer. Preinstalled trial only; not a stock-signed data update.',
 'runtime_hardware_guard':False,
 'scope':'Titan-only trial image and installer must enforce exact authorized hardware/kernel; binary skips query on every device where installed.',
 'source_semantics':'Same omission of the optional HCI request as the guarded source on the exact Titan baseline. Binary retains the support check; source short-circuits it. No runtime hardware guard in binary.',
 'checks':{'payload_avb_signature':True,'container_v3_api29_through37':True,'e2fsck':True,'original_inputs_unchanged':True,'inode_metadata_unchanged':True},
 'remaining':['Independent review','Replace old CAPEX with standalone factory APEX in a copied SYSTEM image','System image AVB rebuild and verification','APEX trust/activation with existing guest userdata','Controlled device boot and Bluetooth functional tests']}
manifest.update(json.loads((P/'integration-guard.json').read_text()))
manifest.update({'byte_identical_to_reference':True,'avb_openssl_path_constrained':True,'tool_hashes':{k:v['sha256'] for k,v in json.loads((P/'source-manifest.json').read_text())['external_tools'].items()},'private_keys_copied':False})
(O/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(O/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
print(json.dumps({k:manifest[k] for k in ['status','candidate_apex_sha256','candidate_apex_bytes','candidate_library_sha256','checks']},indent=2))
