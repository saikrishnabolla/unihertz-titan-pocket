"""Offline Titan guest: larger animation and native hardware navigation property."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,re,shutil,struct,sys,zipfile
sys.dont_write_bytecode=True
if not __debug__:raise RuntimeError('Optimization disables required checks')
P=Path(__file__).resolve().parent
BASE='93829256c4562adbecdaf0261cb1f66a60f81ada802889918508fa39f2de78ff'
OLD_ZIP='89e4a7c6e04ee3e8c49288ef10b05a84048c0901ee9942099979296faf7ee213'
OLD_PROP_SHA='a74b318ac3f5cd114b69313202a55f8991e2d88261c495b339787571a0f55689'
ZIP='b370920629c6a751a5a67e8f7e09e37824c5e02bf818eeca480f9bb54d969714'
ZIP_BYTES=10533398
PROP='/system/build.prop';MEDIA='/system/product/media';ANIM=MEDIA+'/bootanimation.zip'
OVERLAY_PARENT='/system/product/overlay';OVERLAY=OVERLAY_PARENT+'/TitanPocketFingerprint.apk'
JAR='/system/framework/services.jar';JARSHA='6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54'
APEX='/system/apex/com.android.bt.apex';APEXSHA='0d943a6d22c27440f568f8d1107b9db5cd085b7c44e7d7593a880f8d06fc05e7'
FINGERPRINT_SHA='40a0322207dc74fbd716b8d7306528b46503ddbb10f7235bfcfef552d975a7a2'
PUBLIC='4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
PROPERTIES=('qemu.hw.mainkeys',)
EPOCH='1793242775'
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def patch_properties(raw):
 text=raw.decode('utf-8');assert '\0' not in text and '\r' not in text
 additions=[]
 for key in PROPERTIES:
  vals=[]
  for line in text.splitlines():
   stripped=line.strip()
   if not stripped or stripped.startswith('#'):continue
   k,sep,value=stripped.partition('=')
   if k.strip()==key:
    if not sep:raise ValueError('Malformed profile property')
    vals.append(value.strip())
  if len(vals)>1:raise ValueError('Duplicate profile property')
  if vals and vals[0]!='1':raise ValueError('Conflicting profile property')
  if not vals:additions.append(key+'=1\n')
 if not additions:return raw
 return raw+(b'' if raw.endswith(b'\n') else b'\n')+''.join(additions).encode()
def validate_zip(path):
 assert sha(path)==ZIP,'Animation pin mismatch'
 with zipfile.ZipFile(path) as z:
  names=z.namelist();assert len(names)==370 and len(names)==len(set(names))
  assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
  assert all(v.compress_type==zipfile.ZIP_STORED for v in z.infolist()) and z.testzip() is None
  assert z.read('desc.txt')==b'720 720 60\nc 1 90 part0\nc 1 0 part1\np 240 0 part2\np 0 0 part3\n'
  frames=[n for n in names if n.endswith('.png')];assert len(frames)==365
  for n in frames:
   d=z.read(n);assert d.startswith(b'\x89PNG\r\n\x1a\n') and d[12:16]==b'IHDR' and struct.unpack('>II',d[16:24])==(720,720)
  assert all(any(n.startswith(part+'/') for n in frames) for part in ('part0','part1','part2','part3'))
def verify_bundle():
 pins=json.loads((P/'source-manifest.json').read_text())
 for v in pins['bundle_files']:
  name=v['path'];assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
  assert (P/name).is_file() and sha(P/name)==v['sha256'],name
 return pins
def compare(before,after,old_prop,new_prop):
 assert set(before)==set(after),'Added or removed path'
 assert before[PROP]['content_sha256']==hashlib.sha256(old_prop).hexdigest()==OLD_PROP_SHA
 assert after[PROP]['content_sha256']==hashlib.sha256(new_prop).hexdigest()
 assert new_prop==patch_properties(old_prop) and after[PROP]['size']==len(new_prop)
 for path in before:
  excluded={'size','content_sha256'} if path==PROP else {'size','content_sha256','allocated_512_blocks'} if path==ANIM else set()
  assert {k:v for k,v in before[path].items() if k not in excluded}=={k:v for k,v in after[path].items() if k not in excluded},path
 for path,pin in ((JAR,JARSHA),(APEX,APEXSHA),(OVERLAY,FINGERPRINT_SHA)):
  assert before[path]['content_sha256']==after[path]['content_sha256']==pin
 assert before[ANIM]['content_sha256']==OLD_ZIP and after[ANIM]['content_sha256']==ZIP
 assert after[ANIM]['size']==ZIP_BYTES
 assert before[ANIM]['inode']==after[ANIM]['inode']==4406
 assert before[MEDIA]==after[MEDIA]
def main():
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
 for name in ('base-system','animation','key','tools','avbtool','openssl','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--derive-new-output-pin',action='store_true');p.add_argument('--expected-image-sha256')
 a=p.parse_args()
 if a.derive_new_output_pin==bool(a.expected_image_sha256):raise ValueError('Choose derivation OR exact output pin')
 if a.expected_image_sha256 and not re.fullmatch('[a-f0-9]{64}',a.expected_image_sha256):raise ValueError('Invalid output pin')
 pins=verify_bundle()
 sys.path.insert(0,str(P/'helpers'));import image_helpers as b
 out=a.output.resolve();base=a.base_system.resolve();anim=a.animation.resolve();key=a.key.resolve();avb=a.avbtool.resolve();openssl=a.openssl.resolve()
 if out.exists() or a.output.is_symlink() or not out.parent.is_dir():raise ValueError('Invalid output')
 b.D=(a.tools/'debugfs').resolve();b.E=(a.tools/'e2fsck').resolve()
 for name,path in [('debugfs',b.D),('e2fsck',b.E),('avbtool',avb),('openssl',openssl)]:assert path.is_file() and sha(path)==pins['tools'][name]['sha256'],name
 for path in (base,anim,key,avb,openssl,b.D,b.E):
  if not path.is_file() or path.is_relative_to(out):raise ValueError('Missing input or input inside output')
 b.quote(str(out));b.quote(str(anim));b.validate_pin(base,b.SIZE,BASE);validate_zip(anim)
 public=b.run([openssl,'pkey','-in',key,'-pubout'])[0];assert hashlib.sha256(public.encode()).hexdigest()==PUBLIC
 if shutil.disk_usage(out.parent).free < b.SIZE*2:raise ValueError('Insufficient working disk')
 out.mkdir(mode=0o700);(out/'tool-bin').mkdir();(out/'tool-bin/openssl').symlink_to(openssl)
 b.RUN_ENV={**os.environ,'PATH':str(out/'tool-bin'),'E2FSPROGS_FAKE_TIME':EPOCH};b.RUN_ENV.pop('AVB_INVOCATION_LOGFILE',None)
 (out/'system-public.pem').write_text(public);tool=[sys.executable,str(avb)]
 b.run(tool+['verify_image','--image',base,'--key',out/'system-public.pem']);b.run([b.E,'-fn',base])
 before=b.inventory(base,out/'source-tree.json');raw_before=b.inode_bytes(base)
 assert PROP in before and ANIM in before and before[MEDIA]['type']=='directory'
 assert before[PROP]['inode']==659 and before[PROP]['size']==5737 and before[PROP]['permissions']=='0600'
 assert before[JAR]['content_sha256']==JARSHA and before[APEX]['content_sha256']==APEXSHA
 assert before[OVERLAY]['content_sha256']==FINGERPRINT_SHA and before[ANIM]['content_sha256']==OLD_ZIP and before[PROP]['content_sha256']==OLD_PROP_SHA
 old=out/'build.prop.before';b.batch(base,['dump '+PROP+' '+b.quote(str(old))]);old_prop=old.read_bytes();new_prop=patch_properties(old_prop)
 assert len(new_prop)<8192 and before[PROP]['content_sha256']==hashlib.sha256(old_prop).hexdigest()
 replacement=out/'build.prop';replacement.write_bytes(new_prop)
 image=out/'system.img';shutil.copyfile(base,image);b.run(tool+['erase_footer','--image',image]);assert image.stat().st_size==b.FS
 label=out/'system-file-label.bin';label.write_bytes(b'u:object_r:system_file:s0\0')
 commands=[]
 if new_prop!=old_prop:commands+=['rm '+PROP,'write '+b.quote(str(replacement))+' '+PROP]
 commands+=['rm '+ANIM,'write '+b.quote(str(anim))+' '+ANIM]
 paths=[ANIM]+([PROP] if new_prop!=old_prop else [])
 for path in paths:
  commands+=['set_inode_field '+path+' uid 0','set_inode_field '+path+' gid 0','set_inode_field '+path+' mode '+('0100600' if path==PROP else '0100644'),'ea_set -f '+b.quote(str(label))+' '+path+' security.selinux']
 for path in [*paths,MEDIA,'/system']:
  for field in ('atime','mtime','ctime','crtime'):commands.append('set_inode_field '+path+' '+field+' 0x495c0780')
 outputs=b.batch(image,commands,write=True);(out/'write-commands.json').write_text(json.dumps({'commands':commands,'outputs':outputs},indent=2))
 b.run([b.E,'-fn',image]);after=b.inventory(image,out/'candidate-tree-before-avb.json');compare(before,after,old_prop,new_prop)
 raw_after=b.inode_bytes(image);changed=[i for i in raw_before if raw_before[i]!=raw_after[i]]
 allowed={after[ANIM]['inode']}|({before[PROP]['inode']} if old_prop!=new_prop else set())
 assert set(changed)==allowed,changed
 fs_sha=b.sha(image)
 b.run(tool+['add_hashtree_footer','--image',image,'--partition_name','system','--partition_size',b.SIZE,'--hash_algorithm','sha256','--block_size','4096','--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',key,'--salt',fs_sha,'--rollback_index',b.SYSTEM_ROLLBACK,'--rollback_index_location','0',*[v for k,value in b.SYSTEM_PROPERTIES.items() for v in ['--prop',k+':'+value]]])
 assert image.stat().st_size==b.SIZE and b.sha(image,b.FS)==fs_sha
 b.run(tool+['verify_image','--image',image,'--key',out/'system-public.pem']);structure=b.check(image,'system',b.FS,b.SIZE,fs_sha);b.run([b.E,'-fn',image])
 final=b.inventory(image,out/'candidate-tree-final.json');assert final==after and sha(base)==BASE and sha(anim)==ZIP
 verify_bundle()
 result={'status':'OFFLINE CANDIDATE; NOT INSTALLED OR BOOTED','source_sha256':BASE,'candidate_sha256':sha(image),'animation_sha256':ZIP,'build_prop_before_sha256':hashlib.sha256(old_prop).hexdigest(),'build_prop_after_sha256':hashlib.sha256(new_prop).hexdigest(),'added_paths':[],'modified_paths':[ANIM]+([PROP] if old_prop!=new_prop else []),'navigation_property':{'qemu.hw.mainkeys':'1'},'parent_directory_metadata_unchanged':True,'all_other_paths_content_and_metadata_unchanged':True,'changed_inode_bytes':changed,'e2fsck_passed':True,'avb_verified':True,'avb_structure':structure,'fixed_reference_epoch':int(EPOCH),'expected_image_sha256':a.expected_image_sha256,'exact_reference_match':bool(a.expected_image_sha256) and sha(image)==a.expected_image_sha256,'runtime_verified':False,'retained_fingerprint_overlay_sha256':FINGERPRINT_SHA,'output_pin_pending_review':a.derive_new_output_pin}
 (out/'report.json').write_text(json.dumps(result,indent=2)+'\n')
 if a.expected_image_sha256:assert sha(image)==a.expected_image_sha256,'Whole-image reproduction differs'
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
