#!/usr/bin/env python3
"""Build a pinned Titan base SYSTEM and SUPER offline; no device operations."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'helpers'))
import image_helpers as h
sys.path.insert(0,str(ROOT/'super_helpers'))
import assemble_super as assembler
import build_metadata as metadata
SOURCE_SHA='8eadb0b59dfd536354cf88e8bffb5dcb8fbb6b52124ee96eda19fd2fbea71dab'
TREE_SHA='4a05290a7bb73a083da53e46b188cf50307041f36345f5b5c903f085f18f7578'
VENDOR_SHA='4428076fb5e54681e06fc38faa648a9d71f8686acc6e3da017e79744445bb62c'
PREFIX_SHA='b79a001a076880b6679c02d52e51842850e22841ff16b7bc20d999b7459e2acf'
REMOVE_ROOTS=['/system/product/app/'+n for n in ['Camera2','QuickSearchBox','Browser2','webview']]
ASSETS={
 '/system/product/app/TitanCamera/TitanCamera.apk':{'file':None,'sha256':'6e1d05a7b96b308f3a9dff3103db55cfee2cbea38b3249b5879fe35cfcf179ff','package':'app.grapheneos.camera','label':'system_file'},
 '/system/product/app/Chromium/Chromium.apk':{'file':None,'sha256':'44e0f664d80bf3b1c390f8030ff9a260aab06f137d17f2aa0e3816cc2bd61aee','package':'org.ungoogled.chromium.stable','label':'system_file'},
 '/system/product/app/TitanWebView/TitanWebView.apk':{'file':None,'sha256':'dcb233a86d58ca922f8aa08dd4216c9158450866286d727a1358e502e935baa3','package':'com.android.webview','label':'system_file'},
 '/system/lib64/libtitan_keyboard_surface.so':{'file':None,'sha256':'a8b78c2fc7a04b3652d03125fc9f7ba075114554c1ba9de3d55d87089014a179','label':'system_lib_file'},
}

def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def require_pin(path,pin,size=None):
 assert not path.is_symlink() and path.is_file(),str(path)
 if size is not None:assert path.stat().st_size==size
 assert h.sha(path)==pin,'Input differs: '+str(path)
def restore_time(commands,path,entry):
 for line in entry['timestamps_debugfs']:
  m=re.match(r'(\w+): (0x[0-9a-f]+):([0-9a-f]+)',line.strip());assert m and int(m[3],16)==0
  commands.append('set_inode_field '+path+' '+m[1]+' '+m[2])
def set_metadata(commands,path,directory,label,label_file):
 for field,val in [('uid','0'),('gid','0'),('mode','040755' if directory else '0100644')]:commands.append('set_inode_field '+path+' '+field+' '+val)
 commands.append('ea_set -f '+h.quote(str(label_file))+' '+path+' security.selinux')
 for field in ['atime','mtime','ctime','crtime']:commands.append('set_inode_field '+path+' '+field+' 0x495c0780')

def main():
 global SRC,TREE,VENDOR,PREFIX,AVB,AAPT
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--inputs',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 inputs=json.loads(args.inputs.read_text())
 SRC=Path(inputs['system']);TREE=Path(inputs['source_tree']);VENDOR=Path(inputs['vendor']);PREFIX=Path(inputs['prefix']);args.key=Path(inputs['avb_key'])
 AVB=Path(inputs['tools']['avbtool']);AAPT=Path(inputs['tools']['aapt2'])
 for dest,name in {'/system/product/app/TitanCamera/TitanCamera.apk':'camera','/system/product/app/Chromium/Chromium.apk':'browser','/system/product/app/TitanWebView/TitanWebView.apk':'webview','/system/lib64/libtitan_keyboard_surface.so':'touchpad'}.items():ASSETS[dest]['file']=Path(inputs[name])
 out=args.output.absolute();assert not out.exists() and not out.is_symlink()
 assert out.parent.is_dir();assert shutil.disk_usage(out.parent).free>h.SIZE+metadata.SUPER_SIZE+6*1024**3
 os.umask(0o077);out.mkdir(mode=0o700)
 h.D=Path(inputs['tools']['debugfs']);h.E=Path(inputs['tools']['e2fsck'])
 h.RUN_ENV={**os.environ,'E2FSPROGS_FAKE_TIME':'1793242775'};h.RUN_ENV.pop('AVB_INVOCATION_LOGFILE',None)
 require_pin(SRC,SOURCE_SHA,h.SIZE);require_pin(TREE,TREE_SHA);require_pin(VENDOR,VENDOR_SHA,536870912);require_pin(PREFIX,PREFIX_SHA,metadata.PREFIX_SIZE)
 before=json.loads(TREE.read_text());assert '/system/lib64/libtitan_keyboard_surface.so' in before
 asset_manifest={}
 for dest,asset in ASSETS.items():
  require_pin(asset['file'],asset['sha256'])
  asset_manifest[dest]={**{k:v for k,v in asset.items() if k!='file'},'file':str(asset['file']),'bytes':asset['file'].stat().st_size}
  if 'package' in asset:
   text,_=h.run([AAPT,'dump','badging',asset['file']]);assert text.startswith("package: name='"+asset['package']+"'")
   if asset['package']=='com.android.webview':
    assert 'arm64-v8a' in text and 'armeabi-v7a' in text,'Multi-arch WebView must supply both device ABIs'
   (out/(Path(dest).stem+'-badging.txt')).write_text(text)
 public=subprocess.run([inputs['tools']['openssl'],'pkey','-in',str(args.key),'-pubout'],capture_output=True,text=True,check=True).stdout
 assert hashlib.sha256(public.encode()).hexdigest()=='4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
 pub=out/'system-public.pem';pub.write_text(public)
 avb=[sys.executable,str(AVB)]
 h.run(avb+['verify_image','--image',SRC,'--key',pub]);h.run([h.E,'-fn',SRC])
 original_structure=h.check(SRC,'system',h.FS,h.SIZE,h.sha(SRC,h.FS));raw_before=h.inode_bytes(SRC)
 removed={p for p in before if any(p==root or p.startswith(root+'/') for root in REMOVE_ROOTS)}
 assert all(root in removed for root in REMOVE_ROOTS)
 added={str(Path(p).parent) for p in ASSETS if p not in before}|{p for p in ASSETS if p not in before}
 assert not added&before.keys()
 modified={p for p in ASSETS if p in before};assert modified=={'/system/lib64/libtitan_keyboard_surface.so'}
 parents={'/system/product/app','/system/lib64'}
 image=out/'system.img';shutil.copyfile(SRC,image);h.run(avb+['erase_footer','--image',image]);assert image.stat().st_size==h.FS
 labels={}
 for name in ['system_file','system_lib_file']:
  f=out/(name+'.label');f.write_bytes(('u:object_r:'+name+':s0\0').encode());labels[name]=f
 commands=[]
 for path in sorted(removed,key=lambda p:(-p.count('/'),p)):
  commands.append(('rmdir ' if before[path]['type']=='directory' else 'rm ')+path)
 for dest in sorted(ASSETS):
  asset=ASSETS[dest];parent=str(Path(dest).parent)
  if parent in added:
   commands.append('mkdir '+parent);set_metadata(commands,parent,True,'system_file',labels['system_file'])
  if dest in modified:commands.append('rm '+dest)
  commands.append('write '+h.quote(str(asset['file']))+' '+dest)
  set_metadata(commands,dest,False,asset['label'],labels[asset['label']])
 for parent in parents:restore_time(commands,parent,before[parent])
 print('Inputs verified; modifying offline SYSTEM and validating filesystem.',flush=True)
 result=h.batch(image,commands,write=True);save(out/'commands.json',{'commands':commands,'results':result})
 h.run([h.E,'-fn',image]);after=h.inventory(image,out/'candidate-tree-before-avb.json')
 assert set(before)-set(after)==removed
 assert set(after)-set(before)==added
 for path,entry in before.items():
  if path in removed:continue
  ignored={'inode','size','allocated_512_blocks','content_sha256'} if path in modified else ({'size','links','allocated_512_blocks'} if path in parents else set())
  assert {k:v for k,v in entry.items() if k not in ignored}=={k:v for k,v in after[path].items() if k not in ignored},'Unexpected survivor change: '+path
 assert after['/system/product/app']['links']==before['/system/product/app']['links']-4+3
 assert after['/system/lib64']['links']==before['/system/lib64']['links']
 for path,asset in ASSETS.items():
  entry=after[path];assert entry['content_sha256']==asset['sha256'] and entry['size']==asset['file'].stat().st_size
  assert entry['uid']==entry['gid']==0 and entry['permissions']=='0644' and entry['links']==1
  exemplar=before['/system/product/app/Camera2/Camera2.apk'] if asset['label']=='system_file' else before['/system/lib64/libtitan_keyboard_surface.so']
  assert entry['xattrs']==exemplar['xattrs'] and entry['timestamps_debugfs']==exemplar['timestamps_debugfs']
 for path in added-set(ASSETS):
  entry=after[path];exemplar=before['/system/product/app/Camera2'];assert entry['type']=='directory' and entry['uid']==entry['gid']==0 and entry['permissions']=='0755' and entry['xattrs']==exemplar['xattrs'] and entry['timestamps_debugfs']==exemplar['timestamps_debugfs']
 raw_after=h.inode_bytes(image);changed={i for i in raw_before if raw_before[i]!=raw_after[i]}
 allowed={before[p]['inode'] for p in removed|modified|parents}|{after[p]['inode'] for p in added|modified|parents}
 assert changed<=allowed,'Unexpected inode-slot mutation'
 fs_sha=h.sha(image)
 h.run(avb+['add_hashtree_footer','--image',image,'--partition_name','system','--partition_size',h.SIZE,'--hash_algorithm','sha256','--block_size','4096','--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',args.key,'--salt',fs_sha,'--rollback_index',h.SYSTEM_ROLLBACK,'--rollback_index_location','0',*[v for k,value in h.SYSTEM_PROPERTIES.items() for v in ['--prop',k+':'+value]]])
 assert image.stat().st_size==h.SIZE and h.sha(image,h.FS)==fs_sha
 h.run(avb+['verify_image','--image',image,'--key',pub]);assert h.check(image,'system',h.FS,h.SIZE,fs_sha)==original_structure
 h.run([h.E,'-fn',image]);assert h.sha(SRC)==SOURCE_SHA
 final=h.inventory(image,out/'candidate-tree-final.json');assert final==after
 system_sha=h.sha(image)
 print('SYSTEM filesystem, path metadata and AVB verified; assembling unchanged-layout SUPER.',flush=True)
 prefix=PREFIX.read_bytes()
 def verify_prefix(blob):
  assert hashlib.sha256(blob).hexdigest()==PREFIX_SHA
  metadata.validate_minimal(blob)
 payloads=[assembler.Payload('system',image,1048576,h.SIZE,system_sha),assembler.Payload('vendor',VENDOR,3289382912,536870912,VENDOR_SHA)]
 super_report=assembler._assemble(prefix,payloads,metadata.SUPER_SIZE,out/'super',assembler.DEFAULT_RESERVE,verify_prefix)
 stats,_=h.run([h.D,'-R','stats',image]);(out/'filesystem-stats.txt').write_text(stats)
 report={'status':'OFFLINE BASE APP AND WEBVIEW CANDIDATE; PHONE TEST PENDING','source_system_sha256':SOURCE_SHA,'system_sha256':system_sha,'system_bytes':h.SIZE,'filesystem_sha256':fs_sha,'super_sha256':super_report['sha256'],'super_bytes':metadata.SUPER_SIZE,'vendor_sha256':VENDOR_SHA,'vendor_unchanged':True,'super_layout_unchanged':True,'assets':asset_manifest,'removed_paths':sorted(removed),'added_paths':sorted(added),'modified_paths':sorted(modified),'all_other_path_content_and_metadata_unchanged':True,'allowed_parent_metadata_fields':['size','links','allocated_512_blocks'],'changed_inode_slots':sorted(changed),'e2fsck_pass':True,'avb_verified':True,'webview_provider':'com.android.webview; original framework whitelist; no RRO','raw_partition_writes':False,'phone_tested':False}
 save(out/'report.json',report)
 print(json.dumps({k:v for k,v in report.items() if k not in ['assets','removed_paths','added_paths','changed_inode_slots']},indent=2),flush=True)
if __name__=='__main__':main()
