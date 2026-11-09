#!/usr/bin/env python3
"""Build SYSTEM offline from the pinned Google GSI and explicit file payloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/'helpers'))
import image_helpers as h
if not __debug__:raise RuntimeError('Run without Python optimization; inventory checks are required')

FS_BYTES=3221225472
PARTITION_BYTES=3288334336
SOURCE_SHA='e5db44e3365f9e542ee3f6d4caf88ece554a460e2987086b8bf21f6c440a25ec'
SOURCE_BYTES=2072014848
FIELDS=('type','permissions','uid','gid','links','symlink_target','xattrs')

def digest(path):
 with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def regular(path):
 if path.is_symlink() or not path.is_file():raise ValueError('Expected a regular file: '+str(path))

def image_path(path):
 p=PurePosixPath(path)
 if not (path=='/system' or path.startswith('/system/')) or '..' in p.parts or str(p)!=path:raise ValueError('Invalid SYSTEM path: '+path)
 return h.quote(path)

def normalized(tree):
 result={}
 for path,item in tree.items():
  v={k:item.get(k) for k in FIELDS}
  v['xattrs']=sorted(v['xattrs'],key=lambda x:x['name'])
  v['timestamps']=[line.split(' -- ')[0].strip() for line in item['timestamps_debugfs']]
  if item['type']=='regular':v.update(size=item['size'],content_sha256=item['content_sha256'])
  result[path]=v
 return result

def load_payloads(config_path,recipe):
 config=json.loads(config_path.read_text());out={};base=config_path.resolve().parent
 for entry in recipe['files']:
  key=entry['sha256']
  if key not in config:raise ValueError('Missing payload '+entry['path']+'; SHA256 '+key)
  p=Path(config[key]);p=p if p.is_absolute() else base/p
  regular(p)
  if p.stat().st_size!=entry['size'] or digest(p)!=key:raise ValueError('Payload differs: '+entry['path'])
  out[entry['path']]=p.resolve()
 return out

def build(source,recipe_path,payload_config,output,tool_dir,avbtool=None,key=None):
 regular(source);regular(recipe_path);regular(payload_config)
 if source.stat().st_size!=SOURCE_BYTES or digest(source)!=SOURCE_SHA:raise ValueError('Google GSI differs from pinned release')
 recipe=json.loads(recipe_path.read_text())
 if recipe['source_sha256']!=SOURCE_SHA or recipe['filesystem_bytes']!=FS_BYTES:raise ValueError('Recipe baseline differs')
 payloads=load_payloads(payload_config,recipe)
 output=output.absolute()
 if output.exists() or output.is_symlink() or not output.parent.is_dir():raise ValueError('Output must be a new directory')
 if shutil.disk_usage(output.parent).free<FS_BYTES*3:raise ValueError('Need at least9GiB free')
 for name in ('debugfs','e2fsck','resize2fs','tune2fs'):
  p=tool_dir/name
  if not p.is_file() or not os.access(p,os.X_OK):raise ValueError('Missing executable '+str(p))
 os.umask(0o077);output.mkdir(mode=0o700)
 commands=[]
 def run(args,allowed=(0,)):
  r=subprocess.run(list(map(str,args)),text=True,capture_output=True,timeout=900,
   env={**os.environ,'LC_ALL':'C','TZ':'UTC','E2FSPROGS_FAKE_TIME':'1793242775'})
  commands.append({'argv':list(map(str,args)),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if r.returncode not in allowed:raise ValueError('Command failed: '+str(args[0]))
  return r
 h.D=tool_dir/'debugfs'
 before=h.inventory(source,output/'source-tree.json')
 if normalized(before)!=recipe['source_tree']:raise ValueError('Source logical inventory differs from recipe')
 image=output/'system.ext4';shutil.copyfile(source,image)
 with image.open('r+b') as stream:stream.truncate(FS_BYTES)
 run([tool_dir/'resize2fs',image,str(FS_BYTES//4096)])
 run([tool_dir/'tune2fs','-O','^dir_index',image])
 run([tool_dir/'e2fsck','-fy','-E','unshare_blocks,fixes_only',image],(0,1))
 run([tool_dir/'tune2fs','-O','dir_index',image])
 ops=[]
 for p in sorted(recipe['remove'],key=lambda x:(-x.count('/'),x)):
  kind=before[p]['type'];ops.append(('rmdir ' if kind=='directory' else 'rm ')+image_path(p))
 for p in sorted(recipe['directories'],key=lambda x:(x.count('/'),x)):
  ops.append('mkdir '+image_path(p))
 for entry in recipe['files']:
  p=entry['path']
  if p in before:ops.append('rm '+image_path(p))
  ops.append('write '+h.quote(str(payloads[p]))+' '+image_path(p))
 # Restore complete metadata for every changed file and added directory.
 entries={e['path']:e for e in recipe['files']}
 entries.update(recipe['directories'])
 for p,entry in entries.items():
  q=image_path(p)
  mode=(stat.S_IFDIR if entry['type']=='directory' else stat.S_IFREG)|int(entry['permissions'],8)
  for name,value in [('mode','0'+format(mode,'o')),('uid',entry['uid']),('gid',entry['gid'])]:ops.append(f'set_inode_field {q} {name} {value}')
  for attr in entry['xattr_bytes']:
   dest=output/('xattr-'+hashlib.sha256((p+attr['name']).encode()).hexdigest())
   dest.write_bytes(bytes.fromhex(attr['hex']))
   ops.append('ea_set -f '+h.quote(str(dest))+' '+q+' '+h.quote(attr['name']))
  for name in ('atime','mtime','ctime','crtime'):ops.append(f'set_inode_field {q} {name} 0x495c0780')
 for p,item in recipe['target_tree'].items():
  if item['type']=='directory':
   for name in ('atime','mtime','ctime','crtime'):ops.append(f'set_inode_field {h.quote(p)} {name} 0x495c0780')
 script=output/'apply.debugfs';script.write_text('\n'.join(ops)+'\n')
 result=run([h.D,'-w','-f',script,image])
 errors=[line for line in result.stderr.splitlines() if line and not re.fullmatch(r'debugfs \d[^\n]*',line)]
 if errors:raise ValueError('debugfs rejected an operation: '+'; '.join(errors))
 run([tool_dir/'e2fsck','-fn',image])
 after=h.inventory(image,output/'candidate-tree.json')
 actual=normalized(after);expected=recipe['target_tree']
 changes=[p for p in set(actual)|set(expected) if actual.get(p)!=expected.get(p)]
 if changes:raise ValueError('Final logical inventory differs: '+', '.join(sorted(changes)[:15]))
 report={'source_sha256':SOURCE_SHA,'filesystem_sha256':digest(image),'filesystem_bytes':FS_BYTES,
  'target_logical_inventory_verified':True,'signed':False,'device_tested':False}
 if bool(avbtool)!=bool(key):raise ValueError('Supply both avbtool and key, or neither')
 if avbtool:
  regular(avbtool);regular(key)
  if key.stat().st_mode&0o077:raise ValueError('Key must be mode600 or stricter')
  signed=output/'system.img';shutil.copyfile(image,signed)
  props={'com.android.build.system.os_version':'17','com.android.build.system.fingerprint':'Android/generic_system/generic:17/CP3A.260905.010/16176746:user/release-keys','com.android.build.system.security_patch':'2026-09-05'}
  run([sys.executable,avbtool,'add_hashtree_footer','--image',signed,'--partition_name','system',
   '--partition_size',str(PARTITION_BYTES),'--hash_algorithm','sha256','--block_size','4096',
   '--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',key,'--salt',report['filesystem_sha256'],
   '--rollback_index','1788566400',*[arg for k,v in props.items() for arg in ('--prop',k+':'+v)]])
  run([sys.executable,avbtool,'verify_image','--image',signed,'--key',key])
  public=output/'system.avbpubkey'
  run([sys.executable,avbtool,'extract_public_key','--key',key,'--output',public])
  report['signer_public_key_sha256']=digest(public)
  report.update(signed=True,system_sha256=digest(signed),signing_key_phone_compatibility='unverified')
 (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','recipe','payloads','output','tools'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--avbtool',type=Path);p.add_argument('--key',type=Path)
 a=p.parse_args();print(json.dumps(build(a.source,a.recipe,a.payloads,a.output,a.tools,a.avbtool,a.key),indent=2))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError) as e:raise SystemExit(str(e))
