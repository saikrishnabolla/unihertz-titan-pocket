#!/usr/bin/env python3
"""Convert Google's virtualization EROFS payload to the verified EXT4 APEX."""
import argparse,importlib.util,json,os,re,struct,subprocess,sys,zipfile
from pathlib import Path
from clean_system import SOURCE_SHA,SOURCE_BYTES,digest,regular,h
import public_seals as seals

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','repo','tools','output'):p.add_argument('--'+n,type=Path,required=True)
 group=p.add_mutually_exclusive_group(required=True);group.add_argument('--fsck-erofs',type=Path);group.add_argument('--extracted-tree',type=Path)
 a=p.parse_args();regular(a.source)
 if a.source.stat().st_size!=SOURCE_BYTES or digest(a.source)!=SOURCE_SHA:raise ValueError('Wrong Google GSI')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700)
 apex=out/'original.apex'
 r=subprocess.run([str(a.tools/'debugfs'),'-R','dump /system/apex/com.android.virt.apex '+h.quote(str(apex)),str(a.source)],capture_output=True,text=True,check=True,timeout=60)
 if any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in r.stderr.splitlines()):raise ValueError('APEX extraction failed')
 if digest(apex)!='3d103094c71d006b09c302ae1e45d9e1fe9c681487cac0983e50bcdd25a04f28':raise ValueError('Original virtualization APEX differs')
 original=out/'original-payload.img'
 with zipfile.ZipFile(apex) as z:original.write_bytes(z.read('apex_payload.img'))
 recovered=Path(__file__).resolve().parent/'recovered'
 sys.path[:0]=[str(recovered),str(a.repo/'hardware/boot-chain')]
 os.environ['TITAN_E2FSPROGS']=str(a.tools.resolve());os.environ['TITAN_DEBUGFS']=str((a.tools/'debugfs').resolve())
 import read_erofs_metadata as erofs
 import build_virt_ext4 as convert
 metadata=erofs.inventory(original);(out/'original-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
 if a.fsck_erofs:
  tree=out/'extracted'
  subprocess.run([str(a.fsck_erofs),'--extract='+str(tree),str(original)],check=True,timeout=180)
 else:tree=a.extracted_tree.resolve()
 result=convert.make_ext4(tree,metadata,out/'converted')
 filesystem=Path(result['image'])
 # Reproduce recorded host-dependent EXT4 serialization fields. No live inode or file data changes.
 raw=bytearray(filesystem.read_bytes())
 flags=struct.unpack_from('<I',raw,0x560)[0]
 if flags not in (1,2):raise ValueError('Unexpected directory-hash flags')
 struct.pack_into('<I',raw,0x560,2)
 struct.pack_into('<Q',raw,0x578,93385)
 table=struct.unpack_from('<I',raw,4096+8)[0]*4096
 deleted=table+10*256
 if struct.unpack_from('<H',raw,deleted+26)[0]!=0:raise ValueError('Expected deleted lost+found inode')
 struct.pack_into('<I',raw,deleted+20,1)
 filesystem.write_bytes(raw)
 result['before_serialization_sha256']=result['sha256']
 result['sha256']=digest(filesystem)
 result['serialization_fields_normalized']={'directory_hash_flags':2,'kbytes_written':93385,'deleted_lost_found_dtime':1}
 (out/'converted/report.json').write_text(json.dumps(result,indent=2)+'\n')
 subprocess.run([str(a.tools/'e2fsck'),'-fn',str(filesystem)],check=True,capture_output=True,text=True,timeout=120)
 (out/'serialization.json').write_text(json.dumps({'directory_hash_flags':2,'kbytes_written':93385,'deleted_lost_found_dtime':1},indent=2)+'\n')
 prefix='system__apex__com.android.virt.apex';sealroot=Path(__file__).resolve().parent/'seals'
 payload=out/'payload.img';seals.apply_avb(filesystem,sealroot/(prefix+'.avb-seal.json'),payload)
 final=out/'com.android.virt.apex';seals.apply_zip(apex,sealroot/(prefix+'.zip-seal.json'),final,{'apex_payload.img':str(payload)})
 (out/'payloads.json').write_text(json.dumps({digest(final):str(final)},indent=2)+'\n');print(digest(final))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
