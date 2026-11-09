#!/usr/bin/env python3
"""Build the Titan BOOT file offline on Linux ARM64; never access a device."""
import argparse,hashlib,json,os,platform,shutil,subprocess,sys,zipfile
from pathlib import Path
APK_SHA='89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7'
STOCK_SHA='e5dda12d7e2fc346d4c21d58380366555811fdbe3b1fac2c4316386a61ebe24b'
MAGISK_BOOT_SHA='a5d6f52db76031d255ffee71f822d470fb313812c634e756f4575187382d13bb'
FINAL_SHA='c3aa2e73c3efbce4b6fe6558558d91826be868d8981f99d04242b4d0cb6876ce'

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def regular(p):
 if p.is_symlink() or not p.is_file():raise ValueError('Expected regular input: '+str(p))
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('stock','magisk-apk','output','boot-chain'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();regular(a.stock);regular(a.magisk_apk)
 if platform.system()!='Linux' or platform.machine() not in ('aarch64','arm64'):raise ValueError('Use an isolated Linux ARM64 build directory; this does not run on macOS')
 if a.stock.stat().st_size!=33554432 or digest(a.stock)!=STOCK_SHA:raise ValueError('Stock BOOT differs')
 if digest(a.magisk_apk)!=APK_SHA:raise ValueError('Magisk31.1 official APK differs')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700);shutil.copyfile(a.stock,out/'stock-boot.img')
 with zipfile.ZipFile(a.magisk_apk) as z:
  for name in ('magiskboot','magisk','magiskinit','init-ld'):
   target=out/name;target.write_bytes(z.read('lib/arm64-v8a/lib'+name+'.so'));target.chmod(0o700)
 env={**os.environ,'KEEPVERITY':'true','KEEPFORCEENCRYPT':'true','PATCHVBMETAFLAG':'false'};logs=[]
 def run(args):
  r=subprocess.run(list(map(str,args)),cwd=out,env=env,capture_output=True,text=True,timeout=180)
  logs.append({'argv':list(map(str,args)),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  (out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
  if r.returncode:raise ValueError('Magisk file operation failed; inspect commands.json')
 run(['./magiskboot','unpack','stock-boot.img'])
 run(['./magiskboot','cpio','ramdisk.cpio','test'])
 shutil.copyfile(out/'ramdisk.cpio',out/'ramdisk.cpio.orig')
 run(['./magiskboot','compress=xz','magisk','magisk.xz']);run(['./magiskboot','compress=xz','init-ld','init-ld.xz'])
 config='KEEPVERITY=true\nKEEPFORCEENCRYPT=true\nRECOVERYMODE=false\nVENDORBOOT=false\nPREINITDEVICE=cache\nSHA1='+hashlib.sha1(a.stock.read_bytes()).hexdigest()+'\n'
 (out/'config').write_text(config)
 run(['./magiskboot','cpio','ramdisk.cpio','add 0750 init magiskinit','mkdir 0750 overlay.d','mkdir 0750 overlay.d/sbin',
  'add 0644 overlay.d/sbin/magisk.xz magisk.xz','add 0644 overlay.d/sbin/init-ld.xz init-ld.xz','patch',
  'backup ramdisk.cpio.orig','mkdir 000 .backup','add 000 .backup/.magisk config'])
 # Keep the stock compressed kernel and all DTB bytes: no Samsung/SAR patches apply.
 (out/'kernel').unlink()
 run(['./magiskboot','repack','stock-boot.img','magisk-boot.img'])
 magisk=out/'magisk-boot.img'
 if digest(magisk)!=MAGISK_BOOT_SHA:raise ValueError('Magisk BOOT differs from verified baseline')
 sys.path.insert(0,str(a.boot_chain.resolve()));import prepare_bpf_boot_derivative as b
 source=magisk.read_bytes();original=b.parse_boot(source);image,tail,n=b.unpack_kernel(original['parts']['kernel'])
 patched=b.patch_image(image);kernel,n=b.compress_kernel(original['parts']['kernel'],patched)
 candidate,_,_=b.repack(source,kernel)
 if hashlib.sha256(candidate).hexdigest()!=FINAL_SHA:raise ValueError('Final BOOT differs; check zlib version')
 (out/'boot.img').write_bytes(candidate)
 report={'stock_sha256':STOCK_SHA,'magisk_apk_sha256':APK_SHA,'magisk_boot_sha256':MAGISK_BOOT_SHA,
  'boot_sha256':FINAL_SHA,'bytes':len(candidate),'device_operations':False}
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
