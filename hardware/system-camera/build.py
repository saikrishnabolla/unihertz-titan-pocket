#!/usr/bin/env python3
"""Build the pinned Titan system-camera add-on from an externally supplied APK."""
import argparse,hashlib,io,json,tarfile
from pathlib import Path
SHA='ebe906d3d00cd8596c4015975ff58c496f4ce0a946e689da718b295612445f95'
URL='https://www.celsoazevedo.com/files/android/google-camera/dev-greatness/f/dl6/'
PACKAGE='com.google.android.apps.cameralite'
def build(apk,output):
    if apk.is_symlink() or not apk.is_file() or hashlib.sha256(apk.read_bytes()).hexdigest()!=SHA:
        raise ValueError('Supply the exact Greatness NoAux APK; SHA256 '+SHA)
    output.mkdir(parents=True,exist_ok=False)
    files={
      'module.prop':b'id=titan_system_camera\nname=Titan System Camera\nversion=CP3A.260905.010-v1\nversionCode=1\nauthor=Titan Pocket Android 17\ndescription=Greatness Camera Go NoAux system camera; replaces the AOSP Camera2 app.\n',
      'system/product/app/TitanCamera/TitanCamera.apk':apk.read_bytes(),
      'system/product/app/Camera2/.replace':b'',
      'service.sh':b'''#!/system/bin/sh
n=0
while [ "$n" -lt 180 ]; do
 [ "$(getprop sys.boot_completed)" = 1 ] && exit 0
 sleep 2
 n=$((n+1))
done
touch /data/adb/modules/titan_system_camera/disable
sync
reboot
''',
    }
    manifest={'build':'CP3A.260905.010','package':PACKAGE,'version':'Greatness.210726.1455Test','source':URL,'apk_sha256':SHA,'boot_timeout_seconds':360,'files':{}}
    with tarfile.open(output/'system-camera.tar','w') as t:
      for name,data in sorted(files.items()):
        path=output/'module'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        mode=0o755 if name=='service.sh' else 0o644;path.chmod(mode)
        entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=mode;entry.uid=entry.gid=entry.mtime=0
        t.addfile(entry,io.BytesIO(data))
        manifest['files'][name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'mode':mode}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apk',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();build(a.apk,a.output)
