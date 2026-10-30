#!/usr/bin/env python3
"""Patch the exact private CP3 services JAR; never access a device."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, zipfile
ROOT=Path(__file__).resolve().parents[1]
BASE_SHA='6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--dex-tools',type=Path,required=True,help='JAR providing D8 and com.android.tools.smali packages')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java',default='java');p.add_argument('--javac',default='javac')
    a=p.parse_args()
    for value,label in [(a.original,'private original services.jar'),(a.dex_tools,'D8/smali tool JAR')]:
        if not value.is_file():p.error('Missing '+label)
    if hashlib.sha256(a.original.read_bytes()).hexdigest()!=BASE_SHA:p.error('Original services.jar is not the pinned CP3 input.')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):p.error('Use an empty output directory.')
    tool=a.dex_tools.resolve();svc=ROOT/'services'
    def run(argv):return subprocess.check_output(list(map(str,argv)),text=True)
    toolclasses=out/'dex-tool';toolclasses.mkdir()
    run([a.javac,'-cp',tool,'-d',toolclasses,svc/'DexTool.java'])
    j=[a.java,'-Xmx384m','-XX:ActiveProcessorCount=2','-cp',str(toolclasses)+os.pathsep+str(tool),'DexTool']
    original=out/'original.dex'
    with zipfile.ZipFile(a.original) as z:original.write_bytes(z.read('classes2.dex'))
    smali=out/'smali'
    run([*j,'disassemble',original,smali,'Lcom/android/server/input/InputManagerService;','Lcom/android/server/input/InputManagerService$LocalService;'])
    pins=json.loads((svc/'original-smali-pins.json').read_text())
    for name,pin in pins.items():
        q=smali/'com/android/server/input'/name
        if not q.is_file() or hashlib.sha256(q.read_bytes()).hexdigest()!=pin:p.error('Original smali or tool output differs: '+name)
        run(['patch','--batch','--forward','-p1','-d',smali,'-i',(svc/'patches'/(name+'.patch')).resolve()])
    for q in (svc/'smali').rglob('*.smali'):
        dest=smali/q.relative_to(svc/'smali');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(q.read_bytes())
    classes=out/'classes';run([a.javac,'--release','8','-Xlint:all','-Werror','-d',classes,*sorted((svc/'src').rglob('*.java'))])
    helpers=out/'helpers.jar'
    with zipfile.ZipFile(helpers,'w') as z:
        for q in sorted(classes.rglob('*.class')):z.write(q,str(q.relative_to(classes)))
    d8=out/'d8';d8.mkdir();run([a.java,'-Xmx384m','-XX:ActiveProcessorCount=2','-cp',tool,'com.android.tools.r8.D8','--release','--min-api','36','--output',d8,helpers])
    run([*j,'assemble',smali,out/'hooks.dex']);run([*j,'merge',out/'hooks.dex',d8/'classes.dex',out/'patch.dex'])
    run([*j,'merge',original,out/'patch.dex',out/'merged.dex'])
    result=out/'services.jar'
    with zipfile.ZipFile(a.original) as src,zipfile.ZipFile(result,'w') as dest:
        for entry in src.infolist():dest.writestr(entry,(out/'merged.dex').read_bytes() if entry.filename=='classes2.dex' else src.read(entry.filename))
    with zipfile.ZipFile(a.original) as src,zipfile.ZipFile(result) as dest:
        assert src.namelist()==dest.namelist() and dest.testzip() is None
        assert [n for n in src.namelist() if src.read(n)!=dest.read(n)]==['classes2.dex']
    print('Built services.jar; SHA256 '+hashlib.sha256(result.read_bytes()).hexdigest())

if __name__=='__main__':
    try:main()
    except (OSError,KeyError,subprocess.CalledProcessError,zipfile.BadZipFile) as e:raise SystemExit('Build failed: '+str(e))
