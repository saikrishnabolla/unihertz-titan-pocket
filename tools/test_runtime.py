#!/usr/bin/env python3
"""Run actual Runtime.cpp with host substitutes for Android originals and owner."""
from pathlib import Path
import argparse,json,subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCES=['Runtime.cpp','ProductionBridge.cpp','ProductionSink.cpp','NativeMotionAdapter.cpp',
 'OriginalViewportAdapter.cpp','TitanSessionRegistry.cpp','TitanReaderLifecycle.cpp','DispatchEndpoint.cpp',
 'ReaderNotifyBoundary.cpp','FailureReset.cpp','PhysicalArbitration.cpp',
 'proven/mapper/accumulator/MultiTouchMotionAccumulator.cpp']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--sanitizer',choices=['address,undefined','thread'],default='address,undefined')
    a=p.parse_args()
    if not a.inputs.is_file():p.error('Matching CP3 platform headers are required; supply private input configuration.')
    cfg=json.loads(a.inputs.read_text());base=a.inputs.resolve().parent
    flags=['-I',str(ROOT/'native/proven'),'-I',str(ROOT/'native'),'-I',str(ROOT/'tests/host-include')]
    for value in cfg['include_dirs']:
        q=Path(value);q=q if q.is_absolute() else base/q
        if not q.is_dir():p.error('Missing private header directory: '+value)
        flags+=['-I',str(q)]
    output=a.output.resolve();output.mkdir(parents=True,exist_ok=True);exe=output/'runtime-tests'
    subprocess.run([cfg.get('host_cxx',cfg.get('cxx','clang++')),*flags,'-std=c++20','-pthread',
        '-fno-exceptions','-fno-rtti','-O0','-g','-Wall','-Wextra','-Werror','-Wno-invalid-specialization',
        '-Wno-macro-redefined','-fsanitize='+a.sanitizer,'-include','algorithm',
        '-include','android/os/IInputConstants.h','-include','android/os/MotionEventFlag.h',
        *[str(ROOT/'native'/n) for n in SOURCES],str(ROOT/'tests/runtime.cpp'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)

if __name__=='__main__':
    try:main()
    except (OSError,KeyError,json.JSONDecodeError,subprocess.CalledProcessError) as e:raise SystemExit('Runtime test failed: '+str(e))
