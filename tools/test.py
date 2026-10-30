#!/usr/bin/env python3
"""Run core C++ and actual Java session-state tests without firmware or a phone."""
from pathlib import Path
import argparse, os, subprocess
ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cxx',default=os.environ.get('CXX','clang++'))
    p.add_argument('--javac',default='javac')
    p.add_argument('--java',default='java')
    p.add_argument('--sanitizer',choices=['address,undefined','thread'],default='address,undefined')
    a=p.parse_args();output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
    for name in ['native_owner','inventory']:
        exe=output/name
        subprocess.run([a.cxx,'-std=c++20','-pthread','-g','-O1','-Wall','-Wextra','-Werror',
            '-fsanitize='+a.sanitizer,'-I',str(ROOT/'native'),str(ROOT/'tests'/(name+'.cpp')),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
    prod=output/'production-classes';tests=output/'test-classes'
    java=ROOT/'services/src/com/android/server/input'
    subprocess.run([a.javac,'--release','8','-Xlint:all','-Werror','-d',str(prod),*map(str,java.glob('*.java'))],check=True)
    subprocess.run([a.javac,'-Xlint:all','-Werror','-cp',str(prod),'-d',str(tests),*map(str,(ROOT/'tests/java').rglob('*.java'))],check=True)
    for name in ['ProductionSessionStateTest','AsyncPublicationTest']:
        subprocess.run([a.java,'-cp',str(tests)+os.pathsep+str(prod),'com.android.server.input.'+name],check=True)
    print('Core tests passed. Android Runtime/ABI and physical phone behavior need separate verification.')

if __name__=='__main__':
    try:main()
    except (OSError,subprocess.CalledProcessError) as e:raise SystemExit('Test failed: '+str(e))
