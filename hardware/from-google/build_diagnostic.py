#!/usr/bin/env python3
"""Compile the bounded logd recorder offline with an ARM64 Linux GCC toolchain."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
EXPECTED='b980ba79f628a91e4caa89e038523fbbf9fd63a41263fb0162c7a0c6957a65c8'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--gcc',required=True);p.add_argument('--boot-chain',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700)
 source=Path(__file__).resolve().parent/'recovered/google_diag_logdr.c'
 target=out/'titan-diag'
 subprocess.run([a.gcc,'-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wno-unused-function',
  '-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie',
  '-Wl,--build-id=none','-Wl,-e,_start','-Wl,-z,max-page-size=4096','-I',str(a.boot_chain.resolve()),str(source),'-o',str(target)],check=True,timeout=120)
 actual=hashlib.sha256(target.read_bytes()).hexdigest()
 if actual!=EXPECTED:raise ValueError('Recorder differs; use the matching ARM64 Linux GCC toolchain')
 (out/'payloads.json').write_text(json.dumps({EXPECTED:str(target)},indent=2)+'\n');print(actual)
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,subprocess.SubprocessError) as e:raise SystemExit(str(e))
