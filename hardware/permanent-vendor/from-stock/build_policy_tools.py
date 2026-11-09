#!/usr/bin/env python3
"""Build pinned AOSP secilc and the project's legacy-netlink transformer on Linux."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import shutil
import sys

COMMIT = 'a8c5e74f85f869bf236a01ba24181b78f5e39a52'
PINS = {
    'libsepol/src/policydb.c': '6b3ba49cb95594b02784f434708b234a4bcd311c1522690360d2403a1084379e',
    'libsepol/cil/src/cil.c': 'f4766b3a9f0671189f895f68e8d930fa2326996ee9aec45fe8d50588ef8c9103',
    'libsepol/src/write.c': 'a4db29aa98c2c18cc6881101509d44cedd55595eecb6a925c5c9b62904990482',
    'secilc/secilc.c': '7ad740952b901b69df114473d2415eae6aef04c963fbb27ea6dfd6ca75cd144a',
}


def build(source, transformer, output, cc='gcc', flex='flex', fetch_source=False):
    source, output = source.resolve(), output.resolve()
    def run(argv, cwd=output):
        subprocess.run(list(map(str, argv)), cwd=cwd, check=True, timeout=600)
    if fetch_source:
        source.mkdir(mode=0o700, exist_ok=False)
        run(['git', 'init', source], cwd=source)
        run(['git', '-C', source, 'remote', 'add', 'origin', 'https://android.googlesource.com/platform/external/selinux'], cwd=source)
        run(['git', '-C', source, 'fetch', '--depth', '1', 'origin', COMMIT], cwd=source)
        run(['git', '-C', source, 'checkout', '--detach', 'FETCH_HEAD'], cwd=source)
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != COMMIT:
        raise ValueError('AOSP external/selinux checkout must be pinned to ' + COMMIT)
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=no'], text=True).strip():
        raise ValueError('Compiler checkout has tracked modifications')
    for name, pin in PINS.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != pin:
            raise ValueError('Compiler source hash differs: ' + name)
    output.mkdir(mode=0o700, exist_ok=False)
    headers = output / 'include'
    (headers / 'sepol').mkdir(parents=True)
    shutil.copytree(source / 'libsepol/cil/include/cil', headers / 'sepol/cil')
    lexer = output / 'cil_lexer.c'
    run([flex, '-o', lexer, source / 'libsepol/cil/src/cil_lexer.l'])
    includes = [headers] + [source / name for name in ['libsepol/include', 'libsepol/cil/include',
                                         'libsepol/cil/src', 'libsepol/src']]
    flags = ['-O2', '-D_GNU_SOURCE', '-DHAVE_REALLOCARRAY', *['-I' + str(p) for p in includes]]
    sources = sorted((source / 'libsepol/src').glob('*.c')) + sorted((source / 'libsepol/cil/src').glob('*.c'))
    sources = [p for p in sources if p.name != 'cil_lexer.c'] + [lexer]
    run([cc, *flags, '-c', *sources])
    archive = output / 'libsepol.a'
    run(['ar', 'rcs', archive, *sorted(output.glob('*.o'))])
    run([cc, *flags, source / 'secilc/secilc.c', archive, '-o', output / 'secilc'])
    run([cc, *flags, transformer.resolve(), archive, '-o', output / 'transform-policy'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'transformer', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--fetch-source', action='store_true', help='Fetch pinned AOSP source into a new directory')
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--flex', default='flex')
    args = parser.parse_args()
    try:
        build(args.source, args.transformer, args.output, args.cc, args.flex, args.fetch_source)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')
