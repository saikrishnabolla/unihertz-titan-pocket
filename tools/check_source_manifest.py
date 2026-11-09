#!/usr/bin/env python3
"""Check or refresh the complete tracked-file inventory; no private inputs included."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Refresh root manifest from the Git index')
    args = parser.parse_args()
    tracked = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
    files = sorted(p for p in tracked if p and p != 'source-manifest.json')
    current = {}
    for name in files:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit('Source must be a regular file: ' + name)
        current[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = ROOT / 'source-manifest.json'
    if args.write:
        manifest.write_text(json.dumps(current, indent=2) + '\n')
    else:
        recorded = json.loads(manifest.read_text())
        changed = sorted(k for k in current.keys() | recorded.keys() if current.get(k) != recorded.get(k))
        if changed:
            raise SystemExit('Source manifest differs: ' + ', '.join(changed))
    print(f'Source inventory: {len(current)} files verified')


if __name__ == '__main__':
    main()
