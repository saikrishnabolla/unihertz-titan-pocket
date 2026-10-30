#!/usr/bin/env python3
"""Run the first-unlock regression against the added session smali and Java state."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--original-smali', type=Path,
                        help='Optional pinned original InputManagerService.smali for patch roundtrip')
    parser.add_argument('--javac', default='javac')
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    patch = ROOT / 'services/patches/InputManagerService.smali.patch'
    if args.original_smali:
        original = args.original_smali.read_bytes()
        pin = json.loads((ROOT / 'services/original-smali-pins.json').read_text())['InputManagerService.smali']
        if hashlib.sha256(original).hexdigest() != pin:
            parser.error('Original smali differs from the pinned CP3 disassembly.')
        smali = output / 'patched-smali'
        destination = smali / 'com/android/server/input/InputManagerService.smali'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original)
        subprocess.run(['patch', '--batch', '--forward', '-p1', '-d', str(smali),
                        '-i', str(patch)], check=True)
        current = destination
    else:
        # These complete added methods are our patch code; no original class is shipped.
        added = '\n'.join(line[1:] for line in patch.read_text().splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        current = output / 'current-session-methods.smali'
        current.write_text(added + '\n')
    classes = output / 'classes'
    subprocess.run([args.javac, '--release', '8', '-Xlint:all', '-Werror', '-d', str(classes),
                    str(ROOT / 'services/src/com/android/server/input/KeyboardSurfaceSessionState.java'),
                    str(ROOT / 'tests/keyguard-regression/KeyguardRegression.java')], check=True)
    results = []
    for name, source, expected in [
        ('old', ROOT / 'tests/keyguard-regression/old-session-methods.smali', 1),
        ('current', current, 0),
    ]:
        result = subprocess.run([args.java, '-cp', str(classes),
                                 'com.android.server.input.KeyguardRegression', str(source)],
                                capture_output=True, text=True)
        results.append(dict(input=name, sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        print(name + ':\n' + result.stdout, end='')
        (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        if result.returncode != expected:
            raise SystemExit(result.stderr or 'Unexpected regression result')

if __name__ == '__main__':
    main()
