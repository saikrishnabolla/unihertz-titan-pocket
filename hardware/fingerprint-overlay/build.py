"""Build an unsigned RRO reconstructed from the pinned, working overlay.

No device access. Supply matching Android 17 framework resources and aapt2.
Signing and installation are separate; this does not reproduce the signed APK.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
REFERENCE_SHA256 = '40a0322207dc74fbd716b8d7306528b46503ddbb10f7235bfcfef552d975a7a2'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(text):
    return '\n'.join(re.sub(r' \(line=\d+\)', '', line).rstrip()
                     for line in text.strip().splitlines()) + '\n'


def run(command):
    return subprocess.check_output([str(x) for x in command], text=True)


def dumps(aapt2, apk):
    return {
        'manifest': normalized(run([aapt2, 'dump', 'xmltree', apk, '--file', 'AndroidManifest.xml'])),
        'resources': normalized(run([aapt2, 'dump', 'resources', apk])),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aapt2', type=Path, required=True)
    parser.add_argument('--framework', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    expected = {name: (ROOT / ('expected-' + name + '.txt')).read_text()
                for name in ('manifest', 'resources')}
    if args.reference:
        if sha(args.reference) != REFERENCE_SHA256:
            raise ValueError('Reference APK hash mismatch')
        if dumps(args.aapt2, args.reference) != expected:
            raise ValueError('Reference decoded configuration mismatch')
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='fingerprint-rro-') as temporary:
        compiled = Path(temporary) / 'resources.zip'
        run([args.aapt2, 'compile', '--dir', ROOT / 'res', '-o', compiled])
        apk = args.output / 'TitanPocketFingerprint-unsigned.apk'
        run([args.aapt2, 'link', '--manifest', ROOT / 'AndroidManifest.xml',
             '-I', args.framework, '--auto-add-overlay', '-o', apk, compiled])
        actual = dumps(args.aapt2, apk)
        if actual != expected:
            raise ValueError('Reconstructed decoded configuration mismatch')
        result = {
            'status': 'decoded manifest and resource equivalence passed; unsigned; not device tested',
            'reference_signed_apk_sha256': REFERENCE_SHA256,
            'unsigned_apk_sha256': sha(apk),
            'aapt2_sha256': sha(args.aapt2),
            'framework_resources_sha256': sha(args.framework),
            'reference_checked': bool(args.reference),
            'signed_binary_reproduction_claimed': False,
        }
        (args.output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
