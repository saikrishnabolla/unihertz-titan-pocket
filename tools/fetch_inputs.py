#!/usr/bin/env python3
"""Download named, hash-pinned upstream inputs without extracting or running them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate(entry):
    name = entry['filename']
    if not isinstance(name, str) or not name or Path(name).name != name or name in ('.', '..') or '\\' in name:
        raise ValueError('Input filename must be a plain filename')
    if not re.fullmatch(r'[a-f0-9]{64}', entry['sha256']):
        raise ValueError('Expected a SHA256 pin')
    if type(entry['bytes']) is not int or entry['bytes'] <= 0:
        raise ValueError('Expected a positive exact byte count')
    url = urllib.parse.urlsplit(entry['url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError('Expected an HTTPS URL without credentials or fragment')


def fetch(entry, directory, opener=urllib.request.urlopen):
    validate(entry)
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError('Output directory must not be a symlink')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / entry['filename']
    if target.is_symlink():
        raise ValueError('Refusing symlink output')
    if target.exists():
        if not target.is_file() or target.stat().st_size != entry['bytes'] or digest(target) != entry['sha256']:
            raise ValueError('Existing input differs; preserve it and choose another output directory')
        return target
    fd, temporary = tempfile.mkstemp(prefix='.download-', dir=directory)
    temporary = Path(temporary)
    try:
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'TitanPocket-Rebuild/1'})
        with os.fdopen(fd, 'wb') as stream, opener(request, timeout=60) as response:
            if urllib.parse.urlsplit(response.geturl()).scheme != 'https':
                raise ValueError('Refusing a non-HTTPS download redirect')
            count = 0
            h = hashlib.sha256()
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > entry['bytes']:
                    raise ValueError('Download exceeds pinned size')
                h.update(chunk)
                stream.write(chunk)
            if count != entry['bytes'] or h.hexdigest() != entry['sha256']:
                raise ValueError('Downloaded input does not match its size and SHA256')
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication refuses to overwrite a file created during download.
        os.link(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, default=ROOT / 'release/sources.json')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('names', nargs='+', help='Names from release/sources.json; no implicit downloads')
    args = p.parse_args()
    manifest = json.loads(args.manifest.read_text())
    if manifest.get('schema') != 1:
        p.error('Unsupported input manifest schema')
    unknown = set(args.names) - manifest['sources'].keys()
    if unknown:
        p.error('Unknown inputs: ' + ', '.join(sorted(unknown)))
    for name in args.names:
        path = fetch(manifest['sources'][name], args.output)
        print(f'{name}: verified {path.name}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(str(exc))
