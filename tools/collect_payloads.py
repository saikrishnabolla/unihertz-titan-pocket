#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify and combine the rebuilt files required by the clean SYSTEM recipe."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def collect(recipe, maps, files):
    required = {entry['sha256']: entry for entry in json.loads(recipe.read_text())['files']}
    candidates = {}
    for mapping in maps:
        if mapping.is_symlink() or not mapping.is_file():
            raise ValueError('Supply a regular payload map')
        data = json.loads(mapping.read_text())
        for digest, value in data.items():
            if digest not in required:
                raise ValueError('Payload map contains a file outside the pinned recipe')
            path = Path(value)
            candidates.setdefault(digest, []).append(path if path.is_absolute() else mapping.resolve().parent / path)
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Supply regular payload files')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest not in required:
            raise ValueError('File does not match any required payload: ' + path.name)
        candidates.setdefault(digest, []).append(path)
    missing = required.keys() - candidates.keys()
    if missing:
        raise ValueError('Missing rebuilt files: ' + ', '.join(sorted(required[key]['path'] for key in missing)))
    result = {}
    for digest, paths in candidates.items():
        for path in paths:
            if path.is_symlink() or not path.is_file() or path.stat().st_size != required[digest]['size']:
                raise ValueError('Payload type or size differs')
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    raise ValueError('Payload hash differs')
        result[digest] = str(paths[0].resolve())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, default=ROOT / 'hardware/from-google/system-recipe.json')
    parser.add_argument('--map', type=Path, action='append', default=[])
    parser.add_argument('--file', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = collect(args.recipe, args.map, args.file)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print('Verified all ' + str(len(result)) + ' required SYSTEM files.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(str(error))
