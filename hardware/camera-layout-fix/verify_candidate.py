#!/usr/bin/env python3
"""Independently check retained DEX bytes, branch disassembly and input rejection."""
from pathlib import Path
import difflib
import hashlib
import importlib.util
import json
import struct
import zlib

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch', root / 'patch_layout_dex.py')
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
original = (root / 'candidate/original.dex').read_bytes()
candidate = (root / 'candidate/patched.dex').read_bytes()
assert len(original) == len(candidate) == 1888100
changed = [i for i, (a, b) in enumerate(zip(original, candidate)) if a != b]
assert changed == list(range(8, 32)) + [663940]
assert original[663940:663944] == bytes.fromhex('37102c00')
assert candidate[663940:663944] == bytes.fromhex('34102c00')
assert struct.unpack_from('<h', candidate, 663942)[0] == 44
assert candidate[12:32] == hashlib.sha1(candidate[32:]).digest()
assert struct.unpack_from('<I', candidate, 8)[0] == zlib.adler32(candidate[12:]) & 0xffffffff
rebuilt, report = patch.patch_dex(original)
assert rebuilt == candidate
rejected = []
for name, data in [('already patched', candidate), ('wrong bytes', original[:100] + b'\0' + original[101:]), ('truncated', original[:-1])]:
    try:
        patch.patch_dex(data)
    except ValueError:
        rejected.append(name)
    else:
        raise AssertionError('Accepted ' + name)
assert len(rejected) == 3
relative = Path('com/android/camera/CaptureLayoutHelper.smali')
old = (root / 'original-smali' / relative).read_text().splitlines(keepends=True)
new = (root / 'patched-smali' / relative).read_text().splitlines(keepends=True)
diff = list(difflib.unified_diff(old, new, fromfile='original/CaptureLayoutHelper.smali', tofile='patched/CaptureLayoutHelper.smali'))
changes = [line for line in diff if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]
assert changes == ['-    if-le v0, v1, :cond_54\n', '+    if-lt v0, v1, :cond_54\n']
(root / 'instruction.diff').write_text(''.join(diff))
apk = root.parent / 'camera-layout-investigation/Camera2.apk'
assert hashlib.sha256(apk.read_bytes()).hexdigest() == patch.APK_SHA256
result = {'status': 'passed', 'checks': ['exact byte delta', 'unchanged branch target', 'DEX SHA-1', 'DEX Adler-32', 'deterministic reproduction', 'three rejected nonoriginal inputs', 'only intended disassembly instruction differs', 'original APK hash unchanged'], 'rejected_inputs': rejected, 'candidate_dex_sha256': hashlib.sha256(candidate).hexdigest(), 'phone_or_APK_test': False}
(root / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
