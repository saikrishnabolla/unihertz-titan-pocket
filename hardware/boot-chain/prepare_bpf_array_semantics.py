#!/usr/bin/env python3
"""Generate a host-only ARM64 test from pinned stock instructions, never patch an image."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from inspect_kernel_bpf import extract_kernel

START = 0x15E7B4
END = 0x15E85C
IMAGE_HASH = "5c3628a044792a8d62298a54f6e471e509483373a14d9a5907e63ed50990d2e9"
CHANGES = {"original": {}, "nop": {0x15E814: 0xD503201F},
           "fixed": {0x15E814: 0x8B284009, 0x15E81C: 0x91024120}}


def generate(boot, output):
    _, image = extract_kernel(boot.read_bytes())
    if hashlib.sha256(image).hexdigest() != IMAGE_HASH:
        raise ValueError("Unexpected stock kernel")
    words = {address: struct.unpack_from("<I", image, address)[0]
             for address in range(START, END, 4)}
    if words[0x15E814] != 0x35000128 or words[0x15E81C] != 0x91024000:
        raise ValueError("Unexpected original array instructions")
    output.mkdir(mode=0o700, exist_ok=False)
    assembly = [".text", ".p2align 2"]
    for name, changes in CHANGES.items():
        assembly += [f".globl _array_{name}", f"_array_{name}:"]
        for address, word in words.items():
            assembly.append("    bl _memcpy" if address == 0x15E828
                            else f"    .inst 0x{changes.get(address, word):08x}")
    (output / "array.S").write_text("\n".join(assembly) + "\n")
    (output / "test.c").write_bytes(Path(__file__).with_name("test_bpf_array_semantics.c").read_bytes())
    report = {"scope": "Host userspace instruction experiment, not a kernel runtime or patched boot image",
              "image_sha256": IMAGE_HASH, "range": [hex(START), hex(END)],
              "relocated_call": "Only the original memcpy BL is replaced by a host linker relocation",
              "variants": {name: {hex(k): hex(v) for k, v in changes.items()}
                           for name, changes in CHANGES.items()},
              "excluded": "PERCPU_ARRAY path contains privileged TPIDR_EL1 access and is not exercised"}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("boot", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.boot, args.output)
