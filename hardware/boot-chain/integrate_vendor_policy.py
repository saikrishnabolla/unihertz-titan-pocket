#!/usr/bin/env python3
"""Replace four policy payloads on a new offline copy of the keyboard draft."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from compare_vendor_trees import inventory
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA = "7a0e59ff61e0c5da1c1f9dab2e2042d85eb0e0ea1f02df920e6b4d012d0b46c3"
POLICY_SHA = "0cbb089506fb71e38af243ca3c861082ce5e006514db18301697871c9b53138f"
IDENTIFIERS = {
    "plat": "c8d48177da138400906ae4bcd0fcb327707be8d7bcd499d0b6835bdecceb09d6",
    "system_ext": "331b1a87aa08a609e1b5763d9286b4df2635e9a7ba521b15b36d9ca908ec6384",
    "product": "75a11da44c802486bc6f65640aa48a730f0f684c5c07a42ba3cd1735eb3fb070",
}
PREFIX = "/etc/selinux/precompiled_sepolicy"


def restore_metadata(path, item, output):
    if item["type"] != "regular" or item["links"] != 1 or item["same_inode_paths"] != [path]:
        raise ValueError("Replacement must be an unshared regular file")
    fields = [("uid", item["uid"]), ("gid", item["gid"]),
              ("mode", "010" + item["permissions"]), ("flags", item["flags"])]
    if len(item["timestamps_debugfs"]) != 4:
        raise ValueError("Incomplete timestamps")
    for timestamp in item["timestamps_debugfs"]:
        match = re.fullmatch(r"(ctime|atime|mtime|crtime): (0x[0-9a-f]{8}):([0-9a-f]{8}) -- .+", timestamp)
        if not match:
            raise ValueError("Unsupported timestamp")
        fields.extend([(match[1], match[2]), (match[1] + "_extra", "0x" + match[3])])
    commands = [f"set_inode_field {quote(path)} {key} {value}" for key, value in fields]
    for name, value in item["xattrs"].items():
        payload = output / (Path(path).name + "." + name)
        payload.write_bytes(bytes.fromhex(value))
        commands.append("ea_set -f " + quote(str(payload)) + " " + quote(path) + " " + quote(name))
    return commands


def build(source, policy, output):
    for path, expected in [(source, SOURCE_SHA), (policy, POLICY_SHA)]:
        if path.is_symlink() or not path.is_file() or sha(path) != expected:
            raise ValueError("Input does not match the verified artifact")
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    before = inventory(source, output / "before")
    image = output / "vendor.ext4"
    shutil.copyfile(source, image)
    replacements = {PREFIX: policy}
    for name, identifier in IDENTIFIERS.items():
        payload = output / (name + ".sha256")
        payload.write_text(identifier + "\n")
        replacements[PREFIX + "." + name + "_sepolicy_and_mapping.sha256"] = payload
    commands = []
    for path, payload in replacements.items():
        commands.extend(["rm " + quote(path), "write " + quote(str(payload)) + " " + quote(path)])
        commands.extend(restore_metadata(path, before[path], output))
    script = "\n".join(commands) + "\n"
    (output / "commands.debugfs").write_text(script)
    result = subprocess.run(["/usr/sbin/debugfs", "-w", "-f", "/dev/stdin", str(image)],
                            input=script, capture_output=True, text=True, timeout=120)
    (output / "debugfs.stdout").write_text(result.stdout)
    (output / "debugfs.stderr").write_text(result.stderr)
    split_batch(commands, result.stdout, result.stderr, result.returncode)
    check = subprocess.run(["/usr/sbin/e2fsck", "-fn", str(image)], capture_output=True, text=True, timeout=120)
    (output / "e2fsck.txt").write_text(check.stdout + check.stderr)
    check.check_returncode()
    after = inventory(image, output / "after")
    if before.keys() != after.keys():
        raise ValueError("Unexpected path change")
    expected = json.loads(json.dumps(before))
    for path, payload in replacements.items():
        expected[path].update(size=payload.stat().st_size, sha256=sha(payload))
    if after != expected:
        raise ValueError("Unexpected file content or metadata change")
    if sha(source) != SOURCE_SHA or sha(policy) != POLICY_SHA:
        raise ValueError("Original input changed")
    report = {"scope": "Offline unsigned guest VENDOR; no device access or kernel acceptance proof",
              "source_sha256": SOURCE_SHA, "policy_sha256": POLICY_SHA,
              "image_sha256": sha(image), "image_bytes": image.stat().st_size,
              "changed_payloads": sorted(replacements), "all_other_payloads_and_inventoried_logical_metadata_unchanged": True,
              "original_inputs_unchanged": True, "filesystem_check_exit": check.returncode,
              "security_tradeoff": "NLMSG message-type filters removed; coarser legacy netlink authorization remains"}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("source", "policy", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source.absolute(), args.policy.absolute(), args.output.absolute()), indent=2))
