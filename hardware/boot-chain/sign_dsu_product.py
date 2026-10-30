#!/usr/bin/env python3
"""Sign a new host-side copy of the verified PRODUCT draft; never touches USB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


SOURCE_SHA256 = "0d4a4581e1460466478172ffe80ed33f52e3c6cf8ab9e0f171be60f57dd1af27"
SOURCE_BYTES = 654311424
PARTITION_BYTES = 671088640


def sha(path, limit=None):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        remaining = path.stat().st_size if limit is None else limit
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("Truncated input")
            h.update(block)
            remaining -= len(block)
    return h.hexdigest()


def build(source, output, key, avbtool):
    if source.stat().st_size != SOURCE_BYTES or sha(source) != SOURCE_SHA256:
        raise ValueError("Source does not match the verified PRODUCT draft")
    if not key.is_file() or key.is_symlink() or key.stat().st_mode & 0o077:
        raise ValueError("Signing key must be a private regular file")
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    commands = []

    def run(args, label):
        args = [str(x) for x in args]
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        record = {"command": args, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        commands.append(record)
        (output / (label + ".json")).write_text(json.dumps(record, indent=2))
        result.check_returncode()
        return result.stdout

    tool = ["python3", avbtool]
    settings = ["--partition_size", str(PARTITION_BYTES), "--hash_algorithm", "sha256", "--block_size", "4096", "--do_not_generate_fec"]
    maximum = int(run([*tool, "add_hashtree_footer", *settings, "--calc_max_image_size"], "capacity").strip())
    if SOURCE_BYTES > maximum:
        raise ValueError("Filesystem exceeds calculated AVB capacity")
    image = output / "product.img"
    shutil.copyfile(source, image)
    run([*tool, "add_hashtree_footer", "--image", image, "--partition_name", "product", *settings, "--algorithm", "SHA256_RSA2048", "--key", key, "--salt", SOURCE_SHA256], "sign")
    run([*tool, "verify_image", "--image", image, "--key", key], "verify")
    run([*tool, "info_image", "--image", image], "info")
    run(["/usr/sbin/e2fsck", "-fn", image], "filesystem")
    if image.stat().st_size != PARTITION_BYTES or sha(image, SOURCE_BYTES) != SOURCE_SHA256 or sha(source) != SOURCE_SHA256:
        raise ValueError("Image length, filesystem prefix or original source changed unexpectedly")
    report = {"scope": "Host-only signed PRODUCT; runtime mounting and OEM acceptance untested", "source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES, "product_sha256": sha(image), "product_bytes": PARTITION_BYTES, "maximum_filesystem_bytes": maximum, "source_and_filesystem_prefix_unchanged": True, "commands": commands}
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("source", "output", "key", "avbtool"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    report = build(args.source, args.output, args.key, args.avbtool)
    print(json.dumps({k: v for k, v in report.items() if k != "commands"}, indent=2))
