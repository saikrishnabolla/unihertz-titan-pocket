#!/usr/bin/env python3
"""Read-only comparison of vendor payloads and inode metadata across two images."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
from threading import Timer

from inventory_candidate_product import parse_listing, parse_stat, quote, split_batch


def directory_entries(text):
    return parse_listing("\n".join(line for line in text.splitlines() if line != "/0/000000/0/0//0/"))


def inventory(image, output, allow_external_symlinks=False, retain_payloads=True):
    output.mkdir(mode=0o700)
    batch_number = 0

    def batch(commands):
        nonlocal batch_number
        script = "\n".join(commands) + "\n"
        result = subprocess.run(["/usr/sbin/debugfs", "-f", "/dev/stdin", str(image)], input=script, capture_output=True, text=True, timeout=120)
        stem = output / f"batch-{batch_number}"
        batch_number += 1
        stem.with_suffix(".commands").write_text(script)
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        return split_batch(commands, result.stdout, result.stderr, result.returncode)

    def stream_payload(inode, path):
        command = 'cat ' + quote(path)
        stem = output / f'cat-{inode}'
        stem.with_suffix('.commands').write_text(command + '\n')
        h = hashlib.sha256()
        size = 0
        with stem.with_suffix('.stderr').open('wb') as errors:
            with subprocess.Popen(['/usr/sbin/debugfs', '-R', command, str(image)],
                                  stdout=subprocess.PIPE, stderr=errors) as process:
                timer = Timer(120, process.kill)
                timer.start()
                try:
                    for block in iter(lambda: process.stdout.read(1024 * 1024), b''):
                        h.update(block)
                        size += len(block)
                    returncode = process.wait()
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.kill()
        split_batch([], '', stem.with_suffix('.stderr').read_text(), returncode)
        return size, h.hexdigest()

    paths = {"/"}
    pending = ["/"]
    while pending:
        current, pending = pending, []
        for parent, text in zip(current, batch(["ls -l -p " + quote(p) for p in current])):
            for entry in directory_entries(text):
                path = parent.rstrip("/") + "/" + entry["name"]
                if path in paths:
                    raise ValueError("Duplicate path")
                paths.add(path)
                if stat.S_ISDIR(int(entry["mode"], 8)):
                    pending.append(path)
    entries = {}
    paths = sorted(paths)
    for start in range(0, len(paths), 128):
        chunk = paths[start:start + 128]
        for path, text in zip(chunk, batch(["stat " + quote(p) for p in chunk])):
            info = parse_stat(text)
            flags = re.search(r"Flags:\s+(0x[0-9a-fA-F]+)", text)
            if not flags or info["type"] not in ("regular", "directory", "symlink"):
                raise ValueError("Unsupported inode")
            info["flags"] = int(flags[1], 16)
            if info["type"] == "symlink" and info["symlink_target"] is None and not allow_external_symlinks:
                raise ValueError("Non-inline symlink needs a separate reader")
            entries[path] = info
    commands = []
    data_files = {}
    external_symlinks = {}
    attrs = {}
    for path, info in entries.items():
        inode = info["inode"]
        if info["type"] == "regular" and inode not in data_files:
            if retain_payloads:
                target = output / f"data-{inode}"
                commands.append("dump " + quote(path) + " " + quote(str(target)))
                data_files[inode] = target
            else:
                data_files[inode] = path
        if info['type'] == 'symlink' and info['symlink_target'] is None:
            if not 0 < info['size'] <= 4096:
                raise ValueError('External symlink exceeds bounded target size')
            if inode not in external_symlinks:
                target = output / f'symlink-{inode}'
                commands.append('dump ' + quote(path) + ' ' + quote(str(target)))
                external_symlinks[inode] = target
        for attr in info["xattrs"]:
            name = attr["name"]
            if (inode, name) not in attrs:
                target = output / f"attr-{inode}-{name}"
                commands.append("ea_get -f " + quote(str(target)) + " " + quote(path) + " " + quote(name))
                attrs[inode, name] = target
    for start in range(0, len(commands), 128):
        batch(commands[start:start + 128])
    for info in entries.values():
        if info['type'] == 'symlink' and info['symlink_target'] is None:
            raw = external_symlinks[info['inode']].read_bytes()
            if len(raw) != info['size'] or b'\0' in raw:
                raise ValueError('External symlink length or target invalid')
            info['symlink_target'] = raw.decode('utf-8', errors='strict')
    data_hashes = {}
    for inode, path in data_files.items():
        if not retain_payloads:
            data_hashes[inode] = stream_payload(inode, path)
            continue
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        data_hashes[inode] = (path.stat().st_size, h.hexdigest())
    inode_paths = {}
    for path, info in entries.items():
        inode_paths.setdefault(info["inode"], []).append(path)
    result = {}
    for path, info in entries.items():
        item = {k: info[k] for k in ("type", "permissions", "uid", "gid", "size", "links", "symlink_target", "timestamps_debugfs", "flags")}
        item["same_inode_paths"] = sorted(inode_paths[info["inode"]])
        item["xattrs"] = {}
        for attr in info["xattrs"]:
            raw = attrs[info["inode"], attr["name"]].read_bytes()
            if len(raw) != attr["size"]:
                raise ValueError("Attribute length mismatch")
            item["xattrs"][attr["name"]] = raw.hex()
        if info["type"] == "regular":
            size, content_hash = data_hashes[info["inode"]]
            if size != info["size"]:
                raise ValueError("Payload length mismatch")
            item["sha256"] = content_hash
        result[path] = item
    (output / "inventory.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    before = inventory(args.source, args.output / "source")
    after = inventory(args.candidate, args.output / "candidate")
    report = {"source_paths": len(before), "candidate_paths": len(after), "removed": sorted(set(before) - set(after)), "added": sorted(set(after) - set(before)), "changed": {p: [k for k in before[p] if before[p][k] != after[p][k]] for p in sorted(set(before) & set(after)) if before[p] != after[p]}}
    (args.output / "comparison.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
