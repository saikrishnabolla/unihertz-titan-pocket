#!/usr/bin/env python3
"""Read-only debugfs product inventory; no payload extraction or image writes."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess


def split_batch(commands, stdout, stderr, returncode=0):
    # debugfs returns zero for many command errors: only its version banner is safe.
    errors = [s for s in stderr.splitlines() if s and not re.fullmatch(r"debugfs \d[^\n]*", s)]
    if returncode or errors:
        raise ValueError(f"debugfs failed (exit {returncode}): {stderr}")
    sections = re.split(r"^debugfs: (.*)\n", stdout, flags=re.M)
    if sections[0].strip() or sections[1::2] != commands:
        raise ValueError("Missing or unexpected debugfs command boundary")
    return sections[2::2]


def parse_listing(text):
    entries = []
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"/(\d+)/([0-7]+)/([0-9]+)/([0-9]+)/([^/]+)/([0-9]*)/", line)
        if not match:
            raise ValueError(f"Unparsed directory line: {line!r}")
        inode, mode, uid, gid, name, size = match.groups()
        if name in (".", ".."):
            continue
        if int(inode) == 0:
            raise ValueError("Unexpected deleted directory entry")
        entries.append(dict(inode=int(inode), mode=mode, uid=int(uid), gid=int(gid),
                            name=name, listed_size=int(size) if size else None))
    if not text.strip():
        raise ValueError("Empty debugfs output is not proof of an empty directory")
    return entries


def parse_stat(text):
    def required(pattern):
        match = re.search(pattern, text, re.M)
        if not match:
            raise ValueError(f"Missing stat field: {pattern}")
        return match
    first = required(r"^Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)")
    owner = required(r"^User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)$")
    links = required(r"^Links:\s+(\d+)\s+Blockcount:\s+(\d+)")
    target = re.search(r'^Fast link dest: "(.*)"$', text, re.M)
    attrs = []
    in_attributes = False
    for line in text.splitlines():
        if line == "Extended attributes:":
            in_attributes = True
            continue
        candidate = line.startswith("  ") and " (" in line
        if not candidate and not (in_attributes and line.startswith("  ")):
            in_attributes = False
            continue
        match = re.fullmatch(r"  ([\w.]+) \((\d+)\)(?: = (.*))?", line)
        if not match or any(attr["name"] == match[1] for attr in attrs):
            raise ValueError(f"Unsupported or duplicate xattr line: {line!r}")
        attrs.append(dict(name=match[1], size=int(match[2]), debugfs_value=match[3]))
    return dict(inode=int(first[1]), type=first[2], permissions=first[3],
                uid=int(owner[1]), gid=int(owner[2]), size=int(owner[3]),
                links=int(links[1]), allocated_512_blocks=int(links[2]),
                symlink_target=target[1] if target else None, xattrs=attrs,
                timestamps_debugfs=re.findall(r"^\s*((?:[acm]time|crtime):[^\n]*)$", text, re.M))


def quote(path):
    if any(c in path for c in '\\"\n\r'):
        raise ValueError(f"Unsupported debugfs path spelling: {path!r}")
    return '"' + path + '"'


def inventory(image, output, debugfs):
    output.mkdir(parents=True, exist_ok=True)
    before = image.stat()
    batches = []

    def batch(commands):
        index = len(batches)
        stem = output / f"product-layout-batch-{index:03}"
        script = "\n".join(commands) + "\n"
        stem.with_suffix(".commands").write_text(script)
        argv = [debugfs, "-f", "/dev/stdin", str(image)]
        result = subprocess.run(argv, input=script, capture_output=True, text=True, timeout=120)
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        batches.append(dict(argv=argv, commands_file=stem.with_suffix(".commands").name,
                            returncode=result.returncode))
        return split_batch(commands, result.stdout, result.stderr, result.returncode)

    root = "/system/product"
    special_paths = ["/product", "/system", root]
    special = dict(zip(special_paths, map(parse_stat, batch(["stat " + quote(p) for p in special_paths]))))
    entries = {root: special[root]}
    pending = [root]
    listings = {}
    while pending:
        current, pending = pending, []
        for parent, text in zip(current, batch(["ls -l -p " + quote(p) for p in current])):
            for entry in parse_listing(text):
                path = parent + "/" + entry["name"]
                listings[path] = entry
                if stat.S_ISDIR(int(entry["mode"], 8)):
                    pending.append(path)
    paths = sorted(listings)
    for start in range(0, len(paths), 128):
        chunk = paths[start:start + 128]
        for path, text in zip(chunk, batch(["stat " + quote(p) for p in chunk])):
            value = parse_stat(text)
            listed = listings[path]
            if any(value[k] != listed[k] for k in ("inode", "uid", "gid")):
                raise ValueError(f"stat/list mismatch: {path}")
            expected_type = {stat.S_IFREG: "regular", stat.S_IFDIR: "directory", stat.S_IFLNK: "symlink"}.get(
                stat.S_IFMT(int(listed["mode"], 8)))
            if (value["type"] != expected_type or
                    int(value["permissions"], 8) != stat.S_IMODE(int(listed["mode"], 8)) or
                    (listed["listed_size"] is not None and value["size"] != listed["listed_size"])):
                raise ValueError(f"Unsupported type or stat/list mode/size mismatch: {path}")
            if value["type"] == "symlink" and value["symlink_target"] is None:
                raise ValueError(f"Non-inline symlink requires explicit bounded read: {path}")
            entries[path] = value
    unique = {v["inode"]: v for v in entries.values()}
    regular = [v for v in entries.values() if v["type"] == "regular"]
    unique_regular = [v for v in unique.values() if v["type"] == "regular"]
    inode_paths = defaultdict(list)
    for path, value in entries.items():
        inode_paths[value["inode"]].append(path)
    critical = ["etc/build.prop", "etc/selinux", "etc/permissions", "etc/sysconfig", "etc/vintf",
                "etc/init", "etc/fs_config_dirs", "etc/fs_config_files", "app", "priv-app", "overlay",
                "lib64", "bin", "apex", "framework"]
    candidate_size, vendor, super_size, product = before.st_size, 452378624, 4831838208, 640 * 1024**2
    rounded = sum((v["size"] + 4095) // 4096 * 4096 for v in unique_regular)
    reserve = {"filesystem_metadata_and_xattrs": 32 * 1024**2,
               "journal": 32 * 1024**2, "avb_hashtree_fec_footer": 16 * 1024**2}
    after = image.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Image identity/size/mtime changed during inventory")
    refs = {}
    for name in ("candidate-manifest.json", "partitions.json", "fstab.mt6771"):
        source = output / name
        refs[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    report = dict(image=str(image), image_size=before.st_size, image_inode=before.st_ino,
                  image_mtime_ns=before.st_mtime_ns, image_hash_note="No full hash scan; use referenced existing verified manifest.",
                  source_references_sha256=refs, batches=batches, special_paths=special,
                  counts=dict(Counter(v["type"] for v in entries.values())), unique_inodes=len(unique),
                  all_inode_logical_bytes_unique_inode=sum(v["size"] for v in unique.values()),
                  regular_logical_bytes_per_path=sum(v["size"] for v in regular),
                  regular_logical_bytes_unique_inode=sum(v["size"] for v in unique_regular),
                  regular_4k_rounded_bytes_unique_inode=rounded,
                  source_allocated_bytes_unique_inode=sum(v["allocated_512_blocks"] * 512 for v in unique.values()),
                  hardlinked_paths={str(i): p for i, p in inode_paths.items() if len(p) > 1},
                  regular_inodes_with_external_links={str(i): inode_paths[i] for i, v in unique.items()
                                                     if v["type"] == "regular" and v["links"] > len(inode_paths[i])},
                  xattr_names=dict(Counter(a["name"] for v in unique.values() for a in v["xattrs"])),
                  critical_paths={root + "/" + p: entries.get(root + "/" + p) for p in critical},
                  capacity=dict(candidate_system_bytes=candidate_size, unchanged_stock_vendor_bytes=vendor,
                                super_bytes=super_size, proposed_product_bytes=product,
                                partition_sum_bytes=candidate_size + vendor + product,
                                super_remaining_before_lp_metadata_alignment=super_size-candidate_size-vendor-product,
                                product_rounded_regular_bytes=rounded, assumed_reserves_bytes=reserve,
                                product_remaining_after_assumed_reserves=product-rounded-sum(reserve.values()),
                                status="Arithmetic budget only; reserves are assumptions, not a packed ext4/AVB/LP proof."),
                  entries=entries)
    (output / "product-layout-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--debugfs", default="/usr/sbin/debugfs")
    args = parser.parse_args()
    result = inventory(args.image, args.output, args.debugfs)
    print(json.dumps({k: result[k] for k in ("counts", "unique_inodes", "regular_logical_bytes_unique_inode", "capacity")}, indent=2))
