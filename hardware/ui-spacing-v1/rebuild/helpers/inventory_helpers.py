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

