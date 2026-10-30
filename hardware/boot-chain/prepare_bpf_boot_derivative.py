#!/usr/bin/env python3
"""Prepare an OFFLINE review candidate, never authorize or perform installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import zlib

from prepare_bpf_array_semantics import IMAGE_HASH

SOURCE_HASH = "a5d6f52db76031d255ffee71f822d470fb313812c634e756f4575187382d13bb"
STOCK_HASH = "e5dda12d7e2fc346d4c21d58380366555811fdbe3b1fac2c4316386a61ebe24b"
CAPACITY = 33554432
PATCHES = {0x15E814: (0x35000128, 0x8B284009),
           0x15E81C: (0x91024000, 0x91024120)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def align(size, page):
    return (size + page - 1) // page * page


def legacy_id(parts):
    digest = hashlib.sha1()
    # Header v2: kernel, ramdisk, second, recovery_dtbo, dtb, each with u32 size.
    for part in (parts["kernel"], parts["ramdisk"], b"", b"", parts["dtb"]):
        digest.update(part)
        digest.update(struct.pack("<I", len(part)))
    return digest.digest() + bytes(12)


def parse_boot(data):
    require(1660 <= len(data) <= CAPACITY, "Boot size out of bounds")
    require(data[:8] == b"ANDROID!", "Not an Android boot image")
    k, _, r, _, second, _, _, page, version, _ = struct.unpack_from("<10I", data, 8)
    recovery, recovery_offset, header_size = struct.unpack_from("<IQI", data, 1632)
    require(version == 2 and page == 2048 and header_size == 1660,
            "Only observed header v2 / 2048-byte pages supported")
    require(second == recovery == recovery_offset == 0, "Unsupported extra boot sections")
    dt = struct.unpack_from("<I", data, 1648)[0]
    require(k > 0 and r > 0 and dt > 0, "Missing required section")
    require(data[-64:-60] == b"AVBf", "Missing AVB footer")
    major, minor, original, vb_offset, vb_size = struct.unpack_from(">IIQQQ", data, len(data) - 60)
    require((major, minor) == (1, 0), "Unsupported AVB footer version")
    offsets = {"kernel": page, "ramdisk": page + align(k, page)}
    offsets["dtb"] = offsets["ramdisk"] + align(r, page)
    end = offsets["dtb"] + align(dt, page)
    require(end == original == vb_offset and vb_size >= 256,
            "Unsupported AVB placement or section bounds")
    require(vb_offset + vb_size <= len(data) - 64, "VBMeta out of bounds")
    parts = {name: data[offsets[name]:offsets[name] + size]
             for name, size in (("kernel", k), ("ramdisk", r), ("dtb", dt))}
    for name, part in parts.items():
        stop = offsets[name] + len(part)
        require(not any(data[stop:align(stop, page)]), "Nonzero section padding")
    require(not any(data[1660:page]), "Nonzero header padding")
    require(not any(data[vb_offset + vb_size:-64]), "Nonzero trailing padding")
    require(data[vb_offset:vb_offset + 4] == b"AVB0", "Invalid VBMeta magic")
    require(data[576:608] == legacy_id(parts), "Source legacy header ID mismatch")
    return {"parts": parts, "offsets": offsets, "page": page,
            "vb_offset": vb_offset, "vb_size": vb_size,
            "vbmeta": data[vb_offset:vb_offset + vb_size], "end": end}


def unpack_kernel(blob):
    require(blob[:4] == b"\x1f\x8b\x08\x00", "Only gzip without optional fields supported")
    decoder = zlib.decompressobj(31)
    image = decoder.decompress(blob, CAPACITY + 1)
    require(len(image) <= CAPACITY and decoder.eof and not decoder.unconsumed_tail,
            "Invalid, truncated or oversized gzip Image")
    return image, decoder.unused_data, len(blob) - len(decoder.unused_data)


def patch_image(image):
    require(sha(image) == IMAGE_HASH, "Unexpected full kernel Image hash")
    patched = bytearray(image)
    for offset, (old, new) in PATCHES.items():
        require(offset + 4 <= len(image), "Instruction out of bounds")
        require(struct.unpack_from("<I", image, offset)[0] == old,
                "Unexpected original instruction")
        struct.pack_into("<I", patched, offset, new)
    return bytes(patched)


def compress_kernel(blob, image):
    _, tail, _ = unpack_kernel(blob)
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = (blob[:10] + compressor.compress(image) + compressor.flush()
              + struct.pack("<II", zlib.crc32(image), len(image)))
    return stream + tail, len(stream)


def repack(source, kernel):
    before = parse_boot(source)
    parts = dict(before["parts"], kernel=kernel)
    page = before["page"]
    output = bytearray(source[:page])
    struct.pack_into("<I", output, 8, len(kernel))
    output[576:608] = legacy_id(parts)
    for name in ("kernel", "ramdisk", "dtb"):
        output.extend(parts[name])
        output.extend(bytes(align(len(output), page) - len(output)))
    vb_offset = len(output)
    output.extend(before["vbmeta"])
    require(len(output) <= len(source) - 64, "Repacked image exceeds partition capacity")
    output.extend(bytes(len(source) - 64 - len(output)))
    footer = bytearray(source[-64:])
    struct.pack_into(">QQ", footer, 12, vb_offset, vb_offset)
    output.extend(footer)
    after = parse_boot(output)
    require(after["parts"]["ramdisk"] == before["parts"]["ramdisk"]
            and after["parts"]["dtb"] == before["parts"]["dtb"]
            and after["vbmeta"] == before["vbmeta"], "Unrelated payload changed")
    expected_header = bytearray(source[:page])
    expected_header[8:12] = output[8:12]
    expected_header[576:608] = output[576:608]
    require(output[:page] == expected_header, "Unrelated header changed")
    return bytes(output), before, after


def branch_targets(image):
    hits = []
    low, high = min(PATCHES), max(PATCHES) + 4
    for offset in range(0, len(image) - 3, 4):
        word = struct.unpack_from("<I", image, offset)[0]
        bits = None
        if word & 0x7C000000 == 0x14000000:  # B, BL
            bits, immediate = 26, word & 0x3FFFFFF
        elif word & 0xFF000010 == 0x54000000 or word & 0x7E000000 == 0x34000000:
            bits, immediate = 19, (word >> 5) & 0x7FFFF  # B.cond, CBZ/CBNZ
        elif word & 0x7E000000 == 0x36000000:
            bits, immediate = 14, (word >> 5) & 0x3FFF  # TBZ/TBNZ
        if bits:
            signed = immediate - (1 << bits) if immediate & (1 << (bits - 1)) else immediate
            target = offset + signed * 4
            if low <= target < high:
                hits.append({"from": hex(offset), "to": hex(target), "word": hex(word)})
    return hits


def check_output_path(output):
    output = Path(os.path.abspath(output))
    for part in (output, *output.parents):
        require(not part.is_symlink(), "Symlink output or ancestor refused")
    repo = Path(__file__).resolve().parents[3]
    require(not output.is_relative_to(repo), "Private artifacts must remain outside repository")
    require(not output.exists(), "Output already exists; refusing overwrite")
    require(output.parent.is_dir(), "Output parent must already exist")
    return output


def read_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= CAPACITY,
                "Input must be a bounded regular file")
        data = handle.read(CAPACITY + 1)
        require(len(data) == info.st_size, "Input size changed during read")
        return data


def generate(source_path, stock_path, output):
    output = check_output_path(output)
    source, stock = read_input(source_path), read_input(stock_path)
    require(sha(source) == SOURCE_HASH, "Unexpected installed Magisk source hash")
    require(sha(stock) == STOCK_HASH, "Unexpected stock source hash")
    source_info, stock_info = parse_boot(source), parse_boot(stock)
    require(source_info["parts"]["kernel"] == stock_info["parts"]["kernel"],
            "Installed and stock kernel blobs differ")
    blob = source_info["parts"]["kernel"]
    image, tail, source_stream_size = unpack_kernel(blob)
    patched = patch_image(image)
    kernel, stream_size = compress_kernel(blob, patched)
    decoded, new_tail, _ = unpack_kernel(kernel)
    require(decoded == patched and new_tail == tail, "Kernel roundtrip mismatch")
    gzip = shutil.which("gzip")
    require(gzip is not None, "Independent gzip implementation is required")
    independent = subprocess.run([gzip, "-dc"], input=kernel[:stream_size],
                                 capture_output=True, check=True, timeout=60).stdout
    require(independent == patched, "Independent gzip decoding mismatch")
    candidate, before, after = repack(source, kernel)
    byte_changes = [{"offset": hex(i), "old": a, "new": b}
                    for i, (a, b) in enumerate(zip(image, patched)) if a != b]
    allowed = {offset + n for offset in PATCHES for n in range(4)}
    require(len(image) == len(patched) and all(int(x["offset"], 16) in allowed for x in byte_changes),
            "Image changed outside two instruction words")
    report = {
        "scope": "OFFLINE local review candidate only; not bootability or installation authorization",
        "source_sha256": sha(source), "stock_sha256": sha(stock),
        "candidate_sha256": sha(candidate), "candidate_bytes": len(candidate),
        "image_sha256": sha(image), "patched_image_sha256": sha(patched),
        "image_bytes": len(image), "kernel_sha256": sha(kernel),
        "gzip": {"source_stream_bytes": source_stream_size, "new_stream_bytes": stream_size,
                 "preserved_header_hex": blob[:10].hex(), "preserved_appended_tail_bytes": len(tail),
                 "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION, "level": 9,
                 "verification": "Python zlib and installed gzip -dc agree"},
        "instruction_changes": {hex(k): {"old": hex(v[0]), "new": hex(v[1])} for k, v in PATCHES.items()},
        "actual_changed_image_bytes": byte_changes,
        "sections": {name: {"source_offset": before["offsets"][name],
                            "candidate_offset": after["offsets"][name],
                            "source_bytes": len(before["parts"][name]),
                            "candidate_bytes": len(after["parts"][name]),
                            "payload_unchanged": before["parts"][name] == after["parts"][name],
                            "source_sha256": sha(before["parts"][name]),
                            "candidate_sha256": sha(after["parts"][name])}
                     for name in ("kernel", "ramdisk", "dtb")},
        "vbmeta": {"source_offset": before["vb_offset"], "candidate_offset": after["vb_offset"],
                   "bytes": before["vb_size"], "sha256": sha(before["vbmeta"]), "payload_unchanged": True},
        "container_changes": ["kernel size", "v2 legacy SHA-1 ID", "recompressed kernel",
                              "relocated ramdisk, boot DTB and VBMeta", "zero padding lengths",
                              "AVB footer original_image_size and vbmeta_offset"],
        "legacy_id_hex": candidate[576:608].hex(),
        "direct_branch_targets_into_window": branch_targets(image),
        "branch_scan_limit": "Aligned AArch64 decoding heuristic across entire Image, including data; not proof of code boundaries or indirect branches",
        "remaining_risks": ["LK acceptance of newly compressed stream is unresolved",
                            "Preserved stock VBMeta descriptor/signature is stale: source ramdisk was already changed; kernel is now changed too",
                            "No AVB repair/signing performed; internally valid verified boot is not established",
                            "Host semantics do not establish allocator, overflow, concurrency, per-CPU or phone runtime safety"],
    }
    # Exclusive directory creation and dirfd writes refuse overwrite and symlink artifacts.
    output.mkdir(mode=0o700)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        artifacts = {"boot-review-candidate.bin": candidate, "Image.patched": patched,
                     "kernel.patched.gz-tail": kernel,
                     "patched-window.bin": patched[0x15E7A8:0x15E868]}
        objdump = shutil.which("aarch64-linux-gnu-objdump")
        for name, data in artifacts.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        if objdump:
            result = subprocess.run([objdump, "-D", "-b", "binary", "-m", "aarch64",
                                    "--adjust-vma=0x15e7a8", str(output / "patched-window.bin")],
                                    capture_output=True, check=True, timeout=60)
            artifacts = {"patched-window-disassembly.txt": result.stdout}
            report["disassembly"] = "Installed aarch64-linux-gnu-objdump; see patched-window-disassembly.txt"
        else:
            artifacts = {}
            report["disassembly"] = "No installed AArch64 objdump found"
        artifacts["report.json"] = (json.dumps(report, indent=2) + "\n").encode()
        for name, data in artifacts.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
    finally:
        os.close(directory)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("stock", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(args.source, args.stock, args.output), indent=2))
