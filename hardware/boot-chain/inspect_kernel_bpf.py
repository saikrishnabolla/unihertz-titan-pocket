#!/usr/bin/env python3
"""Read-only BPF evidence for the Titan Pocket stock kernel and Android 17 candidate.

Subcommands:
  kernel BOOT_IMG OUT_DIR
      Extract the kernel from an Android boot image (header v0-v2) in memory,
      hash every stage, scan for the mtk-bpf-patcher ALPS05247589 byte
      sequences, and disassemble a bounded window with aarch64 objdump.
  bpfobjs CANDIDATE_SYSTEM_IMG WORK_DIR OUT_DIR [--kver 4.14.186] [--api 3700]
      Copy the tethering APEX out of the candidate ext4 image with debugfs,
      read every BPF ELF object's .android_maps/.android_progs definitions,
      report which maps/programs pass the loader's kernel/API gates, and
      check fixed marker strings in the shipped loader and Java services.
  sources WORK_DIR OUT_DIR
      Download every pinned primary source, record sha256, and compare with a
      previous OUT_DIR/bpf-sources.json if present.
  patched WORK_DIR OUT_DIR
      Rebuild the candidate's Connectivity sources: pinned GrapheneOS base
      files plus RestlessOS patches applied with `git am` in build order.

Nothing here writes to an input image, a block device or a phone. Static
results only: they are not a BPF syscall run on the handset.
"""
import argparse
import gzip
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile

DEBUGFS = shutil.which("debugfs") or "/sbin/debugfs"
OBJDUMP = shutil.which("aarch64-linux-gnu-objdump") or shutil.which("objdump")

# mtk-bpf-patcher commit 7dfffb309347428a2bfa5eb348b55a6c790c8166,
# mtk_bpf_patcher/data/Sequences.py (ByteSequences.array_map_update_elem).
PATCHER_SEQUENCES = {
    "4.14": ("0a2450292801080a087d0a1b28010035", "0a2450292801080a087d0a1b1f2003d5"),
    "4.19": ("48010035822240b980420491e10313aa", "1f2003d5822240b980420491e10313aa"),
}
DISASM_BEFORE = 0x60
DISASM_AFTER = 0x60

BINARY_MARKERS = {
    "/bin/netbpfload": [
        "Critical kernel bug - failure to write into index 1 of 2 element bpf map array.",
        "--- DO NOT EXPECT SYSTEM TO BOOT SUCCESSFULLY ---",
        "[GSI] Android V requires kernel 4.19.",
        "ro.bpf.kver_override",
    ],
    "/javalib/service-connectivity.jar": [
        "Failed initialization BpfMaps, doing without it",
        "Failed to initialize current stats configuration",
        "persist.sys.phh.bpf_broken",
    ],
    "/javalib/framework-connectivity.jar": [
        "BPF maps are unavailable on this device; per-app network blocking (firewall) will not work.",
    ],
}

RESTLESS = "d581178058ecf2d46db8560f0cb13201a7aeffa1"
GOS_CONNECTIVITY = "6ab5be47d49a3f93d424f195958dfaadec8a906c"
GOS_FRAMEWORKS_BASE = "8304f868f2114c6a35c76e21691f3f54c3ee1c4f"
AOSP_R1 = {"frameworks/base": "94b4c163b7dfe5ce3607f7bb8456f9573f7de57d",
           "packages/modules/Connectivity": "347fbd34b368d19f0d87e908ea101eed3601a731"}
PATCHER = "7dfffb309347428a2bfa5eb348b55a6c790c8166"
GIST_REV = "304f3bd15cb10a1f5d5ac925115025a1f9dcb486"
LINUX_STABLE = "v4.14.186"

RAW_RESTLESS = f"https://raw.githubusercontent.com/cawilliamson/treble_restlessos/{RESTLESS}/"
RAW_GOS_CONN = ("https://raw.githubusercontent.com/GrapheneOS/"
                f"platform_packages_modules_Connectivity/{GOS_CONNECTIVITY}/")
RAW_GOS_FB = f"https://raw.githubusercontent.com/GrapheneOS/platform_frameworks_base/{GOS_FRAMEWORKS_BASE}/"
STABLE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/"

CONNECTIVITY_PATCHES = [
    "patches/trebledroid/platform_packages_modules_Connectivity/0001-Allow-failing-to-load-bpf-programs-for-BPF-less-devi.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0002-Support-non-working-BPF-maps-on-old-BPF-less-kernel.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0003-Bring-back-traffic-indicators-for-legacy-devices.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0004-Revert-drop-support-for-V-gsi-on-pixel-5-R-base-kern.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0005-netd-Remove-4.14-kernel-restrictions.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0006-More-bpf-errors-ignore-there-are-some-4.14-without-t.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0007-Revert-netdupdatable-add-back-abort-on-init-fail.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0008-Additional-bpf-prevent-crash.patch",
    "patches/trebledroid/platform_packages_modules_Connectivity/0009-Some-additional-handling-of-bpf-less-device.patch",
    "patches/personal/platform_packages_modules_Connectivity/0001-connectivity-tolerate-BPF-less-legacy-kernels.patch",
    "patches/personal/platform_packages_modules_Connectivity/0002-netbpfload-drop-reboot_on_failure-from-the-loader-rc.patch",
    "patches/personal/platform_packages_modules_Connectivity/0003-libeventpolling-degrade-gracefully-when-the-ringbuf-maps-m.patch",
    "patches/personal/platform_packages_modules_Connectivity/0004-bpfnetmaps-keep-system_server-up-when-lpm_trie-maps-.patch",
    "patches/personal/platform_packages_modules_Connectivity/0005-tethering-allow-the-vpn-as-the-upstream-for-tethered.patch",
]
PATCHED_FILES_OF_INTEREST = [
    "bpf/loader/NetBpfLoad.cpp",
    "bpf/netd/BpfHandler.cpp",
    "service/src/com/android/server/BpfNetMaps.java",
    "framework/src/android/net/BpfNetMapsUtils.java",
    "service-t/src/com/android/server/net/NetworkStatsService.java",
]

SOURCES = {
    "patcher_Sequences.py": f"https://raw.githubusercontent.com/R0rt1z2/mtk-bpf-patcher/{PATCHER}/mtk_bpf_patcher/data/Sequences.py",
    "patcher_main.py": f"https://raw.githubusercontent.com/R0rt1z2/mtk-bpf-patcher/{PATCHER}/mtk_bpf_patcher/main.py",
    "patcher_parser.py": f"https://raw.githubusercontent.com/R0rt1z2/mtk-bpf-patcher/{PATCHER}/mtk_bpf_patcher/utils/parser.py",
    "ALPS05247589_diff.patch": f"https://gist.githubusercontent.com/R0rt1z2/8af7735c6c3802148fa4da61b3cba506/raw/{GIST_REV}/diff.patch",
    "linux_arraymap.c": f"{STABLE}kernel/bpf/arraymap.c?h={LINUX_STABLE}",
    "linux_bpf.h": f"{STABLE}include/linux/bpf.h?h={LINUX_STABLE}",
    "linux_arm64_cache.h": f"{STABLE}arch/arm64/include/asm/cache.h?h={LINUX_STABLE}",
    "linux_helpers.c": f"{STABLE}kernel/bpf/helpers.c?h={LINUX_STABLE}",
    "restless_README.md": f"{RAW_RESTLESS}README.md",
    "restless_build.yml": f"{RAW_RESTLESS}.github/workflows/build.yml",
    "restless_apply.sh": f"{RAW_RESTLESS}patches/apply.sh",
    "restless_system_bpf_0001.patch": f"{RAW_RESTLESS}patches/personal/platform_system_bpf/0001-bpfloader-relax-kernel-version-gates-and-fatal-error.patch",
    "restless_tdroid_fb_0001_vendor_mismatch.patch": f"{RAW_RESTLESS}patches/trebledroid/platform_frameworks_base/0001-Disable-vendor-mismatch-warning.patch",
    "restless_settings_bpf_warning.patch": f"{RAW_RESTLESS}patches/rom/platform_packages_apps_Settings/0004-AppPermissionPreference-warn-when-BPF-based-firewall-is-unavailable.patch",
    "gos_manifest_2026102100.xml": "https://raw.githubusercontent.com/GrapheneOS/platform_manifest/2026102100/default.xml",
    "gos_netd.c": f"{RAW_GOS_CONN}bpf/progs/netd.c",
    "gos_netd.h": f"{RAW_GOS_CONN}bpf/progs/netd.h",
    "gos_bpf_map_def.h": f"{RAW_GOS_CONN}bpf/progs/include/bpf_map_def.h",
    "gos_BpfUtils.h": f"{RAW_GOS_CONN}bpf/headers/include/bpf/BpfUtils.h",
    "gos_PermissionMonitor.java": f"{RAW_GOS_CONN}service/src/com/android/server/connectivity/PermissionMonitor.java",
    "gos_android_os_VintfObject.cpp": f"{RAW_GOS_FB}core/jni/android_os_VintfObject.cpp",
    "gos_ActivityTaskManagerService.java": f"{RAW_GOS_FB}services/core/java/com/android/server/wm/ActivityTaskManagerService.java",
    "aosp_r1_android_os_VintfObject.cpp": ("https://android.googlesource.com/platform/frameworks/base/+/"
                                           f"{AOSP_R1['frameworks/base']}/core/jni/android_os_VintfObject.cpp?format=TEXT"),
    "aosp_r1_NetBpfLoad.cpp": ("https://android.googlesource.com/platform/packages/modules/Connectivity/+/"
                               f"{AOSP_R1['packages/modules/Connectivity']}/bpf/loader/NetBpfLoad.cpp?format=TEXT"),
}
for _p in CONNECTIVITY_PATCHES:
    SOURCES["restless_" + _p.split("/")[1] + "_conn_" + _p.rsplit("/", 1)[1][:4] + ".patch"] = RAW_RESTLESS + _p

BPF_MAP_TYPES = {1: "HASH", 2: "ARRAY", 3: "PROG_ARRAY", 4: "PERF_EVENT_ARRAY",
                 5: "PERCPU_HASH", 6: "PERCPU_ARRAY", 9: "LRU_HASH", 11: "LPM_TRIE",
                 12: "ARRAY_OF_MAPS", 13: "HASH_OF_MAPS", 14: "DEVMAP", 27: "RINGBUF",
                 30: "DEVMAP_HASH"}
MAP_DEF = struct.Struct("<IIIIIIIIiiII70s70sI")   # bpf_map_def, 192 bytes
PROG_DEF = struct.Struct("<IIIIII?3xii70s70sI")   # bpf_prog_def, 180 bytes
assert MAP_DEF.size == 192 and PROG_DEF.size == 180


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def kver(text):
    parts = [int(p) for p in text.split(".")] + [0, 0]
    return (parts[0] << 24) + (parts[1] << 16) + parts[2]


def kver_text(value):
    if value >= 0xFFFFFFFF:
        return "INF"
    return f"{value >> 24}.{(value >> 16) & 0xFF}.{value & 0xFFFF}"


def extract_kernel(boot):
    if boot[:8] != b"ANDROID!":
        raise SystemExit("not an Android boot image")
    kernel_size, = struct.unpack_from("<I", boot, 8)
    page_size, = struct.unpack_from("<I", boot, 36)
    header_version, = struct.unpack_from("<I", boot, 40)
    blob = boot[page_size:page_size + kernel_size]
    info = {"header_version": header_version, "page_size": page_size,
            "kernel_offset": page_size, "kernel_size": kernel_size,
            "kernel_blob_sha256": sha256(blob)}
    if blob[:3] == b"\x1f\x8b\x08":
        image = gzip.decompress(blob)
        info["kernel_blob_format"] = "gzip"
    else:
        image = blob
        info["kernel_blob_format"] = "raw"
    info["image_size"] = len(image)
    info["image_sha256"] = sha256(image)
    return info, image


def find_all(data, needle):
    hits, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def cmd_kernel(args):
    boot = open(args.boot_img, "rb").read()
    info, image = extract_kernel(boot)
    info = {"boot_img": os.path.abspath(args.boot_img), "boot_img_size": len(boot),
            "boot_img_sha256": sha256(boot), **info}
    version = image[image.find(b"Linux version "):][:200].split(b"\n")[0]
    info["linux_banner"] = version.decode("ascii", "replace")
    scans = {}
    for series, (unpatched, patched) in PATCHER_SEQUENCES.items():
        scans[series] = {
            "unpatched_sequence": unpatched,
            "unpatched_offsets": [hex(o) for o in find_all(image, bytes.fromhex(unpatched))],
            "patched_sequence": patched,
            "patched_offsets": [hex(o) for o in find_all(image, bytes.fromhex(patched))],
        }
    info["patcher_scan"] = scans
    os.makedirs(args.out_dir, exist_ok=True)
    hits = [int(o, 16) for s in scans.values() for o in s["unpatched_offsets"]]
    if len(hits) == 1 and OBJDUMP:
        hit = hits[0]
        start = hit - DISASM_BEFORE
        window = image[start:hit + DISASM_AFTER]
        info["disasm_window"] = {"start": hex(start), "end": hex(hit + DISASM_AFTER),
                                 "sha256": sha256(window)}
        tmp = os.path.join(args.out_dir, ".bpf-window.bin")
        with open(tmp, "wb") as f:
            f.write(window)
        try:
            out = subprocess.run([OBJDUMP, "-D", "-b", "binary", "-m", "aarch64",
                                  f"--adjust-vma={start:#x}", tmp],
                                 check=True, capture_output=True, text=True).stdout
        finally:
            os.remove(tmp)
        objdump_version = subprocess.run([OBJDUMP, "--version"], capture_output=True,
                                         text=True).stdout.splitlines()[0]
        with open(os.path.join(args.out_dir, "bpf-array-map-update-disasm.txt"), "w") as f:
            f.write(f"# {objdump_version}\n# image sha256 {info['image_sha256']}\n"
                    f"# window {start:#x}-{hit + DISASM_AFTER:#x}, pattern at {hit:#x}\n")
            f.write("\n".join(out.splitlines()[6:]) + "\n")
    with open(os.path.join(args.out_dir, "bpf-kernel-scan.json"), "w") as f:
        json.dump(info, f, indent=2)
        f.write("\n")
    print(json.dumps({k: info[k] for k in ("image_sha256", "patcher_scan")}, indent=2))


def debugfs(image, request):
    return subprocess.run([DEBUGFS, "-R", request, image], check=True,
                          capture_output=True, text=True).stdout


def walk(image, root):
    """Yield file paths below root in an ext4 image (debugfs `ls -p` format)."""
    for line in debugfs(image, f'ls -p "{root}"').splitlines():
        parts = line.strip("/").split("/")
        if len(parts) < 5 or parts[4] in (".", ".."):
            continue
        path = root.rstrip("/") + "/" + parts[4]
        if parts[1].startswith("04"):
            yield from walk(image, path)
        else:
            yield path


def elf_sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = raw[shstrndx]
    names = data[strtab[4]:strtab[4] + strtab[5]]
    sections = []
    for name_off, sh_type, _, _, off, size, link, _, _, entsize in raw:
        name = names[name_off:names.index(b"\0", name_off)].decode()
        sections.append({"name": name, "type": sh_type, "offset": off, "size": size,
                         "link": link, "entsize": entsize})
    return sections


def elf_symbols_in(data, sections, section_name):
    index = next((i for i, s in enumerate(sections) if s["name"] == section_name), None)
    if index is None:
        return {}
    symtab = next(s for s in sections if s["type"] == 2)
    strtab = sections[symtab["link"]]
    out = {}
    for i in range(symtab["size"] // 24):
        st_name, _, _, st_shndx, st_value, _ = struct.unpack_from(
            "<IBBHQQ", data, symtab["offset"] + i * 24)
        if st_shndx == index:
            start = strtab["offset"] + st_name
            out[st_value] = data[start:data.index(b"\0", start)].decode()
    return out


def parse_bpf_object(data):
    sections = elf_sections(data)
    by_name = {s["name"]: s for s in sections}
    maps, progs = [], []
    if ".android_maps" in by_name:
        sec = by_name[".android_maps"]
        names = elf_symbols_in(data, sections, ".android_maps")
        for off in range(0, sec["size"], MAP_DEF.size):
            f = MAP_DEF.unpack_from(data, sec["offset"] + off)
            maps.append({"symbol": names.get(off, f"@{off}"),
                         "type": BPF_MAP_TYPES.get(f[0], str(f[0])), "key_size": f[1],
                         "value_size": f[2], "max_entries": f[3], "min_api": f[8],
                         "max_api": f[9], "min_kver": f[10], "max_kver": f[11]})
    if ".android_progs" in by_name:
        sec = by_name[".android_progs"]
        names = elf_symbols_in(data, sections, ".android_progs")
        for off in range(0, sec["size"], PROG_DEF.size):
            f = PROG_DEF.unpack_from(data, sec["offset"] + off)
            progs.append({"symbol": names.get(off, f"@{off}"), "prog_type": f[0],
                          "min_kver": f[4], "max_kver": f[5], "optional": f[6],
                          "min_api": f[7], "max_api": f[8]})
    return maps, progs


def eligible(entry, kernel, api):
    return (entry["min_kver"] <= kernel < entry["max_kver"]
            and entry["min_api"] <= api < entry["max_api"])


def cmd_bpfobjs(args):
    kernel, api = kver(args.kver), args.api
    os.makedirs(args.work_dir, exist_ok=True)
    apex_path = os.path.join(args.work_dir, "com.android.tethering.apex")
    debugfs(args.candidate_img, f'dump /system/apex/com.android.tethering.apex "{apex_path}"')
    with zipfile.ZipFile(apex_path) as z:
        payload = z.read("apex_payload.img")
    payload_path = os.path.join(args.work_dir, "apex_payload.img")
    with open(payload_path, "wb") as f:
        f.write(payload)
    result = {"candidate_img": os.path.abspath(args.candidate_img),
              "apex_sha256": sha256(open(apex_path, "rb").read()),
              "apex_payload_sha256": sha256(payload),
              "kernel_version_assumed": args.kver, "kernel_kver": kernel,
              "api_level_full_assumed": api, "objects": {}}
    os.makedirs(args.out_dir, exist_ok=True)
    result["apex_rc"] = {}
    for rc in sorted(e for e in walk(payload_path, "/etc") if e.endswith("rc")):
        text = debugfs(payload_path, f'cat "{rc}"')
        result["apex_rc"][rc] = {"sha256": sha256(text.encode()),
                                 "reboot_on_failure": "reboot_on_failure" in text}
        with open(os.path.join(args.out_dir, "bpf-apex" + rc.replace("/", "-")), "w") as f:
            f.write(text)
    for path in sorted(e for e in walk(payload_path, "/etc/bpf") if e.endswith(".o")):
        name = path[len("/etc/bpf/"):]
        local = os.path.join(args.work_dir, name.replace("/", "_"))
        debugfs(payload_path, f'dump "{path}" "{local}"')
        data = open(local, "rb").read()
        maps, progs = parse_bpf_object(data)
        for entry in maps + progs:
            entry["eligible"] = eligible(entry, kernel, api)
            entry["kver_range"] = f"{kver_text(entry['min_kver'])}..{kver_text(entry['max_kver'])}"
        result["objects"][name] = {"sha256": sha256(data), "maps": maps, "progs": progs}
    affected = []
    for name, obj in result["objects"].items():
        for m in obj["maps"]:
            if m["eligible"] and m["type"] == "ARRAY" and m["max_entries"] > 1:
                affected.append({"object": name, "map": m["symbol"],
                                 "max_entries": m["max_entries"]})
    result["eligible_multi_entry_array_maps"] = affected
    result["binary_markers"] = {}
    for path, markers in BINARY_MARKERS.items():
        local = os.path.join(args.work_dir, os.path.basename(path))
        debugfs(payload_path, f'dump "{path}" "{local}"')
        data = open(local, "rb").read()
        if path.endswith(".jar"):
            with zipfile.ZipFile(local) as z:
                blob = b"".join(z.read(n) for n in z.namelist() if n.endswith(".dex"))
        else:
            blob = data
        result["binary_markers"][path] = {
            "sha256": sha256(data),
            "present": {m: m.encode() in blob for m in markers}}
    with open(os.path.join(args.out_dir, "bpf-candidate-objects.json"), "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    summary = {name: {"eligible_progs": [p["symbol"] for p in o["progs"] if p["eligible"]],
                      "ineligible_progs": len([p for p in o["progs"] if not p["eligible"]])}
               for name, o in result["objects"].items()}
    print(json.dumps({"eligible_multi_entry_array_maps": affected, "programs": summary},
                     indent=2))


def fetch(url):
    import base64
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "titan-pocket-evidence"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    if url.endswith("?format=TEXT"):
        data = base64.b64decode(data)
    return data


def cmd_sources(args):
    os.makedirs(args.work_dir, exist_ok=True)
    record_path = os.path.join(args.out_dir, "bpf-sources.json")
    previous = {}
    if os.path.exists(record_path):
        previous = {k: v["sha256"] for k, v in json.load(open(record_path))["files"].items()}
    files, changed = {}, []
    for name, url in sorted(SOURCES.items()):
        data = fetch(url)
        with open(os.path.join(args.work_dir, name), "wb") as f:
            f.write(data)
        digest = sha256(data)
        files[name] = {"url": url, "sha256": digest, "bytes": len(data)}
        if name in previous and previous[name] != digest:
            changed.append(name)
    record = {"pins": {"restlessos": RESTLESS, "grapheneos_connectivity": GOS_CONNECTIVITY,
                       "grapheneos_frameworks_base": GOS_FRAMEWORKS_BASE,
                       "aosp_android-17.0.0_r1": AOSP_R1, "mtk_bpf_patcher": PATCHER,
                       "alps_gist_revision": GIST_REV, "linux_stable": LINUX_STABLE},
              "files": files}
    os.makedirs(args.out_dir, exist_ok=True)
    with open(record_path, "w") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    print(json.dumps({"files": len(files), "changed_since_previous_record": changed}))
    return 1 if changed else 0


def cmd_patched(args):
    import re
    repo = os.path.join(args.work_dir, "connectivity")
    if os.path.lexists(repo):
        raise ValueError("Scratch target already exists; choose a fresh work directory")
    os.makedirs(repo)
    patches = [fetch(RAW_RESTLESS + p) for p in CONNECTIVITY_PATCHES]
    touched = sorted({m for p in patches
                      for m in re.findall(rb"^diff --git a/(\S+) ", p, re.M)})
    for rel in (t.decode() for t in touched):
        os.makedirs(os.path.join(repo, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(repo, rel), "wb") as f:
            f.write(fetch(RAW_GOS_CONN + rel))
    git = ["git", "-C", repo, "-c", "user.email=evidence@local", "-c", "user.name=evidence"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", f"GrapheneOS {GOS_CONNECTIVITY}"], check=True)
    applied = []
    for path, data in zip(CONNECTIVITY_PATCHES, patches):
        proc = subprocess.run(git + ["am", "-q"], input=data, capture_output=True)
        if proc.returncode:
            subprocess.run(git + ["am", "--abort"], capture_output=True)
            raise SystemExit(f"git am failed: {path}\n{proc.stderr.decode()}")
        applied.append({"patch": path, "sha256": sha256(data)})
    result = {"base": f"GrapheneOS/platform_packages_modules_Connectivity@{GOS_CONNECTIVITY}",
              "applied_in_order": applied, "files": {}}
    for rel in PATCHED_FILES_OF_INTEREST:
        result["files"][rel] = sha256(open(os.path.join(repo, rel), "rb").read())
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "bpf-patched-connectivity.json"), "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(f"applied {len(applied)} patches cleanly; tree at {repo}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("kernel")
    k.add_argument("boot_img")
    k.add_argument("out_dir")
    k.set_defaults(func=cmd_kernel)
    b = sub.add_parser("bpfobjs")
    b.add_argument("candidate_img")
    b.add_argument("work_dir")
    b.add_argument("out_dir")
    b.add_argument("--kver", default="4.14.186")
    b.add_argument("--api", type=int, default=3700)
    b.set_defaults(func=cmd_bpfobjs)
    s = sub.add_parser("sources")
    s.add_argument("work_dir")
    s.add_argument("out_dir")
    s.set_defaults(func=cmd_sources)
    p = sub.add_parser("patched")
    p.add_argument("work_dir")
    p.add_argument("out_dir")
    p.set_defaults(func=cmd_patched)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
