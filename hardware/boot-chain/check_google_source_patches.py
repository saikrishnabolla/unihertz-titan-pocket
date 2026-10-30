#!/usr/bin/env python3
"""Check two narrow draft hunks against pinned AOSP17 sources, without applying.

Not a build or a match to Google's QPR1 binary. VNDK snapshot/product selection
and the complete SELinux30 mapping chain are still required separately.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

CASES = [
    ("vndk30-module", "packages/modules/vndk", "bcab18ef7ad195c3452e78b2eaf9bf7e4998c171",
     "apex/Android.bp", "7835b2d43e6da416980f821c628376a2b6942a14caca52e8f033121b85ae1d8e",
     "a167ee4b86596af667dcfebaa6a790444a53f2c01cb7541a8f58f2ae52431582"),
    ("policy30-build-list", "build", "5ce6f787337d0223710bf7d4a16dbe6d2a35f777",
     "core/config.mk", "9e2410e01e7382da2984de7e3d116e0f63d0afc87bbd2ad428ed1ad2572f15dc",
     "20331de15ff76e2588e2822e1e51c528d36fd694338773e2b998f189f3c9fee2"),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(output):
    output = output.resolve()
    output.mkdir(exist_ok=False)
    patches = Path(__file__).resolve().parents[1] / "patches/google-aosp17-drafts"
    results = []
    for name, project, commit, relative, source_sha, patch_sha in CASES:
        patch = patches / (name + ".patch")
        if sha(patch.read_bytes()) != patch_sha:
            raise ValueError("Draft patch changed: " + name)
        url = f"https://android.googlesource.com/platform/{project}/+/{commit}/{relative}?format=TEXT"
        with urllib.request.urlopen(url, timeout=45) as response:
            encoded = response.read(2_000_001)
        if len(encoded) > 2_000_000:
            raise ValueError("Source response exceeds bound")
        original = base64.b64decode(encoded, validate=True)
        if sha(original) != source_sha:
            raise ValueError("Source hash mismatch: " + name)
        tree = output / name
        source = tree / relative
        source.parent.mkdir(parents=True)
        source.write_bytes(original)
        command = ["git", "apply", "--check", "--verbose", str(patch)]
        result = subprocess.run(command, cwd=tree, capture_output=True, text=True, timeout=30)
        if sha(source.read_bytes()) != source_sha:
            raise ValueError("Original source changed during check")
        results.append({"name": name, "source_url": url, "source_sha256": source_sha,
                        "patch": str(patch), "patch_sha256": patch_sha,
                        "command": command, "cwd": str(tree), "returncode": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr, "source_unchanged": True})
    report = {"baseline": "Pinned AOSP17r1 project sources; NOT established equivalent to Google QPR1 prebuilt",
              "status": "TEXT_CHECK_PASSED" if all(r["returncode"] == 0 for r in results) else "TEXT_CHECK_FAILED",
              "patches_applied": False, "build_started": False,
              "provenance": "VNDK30 additions derived from Restless d581178058ecf2d46db8560f0cb13201a7aeffa1 patch 7aadcc05b9d1e57b468ad889dc3912fb774a8358; policy list narrowed to30.0 from patch95aaad8650b769a9283074ef2defd7a763af7dcf",
              "results": results}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["status"] != "TEXT_CHECK_PASSED":
        raise RuntimeError("Draft patch check failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    check(parser.parse_args().output)
