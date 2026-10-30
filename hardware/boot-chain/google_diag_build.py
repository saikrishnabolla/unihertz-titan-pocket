#!/usr/bin/env python3
"""Build only the offline diagnostic prototype; never modifies an image."""
import argparse
from pathlib import Path
import subprocess


def build(output, test=False, fixture=None, real_mount=False, logcat_only=False, kernel_only=False, real_kernel=False, key_probe_trial=False):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Refusing an existing output")
    if logcat_only and kernel_only:
        raise ValueError("Choose one recorder mode")
    if key_probe_trial and (not kernel_only or fixture is not None):
        raise ValueError("The isolated key trial requires the kernel-only recorder")
    command = ["gcc", "-Os", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
               "-nostdlib", "-static", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
               "-fno-pie", "-no-pie", "-Wl,--build-id=none", "-Wl,-e,_start",
               "-Wl,-z,max-page-size=4096",
               str(Path(__file__).with_name("google_diag_snapshot.c" if fixture is None else "google_diag_exec_fixture.c")), "-o", str(output)]
    if test:
        command.insert(1, "-DGOOGLE_DIAG_TEST")
    if fixture is not None:
        command.insert(1, f"-DFIXTURE_MODE={fixture}")
    if real_mount:
        command.insert(1, "-DGOOGLE_DIAG_REAL_MOUNT")
    if logcat_only:
        command.insert(1, "-DGOOGLE_DIAG_LOGCAT_ONLY")
    if kernel_only:
        command.insert(1, "-DGOOGLE_DIAG_KERNEL_ONLY")
    if real_kernel:
        command.insert(1, "-DGOOGLE_DIAG_REAL_KERNEL")
    if key_probe_trial:
        command.insert(1, "-DGOOGLE_DIAG_KEY_PROBE_TRIAL")
    subprocess.run(command, check=True, capture_output=True, text=True)
    headers = subprocess.check_output(["readelf", "-h", "-l", "-d", str(output)], text=True)
    if "AArch64" not in headers or "INTERP" in headers or "NEEDED" in headers:
        raise ValueError("Expected standalone AArch64 ELF without interpreter/dependencies")
    return headers


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--logcat-only", action="store_true")
    parser.add_argument("--kernel-only", action="store_true")
    parser.add_argument("--key-probe-trial", action="store_true")
    args = parser.parse_args()
    print(build(args.output, args.test, logcat_only=args.logcat_only, kernel_only=args.kernel_only, key_probe_trial=args.key_probe_trial))
