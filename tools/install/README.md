# Installation input checks and SUPER updates

`plan_install.py` verifies local installation inputs and can inspect one explicitly selected device. `execute_update.py` can write only SUPER on an existing installation after repeating those checks. The planner has no flash, erase, reboot, unlock or restore command. Passing its checks does not establish that an image is bootable or that installation is safe.

Run these commands from the repository root. Copy `tools/install/install-manifest.example.json`, fill in the hashes, and supply the files at the listed paths. Paths are relative to that JSON file; absolute paths, traversal and symlinks are rejected. For a gzip backup, `bytes` and `sha256` describe its decompressed contents. The candidate SUPER must be raw and exactly 4,831,838,208 bytes. Protected partition backup sizes are pinned to the tested Titan Pocket layout.

```sh
python3 tools/install/plan_install.py plan --manifest private/install-manifest.json --output private/install-plan.json
```

The default `update` plan proposes only a SUPER write. A `clean` plan also proposes userdata erasure and requires `--allow-userdata-erase`. That option acknowledges data loss in the plan; the tool still performs no write or erase.

Read-only device checks are a separate command. Supply your serial privately; it is recorded only as a SHA256 identity:

```sh
python3 tools/install/plan_install.py preflight --manifest private/install-manifest.json --output private/adb-preflight.json --transport adb --adb /absolute/path/to/adb --serial YOUR_DEVICE_SERIAL --root-helper /system_ext/bin/su
python3 tools/install/plan_install.py preflight --manifest private/install-manifest.json --output private/fastboot-preflight.json --transport fastboot --fastboot /absolute/path/to/fastboot --serial YOUR_DEVICE_SERIAL
```

ADB preflight requires boot-completed Android, the Titan Pocket/MT6771 hardware identifiers, an unlocked bootloader, and matching live BOOT/recovery/vbmeta hashes, all protected backup hashes and a live SUPER hash equal to the rollback image. Update mode also requires the September build outside DSU. The optional root helper supports the existing port's root binary only. Fastboot preflight checks physical bootloader mode, the exact product, unlocked state, non-A/B layout and partition sizes. Neither command changes device mode; enter the required mode yourself.

Use a fresh output filename each time. Records are created with mode 600. Keep manifests, backups and results private: calibration data and hashes belong to your phone. Remaining checks are listed in each result. In particular, the tool does not prove the recovery-button route or hardware behavior.

Run the host-only tests with:

```sh
python3 -m unittest discover -s tools/install -p 'test_*.py' -v
```

Tests use small real byte fixtures and fake ADB/fastboot executables. The production CLI has no size override.

## Execute an update

This executor supports only an `update` plan. It does not perform the initial clean installation, erase userdata or install a boot chain. First run the rooted ADB preflight above and verify your manual recovery route. Its receipt must be less than one hour old and match this plan, device identity, build and baseline. Live SUPER and every protected backup must match before execution is allowed. Keep the matching rollback SUPER and protected backups outside the working image directory.

Enter the physical bootloader yourself. The following command rehashes every planned input, requires an exact match with the saved offline plan, runs a fresh fastboot preflight bound to the explicit serial, then rehashes the candidate again before writing SUPER:

```sh
python3 tools/install/execute_update.py --manifest private/install-manifest.json --plan private/install-plan.json --adb-preflight private/adb-preflight.json --journal private/update-journal.json --fastboot /absolute/path/to/fastboot --serial YOUR_DEVICE_SERIAL
```

The journal must be a new file. It uses mode 600 and records the serial only as a SHA256 identity. Success means fastboot returned success; it does not mean Android booted or the write passed readback. No reboot occurs. A failure stops execution and records unknown device state if a write began. The tool never attempts rollback or writes BOOT, recovery, vbmeta, calibration or bootloader partitions.

After a successful write, reboot manually when ready:

```sh
/absolute/path/to/fastboot -s YOUR_DEVICE_SERIAL reboot
```

After Android starts and USB debugging is available, read back SUPER using the port's existing root helper:

```sh
/absolute/path/to/adb -s YOUR_DEVICE_SERIAL shell "/system_ext/bin/su -c 'sha256sum /dev/block/by-name/super'"
```

Compare the result with the candidate SUPER SHA256 in your manifest. Check the Android build with `adb -s YOUR_DEVICE_SERIAL shell getprop ro.build.id` and compare rooted readback hashes for BOOT/recovery/vbmeta with `expected_partitions`. Do not reuse the old preflight manifest for this check: it expects the previous rollback SUPER. A mismatch needs investigation; writable partitions inside SUPER can change after boot. A hash match alone does not verify the camera, radio or other hardware.

If recovery is needed, use the proven button route to Android Recovery, then choose **Reboot to bootloader**. Prepare a raw rollback image from your verified backup; for gzip, decompress it and check its byte count and SHA256 against `rollback_super` first. The manual SUPER restoration command is:

```sh
/absolute/path/to/fastboot -s YOUR_DEVICE_SERIAL flash super /absolute/path/to/verified-rollback-super.img
```

This restores only SUPER. It is not a full factory restoration. Keep the device in the bootloader if the restore fails; do not erase or overwrite protected partitions to bypass an error. The public update executor has host-only fake-tool coverage. Neither this executor nor the documented recovery command has been run on a phone.

Run the test command above from the repository root. The executor tests check changed plans/images, failed preflight, failed flash and the absence of reboot or automatic rollback.
