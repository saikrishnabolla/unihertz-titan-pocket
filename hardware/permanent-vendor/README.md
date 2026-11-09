# Permanent-install vendor recipe

This offline builder changes the pinned working guest VENDOR image for the permanent Android 17 install. It moves the userdata encryption key directory to `/metadata/vold/metadata_encryption/titan17`, preserving the other fstab settings and filesystem metadata.

The input is the already-adapted guest VENDOR, not an untouched stock image. Its required SHA256 is `a39d5c127539a7858cfc8d558da9c9eebb3e9b7992b9505ea884e89e4afbbe42`. Firmware and private signing keys are not included.

```sh
python3 build_vendor.py --source /absolute/vendor.img --key /absolute/private/vendor.pem --avbtool /absolute/avbtool.py --debugfs /absolute/debugfs --e2fsck /absolute/e2fsck --output /absolute/new-output
```

The output directory must not exist. The signing key must be a private regular file with no group or other permissions. The builder pins the tested `avbtool.py` to SHA256 `69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6`. Run without Python optimization.

By default the key must match the source image. To build an offline candidate with your own RSA-2048 key, add `--new-signing-key`. The output signature is verified against that key; properties, rollback settings and flags must stay unchanged. This option does not establish that the phone's boot chain accepts the new key. Keep the bootloader unlocked and validate the boot chain and recovery route separately; never relock with this port.

The output contains `vendor.img`, inventories, fstab comparisons, command results and `report.json`. A successful build checks exact input bytes, source and output signatures, filesystem consistency and the scope of every filesystem change. It does not flash, erase or reboot a device.

```sh
python3 -m unittest discover -s . -p 'test*.py' -v
```

Set `TITAN_VENDOR_SOURCE` to the pinned private image path to include its AVB-header integration check. A rekeyed image remains an offline candidate with phone boot and recovery unverified.

The separate top-level vbmeta helper reproduces the tested stock flags change:

```sh
python3 boot-chain/build_vbmeta.py --stock-vbmeta /absolute/stock-vbmeta.img --output /absolute/new-vbmeta.img
```

It changes only byte 123, setting flags from 0 to 3. This disables AVB verification and hashtree enforcement and invalidates the original signature. It requires an unlocked bootloader. The helper checks exact source and output hashes, creates a new file and never contacts a phone. It does not prepare BOOT or provide a clean installer.
