# Build from the Google image

These tools work on regular files. They do not flash or reboot a phone. Run commands from the repository root. Use new output directories for every build.

`clean_system.py` starts from Google's original `CP3A.260905.010` SYSTEM image, installs 35 hash-checked files and removes replaced apps and stale compiled files. It compares all 4,368 paths against the working port, including contents, ownership, permissions, links, extended attributes and timestamps. Filesystem layout and the image hash can differ from the installed image.

## Tools and inputs

Follow [the build guide](../../docs/BUILDING.md) to download and extract the pinned Google 17 and Google 13 images, prepare aapt2/avbtool, build the native library and inputflinger hooks, and rebuild the square animation. The commands below use those same directories.

The SYSTEM builders ran on an Apple Silicon Mac with Python 3.15, e2fsprogs 1.47.4, OpenJDK 17.0.21 and the pinned aapt2 9.5.0-16666295 macOS binary. DEX builds use JADX 1.5.3's complete tool JAR. The diagnostic executable and BOOT were rebuilt on Ubuntu 24.04 ARM64 with Python 3.12.3; the diagnostic uses GCC 13.3.0 (`13.3.0-6ubuntu2~24.04.1`). BOOT needs Linux ARM64 because it executes the ARM64 Magisk tools. Other host/tool versions must pass the same output hashes; they have not all been tested.

Set paths for your host. `titan_repo` must be the repository root; `titan_java` must contain `bin/java` and `bin/javac`.

```sh
mkdir -p build
export titan_repo="$PWD"
export titan_gsi="$PWD/inputs/google17/system.img"
export titan_e2fs="/opt/homebrew/opt/e2fsprogs/sbin"
export titan_java="/opt/homebrew/opt/openjdk@17"
export titan_dex="$PWD/inputs/dex-tools.jar"
export titan_aapt="$PWD/build/image-tools/aapt2"
```

Google's raw SYSTEM must be 2,072,014,848 bytes with SHA256 `e5db44e3365f9e542ee3f6d4caf88ece554a460e2987086b8bf21f6c440a25ec`. `inputs/dex-tools.jar` must hash to `05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3`. The builders reject other inputs.

## Rebuild the SYSTEM files

These builds are independent and can run in any order. Each writes a `payloads.json` mapping the output hashes to local files.

```sh
python3 hardware/from-google/build_source_edits.py \
  --source "$titan_gsi" --edits hardware/from-google/source-edits.json \
  --debugfs "$titan_e2fs/debugfs" --output build/source-edits

python3 hardware/from-google/build_services_from_google.py \
  --source "$titan_gsi" --repo "$titan_repo" --dex-tools "$titan_dex" \
  --java-home "$titan_java" --debugfs "$titan_e2fs/debugfs" --output build/services-google

python3 hardware/from-google/build_google_apex_files.py \
  --source "$titan_gsi" --debugfs "$titan_e2fs/debugfs" --output build/apex-google

python3 hardware/from-google/build_connectivity.py \
  --source "$titan_gsi" --repo "$titan_repo" --dex-tools "$titan_dex" \
  --java "$titan_java/bin/java" --debugfs "$titan_e2fs/debugfs" --output build/connectivity-google

python3 hardware/from-google/build_ui.py \
  --source "$titan_gsi" --repo "$titan_repo" --dex-tools "$titan_dex" \
  --java-home "$titan_java" --debugfs "$titan_e2fs/debugfs" \
  --aapt2 "$titan_aapt" --output build/ui-google

python3 tools/extract_vndk.py \
  --source inputs/google13/system.img --debugfs "$titan_e2fs/debugfs" --output build/vndk30
```

The source edits rebuild 16 config, policy, init and VINTF files. Services adds keyboard lights and scrolling. The APEX builds supply ART, Bluetooth and Connectivity changes for the old kernel. The UI builder rebuilds SystemUI and three resource overlays. VNDK30 comes unchanged from the pinned Google 13 donor.

### Virtualization APEX

The virtualization APEX uses EROFS in Google's image. Our kernel needs its contents in EXT4. On Linux with `fsck.erofs` available, run:

```sh
python3 hardware/from-google/build_virtualization.py \
  --source "$titan_gsi" --repo "$titan_repo" --tools "$titan_e2fs" \
  --fsck-erofs /absolute/path/to/fsck.erofs --output build/virt-google
```

For a Mac build, extract the original payload from the pinned Google image, then transfer it to a Linux ARM64 host. No retained investigation tree is needed:

```sh
mkdir -p build/virt-input
"$titan_e2fs/debugfs" -R "dump /system/apex/com.android.virt.apex build/virt-input/original.apex" "$titan_gsi"
python3 - <<'PY'
from pathlib import Path
from zipfile import ZipFile
with ZipFile('build/virt-input/original.apex') as archive:
    Path('build/virt-input/original-payload.img').write_bytes(archive.read('apex_payload.img'))
PY
```

On Linux ARM64, place `original-payload.img` in a new working directory. The verified extractor was Ubuntu's erofs-utils 1.7.1-1build2. This downloads and unpacks the package without installing it:

```sh
curl -fL https://ports.ubuntu.com/ubuntu-ports/pool/universe/e/erofs-utils/erofs-utils_1.7.1-1build2_arm64.deb -o erofs-utils.deb
printf '%s  %s\n' afc3f29f3c0ec4547c60985aa2373dc1dce3324cb3e8970f03b92c4789e74665 erofs-utils.deb | sha256sum -c -
dpkg-deb -x erofs-utils.deb erofs-tools
erofs-tools/usr/bin/fsck.erofs --extract=virt-tree original-payload.img
tar -czf virt-tree.tar.gz virt-tree
```

Copy `virt-tree.tar.gz` back to `build/virt-input/` on the Mac, then run:

```sh
tar -xzf build/virt-input/virt-tree.tar.gz -C build/virt-input
python3 hardware/from-google/build_virtualization.py \
  --source "$titan_gsi" --repo "$titan_repo" --tools "$titan_e2fs" \
  --extracted-tree build/virt-input/virt-tree --output build/virt-google
```

The builder reads metadata independently from the original EROFS image and checks the extracted paths, modes, timestamps and hardlinks. It hashes the extracted files and verifies that conversion preserves their contents. The final filesystem must also match the complete recorded hash. It preserves security xattrs in EXT4, then normalizes three recorded serialization fields: directory-hash flags, the write-stat counter and the deleted `lost+found` inode's deletion time. The EXT4 hash must match before its public AVB signature is restored.

### Diagnostic executable

On the Ubuntu ARM64 host, use a checkout of this same source revision:

```sh
mkdir -p build
python3 hardware/from-google/build_diagnostic.py \
  --gcc /usr/bin/gcc --boot-chain hardware/boot-chain --output build/diag-google
```

Copy the whole output directory to the Mac as `build/diag-google`. Its map uses absolute paths, so regenerate that map after copying:

```sh
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('build/diag-google').resolve()
file = root / 'titan-diag'
(root / 'payloads.json').write_text(json.dumps({hashlib.sha256(file.read_bytes()).hexdigest(): str(file)}, indent=2) + '\n')
PY
```

## Collect and build SYSTEM

Complete the native, hook and animation builds from [BUILDING.md](../../docs/BUILDING.md), and download the three app APKs. Run `prepare_policy_inputs.py` from the [stock VENDOR recipe](../permanent-vendor/from-stock/README.md) to rebuild the two API 30 SELinux mapping files. If you build VENDOR on another host, copy its `extracted/inputs/mapping-30.0.cil` and `mapping-30.0.compat.cil` into `build/vendor-from-stock/extracted/inputs/` on this host; keep the signed VENDOR image for later assembly. The collector requires every one of the 35 files with the expected size and hash. It rejects incomplete or conflicting maps.

Use `--map` for each builder's map and `--file` for standalone outputs. These paths use the output directories from that guide:

```sh
python3 tools/collect_payloads.py \
  --map build/source-edits/payloads.json \
  --map build/services-google/payloads.json \
  --map build/apex-google/payloads.json \
  --map build/connectivity-google/payloads.json \
  --map build/ui-google/payloads.json \
  --map build/virt-google/payloads.json \
  --map build/vndk30/payloads.json \
  --map build/diag-google/payloads.json \
  --file build/vendor-from-stock/extracted/inputs/mapping-30.0.cil \
  --file build/vendor-from-stock/extracted/inputs/mapping-30.0.compat.cil \
  --file build/native/libtitan_keyboard_surface.so \
  --file build/hooks/libinputflinger-final-hooks-v3-OFFLINE-ONLY.so \
  --file build/animation/bootanimation-titan-square-v1.zip \
  --file inputs/Camera-93.apk \
  --file inputs/ChromePublic_arm64.apk \
  --file inputs/CromiteWebView.apk \
  --output build/payloads.json

python3 hardware/from-google/clean_system.py \
  --source "$titan_gsi" --recipe hardware/from-google/system-recipe.json \
  --payloads build/payloads.json --tools "$titan_e2fs" --output build/system
```

Add `--avbtool build/image-tools/avbtool.py --key /absolute/path/to/your-private-key.pem` to sign SYSTEM. The tool verifies the image against that key and records its public-key hash. Keep private keys outside Git. A rebuilt image signed with a new key has not been tested on the phone.

A complete build from source edits, rebuilt components, pinned downloads and caller-supplied stock inputs passed the 35-file collector and the full 4,368-path SYSTEM check. Individual builders reproduced their exact recorded payload hashes. The rebuilt SYSTEM was signed and verified with a fresh key, but has not been booted on the phone. Follow the separate [stock VENDOR build](../permanent-vendor/from-stock/README.md) and assembly instructions in [BUILDING.md](../../docs/BUILDING.md) for the other images.

## Rebuild BOOT

BOOT is separate from SYSTEM. On Linux ARM64, supply the stock BOOT from your own matching firmware backup. It must be 33,554,432 bytes with SHA256 `e5dda12d7e2fc346d4c21d58380366555811fdbe3b1fac2c4316386a61ebe24b`.

Download the official Magisk 31.1 APK (10,679,283 bytes) and check it before running its included file tools:

```sh
mkdir -p inputs build
curl -fL https://github.com/topjohnwu/Magisk/releases/download/v31.1/Magisk-v31.1.apk -o inputs/Magisk-v31.1.apk
printf '%s  %s\n' 89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7 inputs/Magisk-v31.1.apk | sha256sum -c -
python3 hardware/from-google/build_boot.py \
  --stock /absolute/path/to/stock-boot.img --magisk-apk inputs/Magisk-v31.1.apk \
  --boot-chain hardware/boot-chain --output build/boot
```

The builder unpacks, patches and repacks regular files, then applies the two reviewed kernel instruction changes. It reproduced working BOOT SHA256 `c3aa2e73c3efbce4b6fe6558558d91826be868d8981f99d04242b4d0cb6876ce` offline. It does not install Magisk on the host or flash the phone. Magisk retains its GPL-3.0 license.

## Public signatures

`public_seals.py` restores the existing public APK/APEX signatures only after every rebuilt entry matches its recorded hash. AVB seals require an exact filesystem hash. ZIP seals contain container metadata, public signing blocks and public certificates. They contain no private keys or executable entry payloads. Changed entries fail validation.

The seals reproduced the exact signed bytes of Bluetooth, Connectivity and virtualization APEX files, SystemUI and three resource overlays. They do not allow signing modified code with the original key.
