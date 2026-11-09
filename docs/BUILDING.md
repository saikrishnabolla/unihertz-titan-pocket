# Building and reading the Titan Pocket port

Run the commands in this guide from the repository root unless a step says otherwise. Build and test commands do not flash or reboot a phone. Input acquisition commands download from the pinned upstream sources.

## Get the source

```sh
git clone https://github.com/saikrishnabolla/unihertz-titan-pocket.git
cd unihertz-titan-pocket
```

The code targets the Titan Pocket and the September Android 17 preview `CP3A.260905.010`. Matching an Android version alone is insufficient: the patchers check exact input hashes and depend on that build's internal interfaces.

For stock-derived builds, supply the `Titan_pocket_20220928` stock SUPER as a raw image or gzip backup, plus the separately saved stock BOOT and vbmeta images. Extract SYSTEM and VENDOR locally:

```sh
mkdir -p private
python3 tools/extract_stock.py --super /absolute/path/to/stock-super.img.gz --output private/stock-images
```

The output directory must be new. The extractor checks the exact stock SUPER hash and partition layout, then verifies both extracted images. Keep the backup and extracted images private; the repository supplies no stock firmware or device calibration data.

Download and extract the two pinned Google images used by the recipes:

```sh
python3 tools/fetch_inputs.py --output inputs/downloads google-gsi google13-donor
python3 tools/extract_gsi.py --name google-gsi --source inputs/downloads/aosp-arm64-CP3A.260905.010.zip --output inputs/google17
python3 tools/extract_gsi.py --name google13-donor --source inputs/downloads/aosp-arm64-TQ3A.230805.001.A3.zip --output inputs/google13
```

Each extractor checks the archive and extracted SYSTEM hashes, and creates only `system.img` and a report. Use new output directories.



## How to read the repo

| Path | Read it for |
|---|---|
| `native/` | Keyboard-surface scrolling, input ownership and native runtime checks. |
| `services/` | Android input-service session state and framework smali patches, including the first-unlock fix. |
| `hooks/` | Patching the pinned inputflinger library. It rebuilds the exact hook library recorded in the installed port. A standalone component is not a flashable image. |
| `tests/`, `tools/test*.py` | Host tests and the runtime fixture. Android runtime originals are substituted in the host fixture. |
| `hardware/README.md` | A map of hardware changes and historical builders. |
| `hardware/base-apps/` | The final app-layer recipe on top of an already-patched SYSTEM. |
| `private-inputs.example.json` | Required compiler settings, header trees and hash-pinned Android link libraries for the native build. |
| `verification.json` | Recorded build checks and phone observations, including their limits. |
| `source-manifest.json` | SHA256 inventory of published source files. It does not supply the private build inputs. |
| `THIRD_PARTY.md` | Retained notices and licensing limits. |

Start with the host tests if you want to change the scrolling logic. Read the relevant hardware builder and its manifest before trying to reproduce a hardware change. Directory names such as `v1` and `rebuild-v2` record stages of the work, not an installation order.

## Run the host tests

You need Python 3, a C++20 Clang compiler with AddressSanitizer/UndefinedBehaviorSanitizer and ThreadSanitizer support, and JDK 17. Check that the tools are available:

```sh
python3 --version
clang++ --version
javac -version
java -version
```

On macOS, the `java` command can exist even when no JDK is installed. `javac -version` must succeed. Compiler sanitizer support depends on the host toolchain.

```sh
python3 tools/test.py --output build/core
python3 tools/test.py --output build/core-tsan --sanitizer thread
python3 tools/test_keyguard.py --output build/keyguard
```

The core runner compiles and executes native owner/inventory tests and Java session-state tests. A successful run ends with `Core tests passed.` The keyguard test runs both the old and corrected extracted smali control flow: failures in the old fixture are expected, while the corrected fixture must pass. It writes `build/keyguard/results.json`.

Use separate output directories for sanitizer variants. The core runner accepts `--cxx`, `--javac` and `--java` for tools outside PATH; the keyguard runner accepts `--javac` and `--java`. Missing JDK/compiler support is a host setup failure, not a phone result.

These tests cannot establish Android ABI compatibility, touch-surface behavior or safe installation. The runtime fixture also substitutes Android originals and the native owner.

## Build the native extension

Use LLVM tools, `debugfs` from e2fsprogs, Android SDK Build Tools 37.0.0 (`aidl`), and an extracted raw SYSTEM image from the pinned Google CP3 GSI. Header acquisition downloads public Android 17 sources; the build and library extraction run offline and never access a phone.

```sh
python3 tools/acquire_native_headers.py --manifest release/native-header-sources.json --aidl /path/to/android-37.0/aidl --output inputs/native-headers
python3 tools/prepare_native_inputs.py --system /path/to/system.img --headers inputs/native-headers --output inputs/link
python3 tools/build_native.py --inputs inputs/link/native-inputs.json --output build/native
python3 tools/test_runtime.py --inputs inputs/link/native-inputs.json --output build/runtime
```

The acquisition script requires a new output directory, verifies 1,063 header hashes and generates four headers with `aidl`. It downloads only the consumed public headers; their upstream licenses still apply. An Android NDK alone does not supply these platform headers. The preparation script requires a new output directory, checks the header inventory against the pinned source list and extracts five hash-pinned link libraries: SYSTEM's `libc++`, bootstrap `libc` and `libdl`, `liblog`, and `libm` from the runtime APEX. It rejects mismatched libraries.

Pass `--debugfs`, `--cxx`, `--linker` and `--readelf` to the preparation script if those tools are outside PATH. The example configuration shows the portable directory layout; relative paths resolve from its containing directory.

A fresh header download and Clang 23.1.4 build reproduced the installed native library byte for byte: `a8b78c2fc7a04b3652d03125fc9f7ba075114554c1ba9de3d55d87089014a179`. All five link libraries passed their exact hashes when extracted from both the retained patched SYSTEM and a fresh Google GSI download. See [the recorded check](../release/public-inputs-verification.json).

## Patch inputflinger and services

The full services wrapper starts from the original Google image and builds the light and scrolling patches in order. The older `tools/build_services.py` remains an incremental builder; its input is the light-patched JAR listed below. The hook builder uses the original Google library:

| Input | Required SHA256 |
|---|---|
| `libinputflinger.so` | `38761f904a5952bdc958b6348f00d65d467b608bff8d86a696c275f57fc72955` |
| Backlight-patched base `services.jar` | `6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54` |

The services builder also needs Java/Javac, the `patch` command and a tool JAR providing D8 and `com.android.tools.smali`. The tested tool was JADX 1.5.3's complete JAR. Use a fresh services output directory. Download the pinned release and extract its single tool JAR:

```sh
python3 tools/fetch_inputs.py --output inputs dex-tools
unzip -p inputs/jadx-1.5.3.zip lib/jadx-1.5.3-all.jar > inputs/dex-tools.jar
shasum -a 256 inputs/dex-tools.jar
```

The extracted JAR must hash to `05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3`. Keep JADX's bundled notices with the tool. Use a new destination file; the extraction command overwrites an existing `inputs/dex-tools.jar`.

```sh
debugfs -R "dump /system/lib64/libinputflinger.so inputs/libinputflinger.so" inputs/google17/system.img
python3 hooks/build.py --original inputs/libinputflinger.so --output build/hooks --llvm-bin /path/to/llvm/bin
python3 hardware/from-google/build_services_from_google.py --source inputs/google17/system.img --repo "$PWD" --dex-tools inputs/dex-tools.jar --java-home /path/to/jdk17 --debugfs /path/to/debugfs --output build/services-google
```

These outputs are components for SYSTEM assembly. The hooks rebuild matched the recorded installed hash `d7ce6ab0a55591aa87515307771a43ce9f2c4465e0f1c301fefecd21726a3b10`; the build alone does not test Android runtime behavior.

## Build the complete port

The [Google SYSTEM recipe](../hardware/from-google/README.md) now rebuilds all 35 changed files from source or pinned upstream downloads. The [stock VENDOR recipe](../hardware/permanent-vendor/from-stock/README.md) rebuilds its policy, keyboard maps and configuration from original firmware and public Android sources. Neither requires a saved patched SYSTEM or guest VENDOR. The BOOT recipe is in the Google guide; the vbmeta helper is in the VENDOR guide.

Create your own RSA-2048 signing keys before following those guides. The examples use Git-ignored `private/`; keep keys and firmware out of commits:

```sh
mkdir -p private
umask 077
openssl genrsa -out private/system-avb.pem 2048
openssl genrsa -out private/vendor-avb.pem 2048
```

For the SYSTEM build, add `--avbtool build/image-tools/avbtool.py --key private/system-avb.pem` to `clean_system.py`. Use the vendor key for the stock VENDOR build. Image-tool preparation is described below. Linux ARM64 is needed for BOOT and the diagnostic executable; the Google guide explains which output files to copy back for a Mac build.

After both signed images pass their builders, export their public keys and assemble SUPER. Replace the two hash placeholders with `system_sha256` and `vendor_sha256` from the build reports:

```sh
openssl pkey -in private/system-avb.pem -pubout -out private/system-public.pem
openssl pkey -in private/vendor-avb.pem -pubout -out private/vendor-public.pem
python3 tools/assemble_port.py \
  --system build/system/system.img --system-sha256 SYSTEM_SHA256_FROM_REPORT \
  --vendor build/vendor-from-stock/vendor/vendor.img --vendor-sha256 VENDOR_SHA256_FROM_REPORT \
  --system-public-key private/system-public.pem --vendor-public-key private/vendor-public.pem \
  --avbtool build/image-tools/avbtool.py --output build/super
```

The assembler verifies both signatures against those public keys, generates the tested partition metadata, and reads back every output range and zero-filled gap. It rejects existing output directories and changed input files. Use canonical absolute input/output paths if a parent directory is a symlink.

The complete source build passed offline: all 4,368 SYSTEM entries and 1,845 VENDOR entries matched their recorded contents and metadata, and assembled SUPER passed readback. See [the verification record](../release/clean-rebuild-verification.json). Filesystem layout and signatures can differ from the installed images. The new candidate has not been boot-tested.

Google Play core is optional and separate from SYSTEM. Its [source recipe](../hardware/google-play-core/README.md) rebuilds the existing module from Google's matching GMS image without publishing Google APKs.

## Rebuild the app layer

Install e2fsprogs and OpenSSL before image work. On macOS, Homebrew's e2fsprogs tools are under `$(brew --prefix e2fsprogs)/sbin`. On Ubuntu, install `e2fsprogs` and `openssl`. The pinned aapt2 package runs on macOS or x86_64 Linux; ARM Linux needs a compatible host-built aapt2 supplied in the configuration.

Fetch aapt2 and the AVB Python source from their pinned upstream releases:

```sh
mkdir -p build
python3 tools/prepare_build_tools.py --cache inputs/tool-downloads --output build/image-tools
python3 tools/fetch_inputs.py --output inputs camera chromium webview
```

The tool helper retains aapt2's NOTICE and AVB's MIT header. It downloads and unpacks tools without executing them. Configure `aapt2` and `avbtool` to the resulting files and supply absolute paths to `debugfs`, `e2fsck` and OpenSSL.

Follow [hardware/base-apps/README.md](../hardware/base-apps/README.md) for the complete input list and invocation. This step replaces apps inside an existing, already-patched SYSTEM and assembles SUPER with the pinned vendor image and metadata. It does not build Android from AOSP or combine every historical hardware stage for you.

The recipe adds GrapheneOS Camera 93, Ungoogled Chromium 155.0.8059.39, Cromite WebView 153.0.8010.37 with both ARM ABIs, and the performance-fixed touchpad library. It removes AOSP Camera2, QuickSearchBox, Browser2 and the old WebView. The current phone also has a separate Google Play core module; this base-app recipe does not install Google Play services or the Play Store.

The existing square-animation converter rebuilds the installed animation from the pinned upstream download. Use Pillow 12.3.0 in a separate environment:

```sh
python3 tools/fetch_inputs.py --output inputs boot-animation
python3 -m venv build/animation-env
build/animation-env/bin/pip install Pillow==12.3.0
build/animation-env/bin/python hardware/native-ui-v1/rebuild/convert_square.py --source inputs/bootanimation-original.zip --output build/animation
```

The output `build/animation/bootanimation-titan-square-v1.zip` must hash to `b370920629c6a751a5a67e8f7e09e37824c5e02bf818eeca480f9bb54d969714`. The original artwork has separate personal-use terms; see [THIRD_PARTY.md](../THIRD_PARTY.md). No animation assets are published in this repository.

## Installation and recovery boundary

The permanent installation succeeded on the owner's test phone using private firmware, partition backups, signing material and device-specific deployment tooling. The public [installation checks](../tools/install/README.md) verify local images and backups, and inspect an explicitly selected device. A separate executor supports a SUPER-only update on an existing installation, with host-only test coverage. The complete source build and assembly were verified offline. A first installation of these newly signed images has not been tested.

Before attempting an installation elsewhere, you would need matching firmware and partition metadata, verified stock recovery images, a backup of personal data and device-specific calibration partitions, and a recovery route proven on that exact phone. The test phone's initial permanent installation erased its userdata. A later SUPER-only update preserved its userdata, but that does not establish safe upgrades or factory-reset behavior for other setups.

The working manual recovery route on the test phone was:

1. Power the phone off and wait 10 seconds.
2. Hold Volume Up + Power; release when the boot menu/recovery entry appears.
3. If Android shows “No command,” hold Power, briefly press and release Volume Up, then release Power to reveal Android Recovery.
4. “Reboot to bootloader” opens the bootloader. Do not choose wipe/reset while trying to reach it.

This records the observed button route. It is not a full stock restoration guide. Full stock restore remains unverified. Keep the bootloader unlocked with this port.

For an initial installation, the recorded working sequence wrote the port's BOOT, verification-disabled vbmeta and SUPER, erased userdata, then rebooted. These commands are a reference for that sequence, not a newly tested installation. They require an already-unlocked Titan Pocket, its own verified backups and a proven recovery route; erasing userdata deletes its apps and settings. Do not run the update executor for a first install.

Build vbmeta from your matching stock backup, then enter the physical bootloader and use the serial of your own phone:

```sh
python3 hardware/permanent-vendor/boot-chain/build_vbmeta.py --stock-vbmeta private/stock-vbmeta.img --output build/vbmeta.img
fastboot -s YOUR_DEVICE_SERIAL flash boot build/boot/boot.img
fastboot -s YOUR_DEVICE_SERIAL flash vbmeta build/vbmeta.img
fastboot -s YOUR_DEVICE_SERIAL flash super build/super/super.img
fastboot -s YOUR_DEVICE_SERIAL erase userdata
fastboot -s YOUR_DEVICE_SERIAL reboot
```

Run each fastboot command separately and check that it succeeds before continuing. Stop on failure; do not erase userdata or reboot after a failed flash. On first boot, finish Android setup and authorize USB debugging, then verify BOOT, vbmeta and SUPER readback hashes against the built files. The [update guide](../tools/install/README.md) shows the rooted readback command. Booting does not establish working cellular service or every hardware feature; the README lists the remaining phone tests.


## Screenshot provenance

The README uses three unedited captures reviewed for visible private information:

- [Guest home screen](images/guest-home-screen.png): the earlier boot-compatibility guest, before the navigation-bar and search-widget changes.
- [Guest app drawer](images/guest-app-drawer.png): the UI-spacing trial, before the final base-app update. It includes historical apps and the LED test utility.
- [Play Store first launch](images/play-store-first-launch.png): the Google Play core trial on the permanent install, before sign-in. It shows the app launching, not account or download verification.

These images document those stages only. They do not prove the current camera, browser, hardware behavior or final launcher layout.
