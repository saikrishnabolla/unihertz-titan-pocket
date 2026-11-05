# Building and reading the Titan Pocket port

Run the commands in this guide from the repository root unless a step says otherwise. All build and test commands here are offline: they do not flash or reboot a phone.

## Get the source

```sh
git clone https://github.com/saikrishnabolla/unihertz-titan-pocket.git
cd unihertz-titan-pocket
```

The code targets the Titan Pocket and the September Android 17 preview `CP3A.260905.010`. Matching an Android version alone is insufficient: the patchers check exact input hashes and depend on that build's internal interfaces.

## How to read the repo

| Path | Read it for |
|---|---|
| `native/` | Keyboard-surface scrolling, input ownership and native runtime checks. |
| `services/` | Android input-service session state and framework smali patches, including the first-unlock fix. |
| `hooks/` | Patching the pinned inputflinger library. Its builder labels the output an offline lifecycle experiment; do not treat it as an installation candidate. |
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

In addition to the host tools, supply LLVM tools, the matching CP3 platform/generated headers and the private Android link libraries listed in the example configuration:

```sh
cp private-inputs.example.json private-inputs.json
```

Edit `private-inputs.json` before building. Set `cxx`, `linker` and `readelf` to compatible tools, supply every header directory, and provide link libraries with the listed hashes. Relative input paths resolve from the configuration file's directory. The header layout reflects the original development environment; this repo does not automate downloading or generating it. An Android NDK alone does not supply all those platform/generated headers.

```sh
python3 tools/build_native.py --inputs private-inputs.json --output build/native
python3 tools/test_runtime.py --inputs private-inputs.json --output build/runtime
```

A missing directory or mismatched library is a reason to obtain the correct input. Do not remove the hash checks to force another build through. A clean-environment rebuild has not been verified.

## Patch inputflinger and services

These builders need private originals from the pinned build:

| Input | Required SHA256 |
|---|---|
| `libinputflinger.so` | `38761f904a5952bdc958b6348f00d65d467b608bff8d86a696c275f57fc72955` |
| Backlight-patched base `services.jar` | `6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54` |

The services builder also needs Java/Javac, the `patch` command and a tool JAR providing D8 and `com.android.tools.smali`. The tested tool was JADX 1.5.3's complete JAR. Use a fresh services output directory.

```sh
python3 hooks/build.py --original inputs/libinputflinger.so --output build/hooks
python3 tools/build_services.py --original inputs/services.jar --dex-tools inputs/dex-tools.jar --output build/services
```

These outputs are components for further integration and verification. In particular, the hooks builder explicitly describes its output as an offline experiment, not a phone installation candidate.

## Rebuild the app layer

Follow [hardware/base-apps/README.md](../hardware/base-apps/README.md) for the complete input list and invocation. This step replaces apps inside an existing, already-patched SYSTEM and assembles SUPER with the pinned vendor image and metadata. It does not build Android from AOSP or combine every historical hardware stage for you.

The recipe adds GrapheneOS Camera 93, Ungoogled Chromium 155.0.8059.39, Cromite WebView 153.0.8010.37 with both ARM ABIs, and the performance-fixed touchpad library. It removes AOSP Camera2, QuickSearchBox, Browser2 and the old WebView. The current phone also has a separate Google Play core module; this base-app recipe does not install Google Play services or the Play Store.

## Installation and recovery boundary

The permanent installation succeeded on the owner's test phone using private firmware, partition backups, signing material and device-specific deployment tooling. That deployment tooling is not a public installer in this repo. There is no documented, verified clean-clone-to-flash path yet.

Before attempting an installation elsewhere, you would need matching firmware and partition metadata, verified stock recovery images, a backup of personal data and device-specific calibration partitions, and a recovery route proven on that exact phone. The test phone's initial permanent installation erased its userdata. A later SUPER-only update preserved its userdata, but that does not establish safe upgrades or factory-reset behavior for other setups.

The working manual recovery route on the test phone was:

1. Power the phone off and wait 10 seconds.
2. Hold Volume Up + Power; release when the boot menu/recovery entry appears.
3. If Android shows “No command,” hold Power, briefly press and release Volume Up, then release Power to reveal Android Recovery.
4. “Reboot to bootloader” opens the bootloader. Do not choose wipe/reset while trying to reach it.

This records the observed button route. It is not a full stock restoration guide. Full stock restore remains unverified. Keep the bootloader unlocked with this port.

## Screenshot provenance

The README uses three unedited captures reviewed for visible private information:

- [Guest home screen](images/guest-home-screen.png): the earlier boot-compatibility guest, before the navigation-bar and search-widget changes.
- [Guest app drawer](images/guest-app-drawer.png): the UI-spacing trial, before the final base-app update. It includes historical apps and the LED test utility.
- [Play Store first launch](images/play-store-first-launch.png): the Google Play core trial on the permanent install, before sign-in. It shows the app launching, not account or download verification.

These images document those stages only. They do not prove the current camera, browser, hardware behavior or final launcher layout.
