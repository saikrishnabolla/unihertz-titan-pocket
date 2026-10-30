# Titan Pocket Android 17

Source patches, build steps and test findings for the Unihertz Titan Pocket running the September Android 17 GSI, `CP3A.260905.010`. This package builds the native scrolling extension, patches its exact `libinputflinger.so`, and patches `services.jar`. It does not build a complete ROM or install anything on a phone.


The port uses the stock MediaTek kernel and vendor drivers in a DSU guest. Stock Android remains available for recovery. It is an unofficial adaptation; these sources do not establish a complete clean ROM build or a safe permanent installation.

## Phone tests

| Area | Evidence |
|---|---|
| Boot | September guest boots with SELinux Enforcing; installed SYSTEM and payload hashes verified. |
| Keyboard surface | First-unlock scrolling and two lock/wake cycles passed owner tests. Touchscreen and keyboard scrolling both work; no cursor; normal typing works. |
| Earlier hardware checks | Physical PIN, Alt+A, navigation keys, keyboard light timeout, fingerprint enrollment, Bluetooth music, front camera preview and green notification LED passed owner tests. |
| Still unverified | Camera capture/video/flash, BLE and call audio, other LED colors, sensors in use, endurance, and full stock restore/permanent installation. |
| Cellular | No SIM is available. Carrier calls, SMS, mobile data and VoLTE remain untested. |

The old kernel/vendor security level is unchanged by the newer Android system. An unlocked bootloader and custom system may fail app integrity checks. No relocking or permanent flashing has been verified.

## Build and test

Core tests require Python 3, Clang with C++20 and sanitizer support, and JDK 17:

```sh
python3 tools/test.py --output build/core
python3 tools/test.py --output build/core-tsan --sanitizer thread
python3 tools/test_keyguard.py --output build/keyguard
```

Android builds also need LLVM tools, matching CP3 platform/generated headers, and the private Android link libraries. Copy `private-inputs.example.json` to `private-inputs.json`, supply its header directories and hash-matched libraries, then run:

```sh
python3 tools/build_native.py --inputs private-inputs.json --output build/native
python3 tools/test_runtime.py --inputs private-inputs.json --output build/runtime
```

The header directories in the example describe the existing build environment. Downloading or generating that header tree is not automated. The Runtime test substitutes Android originals and the native owner; it cannot establish phone behavior or ABI compatibility by itself.

Supply private originals for the remaining builds. The hooks builder requires `libinputflinger.so` with SHA256 `38761f904a5952bdc958b6348f00d65d467b608bff8d86a696c275f57fc72955`. The services builder requires the backlight-patched base `services.jar` with SHA256 `6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54` and a tool JAR providing D8 and `com.android.tools.smali` (the tested tool is JADX 1.5.3's complete JAR):

```sh
python3 hooks/build.py --original inputs/libinputflinger.so --output build/hooks
python3 tools/build_services.py --original inputs/services.jar --dex-tools inputs/dex-tools.jar --output build/services
```

Use an empty services output directory. Firmware, Google/system binaries, device logs, credentials and personal data are not included. See `THIRD_PARTY.md` for retained upstream notices.

## Other hardware sources

See [hardware/README.md](hardware/README.md) for the recovered boot-chain, keyboard, lighting, fingerprint, Bluetooth, camera and layout sources, their pinned inputs and remaining build limits. Firmware, signing keys, original compiled components and animation assets must be supplied separately. Upstream notices are retained; no new license is granted for third-party material.
