# Titan Pocket Android 17

Source patches, build steps and test findings for the Unihertz Titan Pocket running the September Android 17 GSI, `CP3A.260905.010`. This package builds the native scrolling extension, patches its exact `libinputflinger.so`, and patches `services.jar`. It does not build a complete ROM or install anything on a phone.


The port uses the stock MediaTek kernel and vendor drivers. A permanent clean installation now boots on the test phone, without DSU. Installation erased its apps and settings with the owner’s consent. This is an unofficial port; the source package does not provide a complete ROM build or a general-purpose installer.

## Phone tests

| Area | Evidence |
|---|---|
| Boot | Permanent September build boots with SELinux Enforcing and encrypted userdata. Full SUPER, BOOT, recovery and vbmeta readback hashes match; a normal reboot passed. |
| Keyboard surface | First-unlock scrolling, normal typing, Alt+A and keyboard light timeout passed owner checks after the permanent install. The same SYSTEM also passed two lock/wake cycles, touchscreen/keyboard scrolling together and no-cursor checks in the guest. |
| Camera app | GrapheneOS Camera 93 is built into SYSTEM. AOSP Camera2, Camera Go and BSG are absent. Photo/video capture intents resolve to GrapheneOS Camera; capture quality remains unverified. |
| Earlier hardware checks | In the earlier guest, physical PIN, Alt+A, navigation keys, keyboard light timeout, fingerprint enrollment, Bluetooth music, front camera preview and green notification LED passed owner tests. The clean install requires fresh enrollment and pairing. |
| Still unverified | Camera capture/video/flash, BLE and call audio, other LED colors, sensors in use, endurance, remaining permanent-install hardware rechecks, and full stock restore. |
| Cellular | No SIM is available. Carrier calls, SMS, mobile data and VoLTE remain untested. |

A performance fix removes repeated `/proc/self/maps` scans from live input-thread checks. The fixed library is now built into SYSTEM; the owner reported faster touchscreen scrolling and animations when it was first tested as an override. A second input-thread profile no longer lists memory-map parsing among symbols above 1%. These profiles used different input activity and do not establish a percentage speedup.

The old kernel/vendor security level is unchanged by the newer Android system. An unlocked bootloader and custom system may fail app integrity checks. Relocking has not been tested and must not be attempted. NVRAM, proinfo, TEE, bootloader and DTBO raw hashes match their pre-install values. Four vendor ext4 partitions changed raw hashes while mounted read/write; their calibration files have not been compared individually. Stock firmware backups exist; a full stock userdata backup was waived before erasure.

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

The base-app recipe at [hardware/base-apps](hardware/base-apps/README.md) integrates the camera, Brave 1.98.63 (Chromium 156), mixed-ABI Cromite WebView 153 and the input performance fix. It removes AOSP Camera2, QuickSearchBox and the test-shell browser. The phone booted after a SUPER-only update with userdata retained, matching firmware readback and unchanged protected partitions. WebView prepared both architectures. WebView 153 is behind current Chromium 156; browser page rendering remains unverified. Factory-reset behavior has not been tested.

The earlier camera add-on is built with `python3 hardware/system-camera/build.py --apk inputs/Camera-93.apk --output build/system-camera`. See [its instructions](hardware/system-camera/README.md) for the pinned download, installation and checks.

See [hardware/README.md](hardware/README.md) for the recovered boot-chain, keyboard, lighting, fingerprint, Bluetooth, camera and layout sources, their pinned inputs and remaining build limits. Firmware, signing keys, original compiled components and animation assets must be supplied separately. Upstream notices are retained; no new license is granted for third-party material.
