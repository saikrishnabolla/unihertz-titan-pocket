# Titan Pocket hardware work

Source and offline build steps for the Titan Pocket Android 17 guest. The phone still uses its stock kernel, vendor drivers and stock Android as the recovery system. This is not official Unihertz firmware or a full firmware rebuild.

- `boot-chain`: recovered init, zygote, IR, policy, connectivity and diagnostic builders, with their tests. These are historical pinned steps; some use Linux `/tmp/opencode` tool defaults. `prepare_google_zygote_stdio_guest.py` moves its input image into the output directory. Use a disposable copy.
- `backlight`: light policy, Android bridge, host tests and pinned framework/image rebuilds.
- `keyboard-layout-v1`, `pin-hardware-v1`: physical keyboard symbols and PIN entry patches.
- `bluetooth-module`, `bluetooth-system`: controller patch and pinned APEX/image rebuilds.
- `navigation-overlay`, `native-ui-v1`, `ui-spacing-v1`: physical navigation and layout changes.
- `notification-led-v1`: notification light resource overlay and image builder.
- `camera-layout-fix`, `camera-app-update`: camera layout patch, verifier and signing source.
- `legacy-kernel`: CLAT label adapter, local-network capability guards and LPM backport experiments. Host tests do not prove a kernel module is safe to load.

Firmware, APKs, APEX files, framework JARs, decompiled original classes, tool binaries and signing keys are excluded. Builders retain exact input hashes and reject a different build. Supply your own matching inputs and signing keys; follow the source manifests for each step. Original source notices remain in the files. This directory grants no new license for third-party material.

`fingerprint-overlay` reconstructs the pinned working overlay's minimal XML. Its unsigned build has the same decoded manifest and resource table as signed APK `40a0322207dc74fbd716b8d7306528b46503ddbb10f7235bfcfef552d975a7a2`: `config_biometric_sensors = ["0:2:4095"]` for `Titan_pocket`. The previously observed provider/defaultHIDL route is a runtime result; this overlay contains no provider-routing resource. This build proves configuration equivalence, not signed binary reproduction or a new device test. The builder needs an Android 17 `framework-res.apk` and `aapt2`; tool hashes from the comparison are in `fingerprint-overlay/reconstruction-verification.json`. Boot animation assets are excluded; their redistribution rights have not been established. `native-ui-v1/rebuild/convert_square.py` scales the externally supplied pinned original animation (`97d77f7d8ce57b8d47102d541938e60113c0a489628fd8a1308def33a1e4b8a6`) to the verified square output (`b370920629c6a751a5a67e8f7e09e37824c5e02bf818eeca480f9bb54d969714`) using Pillow. The current backlight rebuild also needs the pinned original controller smali and `services.jar`. CLAT replay tests need the pinned `libservice-connectivity.so` through `TITAN_CLAT_SOURCE`. Local-policy scripts use `TITAN_LOCAL_POLICY_WORK` for their input/output tree.

This stage passed 26 boot-transform unit tests, backlight host tests and 778 LPM iterator cases under AddressSanitizer/UndefinedBehaviorSanitizer. The broader historical Linux suite was not verified on this Mac: eight tests required `/usr/sbin/mke2fs`, and thirteen skipped unavailable Linux tooling. No full image rebuild or device test was run from this public source stage.
