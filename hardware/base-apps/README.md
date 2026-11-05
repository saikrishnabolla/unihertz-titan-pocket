# Current base-app recipe

This offline recipe updates the pinned CP3 SYSTEM image and assembles SUPER with the original vendor image and partition layout. The input SYSTEM must already contain the earlier port changes. This is the final app-layer step, not a complete Android build or an installer.

It removes AOSP Camera2, QuickSearchBox, Browser2 and the old WebView, including their oat files. It adds GrapheneOS Camera 93, Ungoogled Chromium 155.0.8059.39, mixed-ABI Cromite WebView 153.0.8010.37 and the verified touchpad performance library. The original WebView provider configuration is retained; no provider overlay is added. Google Play core is a separate module and is not installed by this recipe.

## Inputs

Copy `private-inputs.example.json` to `private-inputs.json` in this directory and edit its paths. Every input must match the hashes checked in `build.py` and its helper sources.

| Configuration key | Required input |
|---|---|
| `system` | The already-patched, pinned CP3 SYSTEM image. A fresh Google GSI is not a substitute. |
| `source_tree` | The matching `candidate-tree-final.json` filesystem inventory. |
| `vendor` | The pinned original vendor image. |
| `prefix` | The pinned SUPER metadata prefix for the test phone's partition layout. |
| `camera` | Official GrapheneOS Camera 93 APK. |
| `browser` | Ungoogled Chromium 155.0.8059.39 ARM64 APK. |
| `webview` | Cromite WebView 153.0.8010.37 APK containing both ARM32 and ARM64 libraries. |
| `touchpad` | The pinned performance-fixed `libtitan_keyboard_surface.so`. |
| `avb_key` | The existing private SYSTEM AVB signing key. Its public-key hash is checked; an arbitrary new key will fail. |
| `tools` | Paths to working `debugfs`, `e2fsck`, OpenSSL, `avbtool` and `aapt2`. |

Pinned APK releases:

- [GrapheneOS Camera 93](https://github.com/GrapheneOS/Camera/releases/tag/93)
- [Ungoogled Chromium 155.0.8059.39-1](https://github.com/ungoogled-software/ungoogled-chromium-android/releases/tag/155.0.8059.39-1)
- [Cromite 153.0.8010.37](https://github.com/uazo/cromite/releases/tag/v153.0.8010.37-11507ac1061b5ea227806f5e84db5a57df6ccf6a)

Keep the signing key outside this source directory and set `avb_key` to its absolute path. The builder checks the key without copying it. Firmware, APKs, compiled libraries, private inventories, metadata and signing keys are not supplied by this repo. These dependencies prevent a complete rebuild from a clean clone alone.

## Run

From the repository root:

```sh
cd hardware/base-apps
cp private-inputs.example.json private-inputs.json
```

Edit the configuration, then run:

```sh
python3 build.py --inputs private-inputs.json --output /absolute/fresh/output
```

Replace `/absolute/fresh/output` with your intended output path. That directory must not exist, its parent must exist, and the destination needs more than about 13.6 GiB free, excluding input files. Relative paths inside this configuration resolve from your working directory, unlike the native builder's config-relative paths. Absolute paths avoid that ambiguity.

Do not run Python with `-O`: the builder uses assertions for its input and consistency checks. If an input hash differs, obtain the matching input rather than bypassing the check.

## Outputs and checks

The output contains `system.img`, `super/super.img` and reports. The builder checks input hashes, package names, both WebView ABIs, filesystem consistency, file permissions and SELinux labels, unchanged surviving files, AVB signatures and assembled SUPER readback. It performs no device operations.

A successful run produces an offline candidate. Phone boot, app behavior, userdata preservation and factory-reset behavior require separate device checks. The recorded test phone booted after the update, with matching SUPER readback and a preserved userdata sentinel. The owner tested camera image quality and found it comparable to stock, with no observed regression. Video recording/playback, flash, browser page rendering and factory reset remain unverified; see [verification.json](../../verification.json).
