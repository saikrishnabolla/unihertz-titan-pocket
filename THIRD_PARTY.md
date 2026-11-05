# Licensing and third-party notices

AOSP code retained under Apache License 2.0:

- `native/proven/mapper/accumulator/MultiTouchMotionAccumulator.{h,cpp}`: AOSP inputflinger accumulator, with its namespace changed for this extension. Original copyright and license notices remain in both files.
- `native/official-value-types.h`: selected `InputDeviceIdentifier` and `RawEvent` declarations from AOSP inputflinger `reader/include/EventHub.h`. Its original notice is retained.

The small `proven` support headers adapt these declarations for this extension. Private CP3 platform headers and Android libraries remain external inputs. Their licenses still apply. The Apache license text is in `LICENSES/Apache-2.0.txt`.

The PIN adapter builder transforms a caller-supplied, hash-pinned SystemUI class. The original class is not included. Its license still applies to the generated output.

The project's original code and documentation are licensed under Apache License 2.0, in the root `LICENSE` file. This grant does not replace upstream licenses or grant rights to excluded firmware, APKs, signing material or other external inputs.

The system-camera builder uses the official GrapheneOS Camera 93 APK as an external, hash-pinned input. GrapheneOS Camera is MIT licensed; its source and license are at https://github.com/GrapheneOS/Camera. The APK is not included in this repository. The release is linked in `hardware/system-camera/README.md`.

The base-app recipe takes Ungoogled Chromium and Cromite WebView APKs as external inputs. Their source and notices are at https://github.com/ungoogled-software/ungoogled-chromium-android and https://github.com/uazo/cromite. APKs are not included.

Linux-derived LPM implementations in `hardware/legacy-kernel/lpm-source/backport/` and the Linux kernel module in `hardware/legacy-kernel/lpm-source/module/module.c` retain GPL version 2. The upstream notices and module license declaration remain in place. The GPL-2.0 text is in `LICENSES/GPL-2.0.txt`. These files are exceptions to the project's Apache 2.0 license.
