AOSP code retained under Apache License 2.0:

- `native/proven/mapper/accumulator/MultiTouchMotionAccumulator.{h,cpp}`: AOSP inputflinger accumulator, with its namespace changed for this extension. Original copyright and license notices remain in both files.
- `native/official-value-types.h`: selected `InputDeviceIdentifier` and `RawEvent` declarations from AOSP inputflinger `reader/include/EventHub.h`. Its original notice is retained.

The small `proven` support headers adapt these declarations for this extension. Private CP3 platform headers and Android libraries remain external inputs. Their licenses still apply. The Apache license text is in `LICENSES/Apache-2.0.txt`.

The PIN adapter builder transforms a caller-supplied, hash-pinned SystemUI class. The original class is not included. Its license still applies to the generated output.

No project-wide license has been chosen for the remaining code.

The system-camera builder requires Greatness’s Camera Go NoAux modification of Google Camera Go. Its APK is an external, hash-pinned input; this repository contains no Google camera code or APK and grants no license to it. The maintainer’s release is linked in `hardware/system-camera/README.md`.
