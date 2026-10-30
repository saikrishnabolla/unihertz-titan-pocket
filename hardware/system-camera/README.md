GrapheneOS Camera 93 is now integrated into SYSTEM by the [base-app recipe](../base-apps/README.md). This earlier add-on builder masks AOSP Camera2 on the previous base image. Removing that add-on restores AOSP Camera2 only on the previous image; the updated base removes Camera2 itself. GrapheneOS Camera is an open-source project under the MIT license. The upstream source and license remain at https://github.com/GrapheneOS/Camera. This builder uses the official APK unchanged.

Supply `Camera-93.apk` from [the official release](https://github.com/GrapheneOS/Camera/releases/tag/93). The builder checks SHA256 `6e1d05a7b96b308f3a9dff3103db55cfee2cbea38b3249b5879fe35cfcf179ff`:

```sh
python3 hardware/system-camera/build.py --apk inputs/Camera-93.apk --output build/system-camera
```

On the tested CP3 build, place the generated `module/` contents in `/data/adb/modules/titan_system_camera/` with root ownership, directory mode 755, file mode 644, `service.sh` mode 755 and `u:object_r:system_file:s0` labels. If GrapheneOS Camera was installed under `/data/app`, first use `pm uninstall -k app.grapheneos.camera` to retain its settings while removing that copy, then reboot. Run `cmd package install-existing --user 0 app.grapheneos.camera` and `pm enable --user 0 app.grapheneos.camera` after boot if needed. Grant camera and microphone permissions through Android.

Check that `pm path app.grapheneos.camera` points to `/system/product/app/TitanCamera/TitanCamera.apk`, the package has the SYSTEM flag, AOSP Camera2 is absent from the launcher, and `android.media.action.STILL_IMAGE_CAMERA` and `android.media.action.IMAGE_CAPTURE` resolve to GrapheneOS Camera. A successful boot alone does not prove camera operation. The 360-second boot guard disables the add-on and reboots only if boot completion fails.
