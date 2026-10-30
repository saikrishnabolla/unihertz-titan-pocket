Greatness Camera Go NoAux is installed as the system camera. The add-on masks AOSP Camera2 without changing the raw SYSTEM partition. Removing the add-on and rebooting restores AOSP Camera2. Camera Go remains a third-party modification of Google software; no ownership or new license is claimed.

Supply `CameraGo_2.5_Greatness_210726_1455_NoAux.apk` from [Greatness’s release](https://www.celsoazevedo.com/files/android/google-camera/dev-greatness/f/dl6/). The builder checks SHA256 `ebe906d3d00cd8596c4015975ff58c496f4ce0a946e689da718b295612445f95`:

```sh
python3 hardware/system-camera/build.py --apk inputs/CameraGo_2.5_Greatness_210726_1455_NoAux.apk --output build/system-camera
```

On the tested CP3 build, place the generated `module/` contents in `/data/adb/modules/titan_system_camera/` with root ownership, directory mode 755, file mode 644, `service.sh` mode 755 and `u:object_r:system_file:s0` labels. If Camera Go was installed under `/data/app`, first use `pm uninstall -k com.google.android.apps.cameralite` to retain its settings while removing that copy, then reboot. Run `cmd package install-existing --user 0 com.google.android.apps.cameralite` and `pm enable --user 0 com.google.android.apps.cameralite` after boot if needed. Grant camera, microphone and media permissions through Android.

Check that `pm path com.google.android.apps.cameralite` points to `/system/product/app/TitanCamera/TitanCamera.apk`, the package has the SYSTEM flag, AOSP Camera2 is absent from the launcher, and `android.media.action.STILL_IMAGE_CAMERA` and `android.media.action.IMAGE_CAPTURE` resolve to Camera Go. A successful boot alone does not prove camera operation. The 360-second boot guard disables the add-on and reboots only if boot completion fails.
