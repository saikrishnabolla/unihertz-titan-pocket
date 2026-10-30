This offline recipe updates the pinned CP3 SYSTEM image and assembles SUPER with the original vendor and partition layout. It removes AOSP Camera2, QuickSearchBox, Browser2 and the old WebView, including their oat files. It adds GrapheneOS Camera 93, Brave, the official mixed-ABI Cromite WebView and the verified touchpad performance library. The original WebView provider configuration is retained; no provider overlay is added.

Supply the exact hash-pinned input files and tools listed in `private-inputs.example.json`. Keep the existing private SYSTEM AVB signing key outside this source directory. The builder checks its public-key hash without copying the key. This source package includes no firmware, APKs, compiled libraries or signing keys.

```sh
python3 build.py --inputs private-inputs.json --output /absolute/fresh/output
```

The output contains `system.img`, `super/super.img` and their reports. The builder checks input hashes, package names, both WebView ABIs, filesystem consistency, file permissions and SELinux labels, unchanged surviving files, AVB signatures and SUPER readback. Its output is an offline candidate. Phone boot, app behavior, userdata preservation and factory-reset behavior require separate device checks. The builder performs no device operations.
