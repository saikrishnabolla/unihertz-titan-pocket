# Optional Google Play Core module

This rebuilds the port's optional Magisk module from the matching Google GMS image. It adds Play Store, Play Services, Services Framework and Play Services' internal AndroidPlatformServices APK. It includes no Setup Wizard or other Google apps.

The module is separate from the base SYSTEM image. The builder creates a local directory and does not install anything on a phone.

## Build

Run from the repository root with Python 3 and e2fsprogs installed. Use a new output directory for each command. Set the paths below to a private build directory.

```sh
python3 tools/fetch_inputs.py \
  --manifest hardware/google-play-core/sources.json \
  --output /private/path/downloads \
  google-gms-gsi

python3 hardware/google-play-core/extract_source.py \
  --source /private/path/downloads/gsi-gms-arm64-CP3A.260905.010.zip \
  --output /private/path/google-gms

python3 hardware/google-play-core/build.py \
  --source /private/path/google-gms/system.img \
  --debugfs /usr/sbin/debugfs \
  --output /private/path/google-play-core
```

On a Homebrew Mac, use `/opt/homebrew/opt/e2fsprogs/sbin/debugfs`.

The result is `/private/path/google-play-core/module/`. The builder checks all eleven file hashes against the original module: four unchanged APKs, five filtered XML files and the two project templates. Its report records the result. APK signatures are preserved.

The included `service.sh` waits up to 360 seconds for Android to finish booting. If it does not, the service disables this module and reboots. The builder does not run this script.

## Source and licenses

`sources.json` pins Google's CP3A.260905.010 GMS archive. Extraction checks the complete archive and raw SYSTEM hashes. The XML files are filtered from that local image to retain the three core packages and their broadcasts.

The repository contains the builder and project templates. Google APKs and upstream XML are not included; their upstream terms still apply to locally generated files. The project's Apache 2.0 license covers its own code and templates.
