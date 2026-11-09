# Build VENDOR from stock firmware

This recipe replaces the private, already-modified guest VENDOR input. It starts with stock Titan Pocket files and builds the same file contents, ownership, modes, SELinux labels and timestamps as the tested permanent VENDOR. The ext4 layout and signed image hash can differ.

These commands build files offline. A newly signed image still needs a boot and recovery test. The bootloader must remain unlocked.

## Inputs

Use raw ext4 partition images:

- Stock Titan Pocket `vendor.img` and `system.img`, extracted from the retained stock SUPER image.
- Original September Android 17 Google GSI `system.img`.
- Android 13 Google GSI `system.img`, from `aosp_arm64-exp-TQ3A.230805.001.A3-10454027-66e107ed.zip`. Its API 30 mapping is expanded through Android 17's API 31 mapping. A hash-pinned AOSP 16 compatibility file is combined with Android 17's API 31 compatibility file.

The extraction script checks every file hash. Stock VENDOR must have SHA-256 `d991ee39bb233c7f717d9007b1acf9f83c41b3db3e8af188a9c78d4f27b1408f`. Stock SYSTEM supplies the three `aw9523-key` keyboard maps under `/system/usr`.

## Build

Run on Linux with Python 3, Git, GCC, binutils, Flex, OpenSSL and e2fsprogs installed. Run from the repository root. Set the input paths below to your raw images. Keep the signing key outside the repository. Use `--aosp16-compat /path/to/30.0.compat.cil` instead of `--fetch-compat` for an offline build.

```sh
REPO="$PWD"
RECIPE="$REPO/hardware/permanent-vendor/from-stock"
WORK="$REPO/build/vendor-from-stock"
mkdir -p "$WORK"

python3 "$RECIPE/prepare_policy_inputs.py" \
  --google17-system /path/to/google17/system.img \
  --google13-system /path/to/google13/system.img \
  --stock-vendor /path/to/stock/vendor.img \
  --stock-system /path/to/stock/system.img \
  --debugfs /usr/sbin/debugfs \
  --fetch-compat \
  --output "$WORK/extracted"

python3 "$RECIPE/build_policy_tools.py" \
  --fetch-source \
  --source "$WORK/aosp-selinux" \
  --transformer "$REPO/hardware/boot-chain/transform_policy_legacy_netlink.c" \
  --output "$WORK/policy-tools"

python3 "$RECIPE/build_policy.py" \
  --inputs "$WORK/extracted/inputs" \
  --output "$WORK/policy" \
  --secilc "$WORK/policy-tools/secilc" \
  --transformer "$WORK/policy-tools/transform-policy"

openssl genrsa -out /private/path/vendor-avb.pem 2048
chmod 600 /private/path/vendor-avb.pem

python3 "$RECIPE/build_stock_vendor.py" \
  --stock-vendor /path/to/stock/vendor.img \
  --keymaps "$WORK/extracted/keymaps" \
  --policy "$WORK/policy" \
  --key /private/path/vendor-avb.pem \
  --avbtool /path/to/pinned/avbtool.py \
  --vendor-tools "$REPO/hardware/permanent-vendor" \
  --debugfs /usr/sbin/debugfs \
  --e2fsck /usr/sbin/e2fsck \
  --resize2fs /usr/sbin/resize2fs \
  --output "$WORK/vendor"
```

Use the pinned `avbtool.py` described in the parent VENDOR recipe. Every output directory must be new. A failed build retains its files for inspection.

## What changes

The recipe adds stock keyboard maps, replaces the SELinux policy and its cache identifiers, removes the unused APD mount, removes `formattable` from seven shared physical partitions, and removes the old raw-userdata `tune2fs` command. It keeps `/data` formatting and encryption flags, giving Android 17 its own metadata key directory.

The policy compiler is AOSP `external/selinux` commit `a8c5e74f85f869bf236a01ba24181b78f5e39a52`. Its output must match the tested policy hash `cb2e4b879e2de0c0acb97309c9a8380e2c25771a16ed0557733ef80bfd3b2e22`.

This retains the port's existing security tradeoff: policy compilation disables neverallow checks, and the legacy-kernel transformer removes NLMSG message-type filters. Those permissions become coarser. Existing ioctl filters are retained. These changes do not fix vulnerabilities in the stock kernel.
