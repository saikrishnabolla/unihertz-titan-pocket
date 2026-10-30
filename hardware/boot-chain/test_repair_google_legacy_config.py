import unittest

import repair_google_legacy_config as tool


APD = (b'/dev/block/by-name/apd /mnt/vendor/apd ext4 '
       b'noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n')
TUNE = b'exec /system/bin/tune2fs -O has_journal -u 10010 -r 4096 /dev/block/by-name/userdata'
SHARED = (
    b'/dev/block/by-name/md_udc\t /metadata ext4 noatime,nosuid,nodev,discard wait,check,formattable,first_stage_mount\n'
    b'/dev/block/by-name/cache /cache ext4 noatime,nosuid,nodev,noauto_da_alloc,discard wait,check,formattable\n'
    b'/dev/block/by-name/protect1 /mnt/vendor/protect_f ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n'
    b'/dev/block/by-name/protect2 /mnt/vendor/protect_s ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n'
    b'/dev/block/by-name/nvdata /mnt/vendor/nvdata ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n'
    b'/dev/block/by-name/nvcfg /mnt/vendor/nvcfg ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n'
    b'/dev/block/by-name/persist /mnt/vendor/persist ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check,formattable\n'
)
SAFE_SHARED = (
    b'/dev/block/by-name/md_udc\t /metadata ext4 noatime,nosuid,nodev,discard wait,check,first_stage_mount\n'
    b'/dev/block/by-name/cache /cache ext4 noatime,nosuid,nodev,noauto_da_alloc,discard wait,check\n'
    b'/dev/block/by-name/protect1 /mnt/vendor/protect_f ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check\n'
    b'/dev/block/by-name/protect2 /mnt/vendor/protect_s ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check\n'
    b'/dev/block/by-name/nvdata /mnt/vendor/nvdata ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check\n'
    b'/dev/block/by-name/nvcfg /mnt/vendor/nvcfg ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check\n'
    b'/dev/block/by-name/persist /mnt/vendor/persist ext4 noatime,nosuid,nodev,noauto_da_alloc,commit=1,nodelalloc wait,check\n'
)
USERDATA = (b'/dev/block/by-name/userdata /data ext4 noatime,nosuid,nodev,noauto_da_alloc,errors=panic,inlinecrypt '
            b'wait,check,formattable,quota,latemount,resize,reservedsize=128m,checkpoint=block,'
            b'fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption\n')
FSTAB = SHARED + USERDATA + APD
SAFE_FSTAB = SAFE_SHARED + USERDATA


class LegacyConfigTests(unittest.TestCase):
    def test_fstab_removes_shared_format_tokens_but_preserves_userdata_and_other_bytes(self):
        self.assertEqual(tool.patch_fstab(b'# start\n' + FSTAB + b'# end\xff'),
                         b'# start\n' + SAFE_FSTAB + b'# end\xff')

    def test_ueventd_adds_legacy_import_immediately_after_modern_import(self):
        source = b'# keep\nimport /vendor/etc/ueventd.rc\nimport /odm/etc/ueventd.rc\n\xff'
        self.assertEqual(
            tool.patch_ueventd(source),
            b'# keep\nimport /vendor/etc/ueventd.rc\nimport /vendor/ueventd.rc\n'
            b'import /odm/etc/ueventd.rc\n\xff',
        )

    def test_vndk_manifest_declares_installed_vndk30(self):
        block30 = b'    <vendor-ndk>\n        <version>30</version>\n    </vendor-ndk>\n'
        source = (b'<manifest version="1.0" type="framework">\n'
                  b'    <vendor-ndk>\n        <version>31</version>\n    </vendor-ndk>\n'
                  b'    <vendor-ndk>\n        <version>32</version>\n    </vendor-ndk>\n'
                  b'    <vendor-ndk>\n        <version>33</version>\n    </vendor-ndk>\n'
                  b'    <vendor-ndk>\n        <version>34</version>\n    </vendor-ndk>\n'
                  b'    <system-sdk><version>30</version></system-sdk>\n</manifest>\n')
        self.assertEqual(tool.patch_vndk_manifest(source),
                         b'<manifest version="1.0" type="framework">\n' + block30
                         + source.split(b'\n', 1)[1])
        for invalid in (b'<?xml#', source.replace(b'type="framework"', b'type="device"'),
                        source.replace(b'<version>31</version>', b'<version>30</version>'),
                        source.replace(b'<version>34</version>', b'<version>35</version>')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                tool.patch_vndk_manifest(invalid)

    def test_ueventd_refuses_missing_duplicate_legacy_and_nonexact_imports(self):
        modern = b'import /vendor/etc/ueventd.rc\n'
        cases = [b'', b'# ' + modern, modern * 2,
                 modern + b'import /vendor/ueventd.rc\n',
                 modern + b'  import\t/vendor/ueventd.rc # present\n',
                 modern + b' import /vendor/etc/ueventd.rc\n',
                 b' import /vendor/etc/ueventd.rc\n', modern.rstrip(b'\n'),
                 modern + b'import /vendor/etc/ueventd.rc extra\n']
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                tool.patch_ueventd(source)

    def test_fstab_preserves_unrelated_comments_and_bytes(self):
        source = b'# apd retained comment\n\xff unrelated\n' + FSTAB + b'other\trow'
        self.assertEqual(tool.patch_fstab(source), b'# apd retained comment\n\xff unrelated\n' + SAFE_FSTAB + b'other\trow')

    def test_fstab_accepts_horizontal_whitespace_without_rewriting_other_rows(self):
        source = b'# start\n' + SHARED + USERDATA + b' \t' + APD.replace(b' ', b'\t') + b'# end'
        self.assertEqual(tool.patch_fstab(source), b'# start\n' + SAFE_FSTAB + b'# end')
        self.assertEqual(tool.patch_fstab(FSTAB.rstrip(b'\n')), SAFE_FSTAB)

    def test_fstab_does_not_confuse_comments_or_similarly_named_paths_with_apd(self):
        source = (b'# /dev/block/by-name/apd /mnt/vendor/apd ext4 defaults wait\n'
                  + FSTAB + b'/dev/block/by-name/apd_backup /mnt/vendor/apd_backup ext4 defaults wait # apd\n')
        self.assertEqual(
            tool.patch_fstab(source),
            b'# /dev/block/by-name/apd /mnt/vendor/apd ext4 defaults wait\n'
            + SAFE_FSTAB + b'/dev/block/by-name/apd_backup /mnt/vendor/apd_backup ext4 defaults wait # apd\n',
        )

    def test_fstab_refuses_missing_duplicate_drift_and_aliases(self):
        cases = [b'', b'# ' + APD, APD * 2,
                 APD.replace(b' ext4 ', b' f2fs '),
                 APD.replace(b'wait,check,formattable', b'wait,check'),
                 APD.replace(b'commit=1', b'commit=2'),
                 APD.replace(b' /mnt/vendor/apd ', b' /elsewhere '),
                 APD.replace(b'/dev/block/by-name/apd ', b'/dev/block/platform/x/by-name/apd '),
                 APD.rstrip(b'\n') + b' extra\n',
                 APD + b'/dev/other /mnt/vendor/apd ext4 defaults wait\n',
                 APD + b'/dev/block/platform/x/by-name/apd /elsewhere ext4 defaults wait\n',
                 APD + b'LABEL=apd /elsewhere ext4 defaults wait\n',
                 APD + b'PARTLABEL=apd /elsewhere ext4 defaults wait\n',
                 APD + b'/dev/block/by-name/APD /elsewhere ext4 defaults wait\n',
                 APD + b'/dev/block/by-name/apd_alias /mnt/apd ext4 defaults wait\n',
                 APD + b'apd /elsewhere ext4 defaults wait\n']
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                tool.patch_fstab(SHARED + USERDATA + source)

    def test_fstab_requires_all_seven_shared_routes_once_with_expected_mount_and_type(self):
        for row in SHARED.splitlines(keepends=True):
            fields = row.split()
            for source in [FSTAB.replace(row, b''), FSTAB + row,
                           FSTAB.replace(row, b'# ' + row),
                           FSTAB.replace(row, row.replace(fields[0], b'/dev/block/by-name/unknown', 1)),
                           FSTAB.replace(row, row.replace(fields[1], b'/unexpected', 1)),
                           FSTAB.replace(row, row.replace(b' ext4 ', b' f2fs ', 1)),
                           FSTAB.replace(row, row.replace(b',formattable', b'', 1)),
                           FSTAB.replace(row, row.replace(b',formattable', b',formattable,formattable', 1))]:
                with self.subTest(row=row, source=source), self.assertRaises(ValueError):
                    tool.patch_fstab(source)

    def test_fstab_refuses_unknown_formattable_routes_and_mismatched_userdata(self):
        for extra in [b'/dev/block/by-name/other /other ext4 defaults wait,formattable\n',
                      b'/dev/block/by-name/other /other ext4 defaults formattable,wait\n',
                      b'/dev/block/by-name/other /other ext4 formattable wait\n',
                      b'/dev/block/by-name/other /data ext4 defaults wait,formattable\n',
                      b'/dev/block/by-name/userdata /other ext4 defaults wait,formattable\n',
                      USERDATA]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                tool.patch_fstab(FSTAB + extra)
        with self.assertRaises(ValueError):
            tool.patch_fstab(FSTAB.replace(USERDATA, USERDATA.replace(b' ext4 ', b' f2fs ')))

    def test_fstab_removes_only_comma_token_preserving_flag_order_whitespace_and_comments(self):
        source = (FSTAB.replace(b'wait,check,formattable,first_stage_mount',
                               b'formattable,first_stage_mount,wait,check')
                  .replace(b'discard wait,check,formattable\n',
                           b'discard\t  wait,formattable,check\t # keep formattable\n'))
        expected = (SAFE_FSTAB.replace(b'wait,check,first_stage_mount', b'first_stage_mount,wait,check')
                    .replace(b'discard wait,check\n', b'discard\t  wait,check\t # keep formattable\n'))
        self.assertEqual(tool.patch_fstab(source), expected)

    def test_init_removes_only_exact_command_without_success_replacement(self):
        source = (b'on fs\n    mount_all /vendor/etc/fstab.mt6771 --early\n    '
                  + TUNE + b'\n    mount_all /vendor/etc/fstab.mt6771 --late\n# \xff')
        self.assertEqual(
            tool.patch_init(source),
            b'on fs\n    mount_all /vendor/etc/fstab.mt6771 --early\n'
            b'    mount_all /vendor/etc/fstab.mt6771 --late\n# \xff',
        )
        self.assertEqual(tool.patch_init(b'\t ' + TUNE), b'')

    def test_init_preserves_commented_command_and_unrelated_tune2fs(self):
        source = b'# ' + TUNE + b'\n' + TUNE + b'\nexec /system/bin/tune2fs -l /dev/other\n'
        self.assertEqual(tool.patch_init(source), b'# ' + TUNE + b'\nexec /system/bin/tune2fs -l /dev/other\n')

    def test_unrelated_bytes_including_non_lf_separators_are_preserved(self):
        for patcher, valid, expected in [
            (tool.patch_ueventd, b'import /vendor/etc/ueventd.rc\n',
             b'import /vendor/etc/ueventd.rc\nimport /vendor/ueventd.rc\n'),
            (tool.patch_fstab, FSTAB, SAFE_FSTAB),
            (tool.patch_init, TUNE + b'\n', b''),
        ]:
            with self.subTest(patcher=patcher.__name__):
                self.assertEqual(patcher(b'# \xff\v\f\n' + valid + b'# tail\t'),
                                 b'# \xff\v\f\n' + expected + b'# tail\t')

    def test_init_refuses_missing_duplicate_drift_and_other_userdata_tune2fs(self):
        cases = [b'', b'# ' + TUNE, TUNE + b'\n' + TUNE,
                 TUNE.replace(b'-u 10010', b'-u 10011'),
                 TUNE.replace(b'exec ', b'exec\t'), TUNE + b' # changed',
                 TUNE + b'\nexec /system/bin/tune2fs -O other /dev/block/by-name/userdata\n',
                 TUNE + b'\nexec /system/bin/tune2fs -O other /dev/block/platform/x/by-name/userdata\n',
                 TUNE + b'\nexec /system/bin/sh -c "tune2fs -O other /dev/block/by-name/userdata"\n']
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                tool.patch_init(source)

    def test_init_refuses_continued_userdata_mutation_but_preserves_other_continuations(self):
        with self.assertRaises(ValueError):
            tool.patch_init(TUNE + b'\nexec /system/bin/tune2fs -O other \\\n'
                            b'    /dev/block/by-name/userdata\n')
        self.assertEqual(tool.patch_init(TUNE + b'\nexec /other \\\n    argument\n'),
                         b'exec /other \\\n    argument\n')

    def test_all_patches_reject_nul_and_cr_in_any_location(self):
        for patcher, valid in [(tool.patch_ueventd, b'import /vendor/etc/ueventd.rc\n'),
                               (tool.patch_fstab, FSTAB), (tool.patch_init, TUNE + b'\n')]:
            for invalid in [valid + b'# \x00', valid.replace(b'\n', b'\r\n'), valid + b'\r']:
                with self.subTest(patcher=patcher.__name__, invalid=invalid), self.assertRaises(ValueError):
                    patcher(invalid)

    def test_already_patched_inputs_are_refused(self):
        for patcher, valid in [(tool.patch_ueventd, b'import /vendor/etc/ueventd.rc\n'),
                               (tool.patch_fstab, FSTAB), (tool.patch_init, TUNE + b'\n')]:
            result = patcher(valid)
            with self.subTest(patcher=patcher.__name__), self.assertRaises(ValueError):
                patcher(result)


if __name__ == '__main__':
    unittest.main()
