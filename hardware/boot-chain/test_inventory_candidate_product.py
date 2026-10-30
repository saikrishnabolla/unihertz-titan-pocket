import unittest

from inventory_candidate_product import parse_listing, parse_stat, quote, split_batch


class InventoryTests(unittest.TestCase):
    def test_zero_exit_error_is_not_absence(self):
        with self.assertRaises(ValueError):
            split_batch(['stat "/missing"'], 'debugfs: stat "/missing"\n',
                        'debugfs 1.47.0 (5-Feb-2023)\n/missing: File not found by ext2_lookup\n', 0)

    def test_empty_output_is_not_empty_directory(self):
        with self.assertRaises(ValueError):
            parse_listing("")

    def test_listing_modes_owners_and_hardlink_identity(self):
        rows = parse_listing('/2/040755/0/0/.//\n/9/100640/1000/1001/a b/17/\n/9/100640/1000/1001/c/17/\n')
        self.assertEqual(rows[0], dict(inode=9, mode="100640", uid=1000, gid=1001, name="a b", listed_size=17))
        self.assertEqual(rows[0]["inode"], rows[1]["inode"])

    def test_bad_listing_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_listing("File not found")

    def test_stat_metadata(self):
        value = parse_stat('Inode: 51   Type: symlink    Mode:  0644   Flags: 0x0\n'
                           'User: 0   Group: 2000   Project: 0   Size: 15\n'
                           'Links: 2   Blockcount: 0\n'
                           ' ctime: 0x495c0780:00000000 -- Thu Jan  1 00:00:00 2009\n'
                           '  security.selinux (26) = "u:object_r:system_file:s0\\000"\n'
                           'Fast link dest: "/system/product"\n')
        self.assertEqual((value["inode"], value["gid"], value["links"]), (51, 2000, 2))
        self.assertEqual(value["symlink_target"], "/system/product")
        self.assertEqual(value["xattrs"][0]["name"], "security.selinux")
        self.assertEqual(len(value["timestamps_debugfs"]), 1)

    def test_incomplete_stat_rejected(self):
        with self.assertRaises(ValueError):
            parse_stat("Inode: 4")

    def test_unsupported_or_duplicate_xattr_is_not_omitted(self):
        base = ('Inode: 4 Type: regular Mode: 0644\n'
                'User: 0 Group: 0 Size: 1\nLinks: 1 Blockcount: 8\nExtended attributes:\n')
        for attrs in ['  user.custom-name (1) = "a"\n',
                      '  unexpected attribute output\n',
                      '  security.selinux (1) = "a"\n  security.selinux (1) = "b"\n']:
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                parse_stat(base + attrs)

    def test_command_boundaries_required(self):
        with self.assertRaises(ValueError):
            split_batch(["stat x"], "", "")
        self.assertEqual(split_batch(["stat x"], "debugfs: stat x\nhello\n", "debugfs 1.47.0 (5-Feb-2023)\n"), ["hello\n"])

    def test_paths_cannot_inject_commands(self):
        self.assertEqual(quote("/a b"), '"/a b"')
        with self.assertRaises(ValueError):
            quote('/a"\nwrite anything')


if __name__ == "__main__":
    unittest.main()
