import tempfile
from pathlib import Path
import unittest

from integrate_vendor_policy import build, restore_metadata


class VendorPolicyTests(unittest.TestCase):
    def test_changed_source_refused_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.write_bytes(b"wrong")
            with self.assertRaises(ValueError):
                build(source, root / "policy", root / "output")
            self.assertFalse((root / "output").exists())

    def test_symlink_refused_without_reading_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.symlink_to(root / "missing")
            with self.assertRaises(ValueError):
                build(source, root / "policy", root / "output")
            self.assertFalse((root / "output").exists())

    def test_hardlinked_payload_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                restore_metadata("/policy", {"type": "regular", "links": 2}, Path(tmp))

    def test_metadata_restores_all_timestamp_words_and_raw_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            item = {"type": "regular", "links": 1, "same_inode_paths": ["/policy"],
                    "uid": 0, "gid": 0, "permissions": "0644", "flags": 524288,
                    "timestamps_debugfs": [name + ": 0x495c0780:00000000 -- fixed" for name in ("ctime", "atime", "mtime", "crtime")],
                    "xattrs": {"security.selinux": "61626300"}}
            commands = restore_metadata("/policy", item, root)
            self.assertIn('set_inode_field "/policy" mode 0100644', commands)
            self.assertEqual(sum("_extra " in command for command in commands), 4)
            self.assertEqual((root / "policy.security.selinux").read_bytes(), b"abc\0")


if __name__ == "__main__":
    unittest.main()
