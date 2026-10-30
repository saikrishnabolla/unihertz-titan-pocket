import hashlib
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import prepare_bpf_boot_derivative as repacker


def fixture():
    image = bytearray(0x15E900)
    for offset, (old, _) in repacker.PATCHES.items():
        struct.pack_into("<I", image, offset, old)
    image = bytes(image)
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    kernel = compressor.compress(image) + compressor.flush()
    parts = {"kernel": kernel, "ramdisk": b"private ramdisk", "dtb": b"boot-dtb"}
    header = bytearray(2048)
    header[:8] = b"ANDROID!"
    for offset, value in ((8, len(kernel)), (16, len(parts["ramdisk"])), (36, 2048),
                          (40, 2), (1644, 1660), (1648, len(parts["dtb"]))):
        struct.pack_into("<I", header, offset, value)
    header[576:608] = repacker.legacy_id(parts)
    data = header
    for name in ("kernel", "ramdisk", "dtb"):
        data.extend(parts[name])
        data.extend(bytes(repacker.align(len(data), 2048) - len(data)))
    vb_offset = len(data)
    data.extend(b"AVB0" + bytes(252))
    data.extend(bytes(32768 - 64 - len(data)))
    footer = bytearray(64)
    footer[:4] = b"AVBf"
    struct.pack_into(">IIQQQ", footer, 4, 1, 0, vb_offset, vb_offset, 256)
    data.extend(footer)
    return bytes(data), image


class RepackerTests(unittest.TestCase):
    def test_sections_id_and_relocation(self):
        source, _ = fixture()
        before = repacker.parse_boot(source)
        kernel = before["parts"]["kernel"] + bytes(5000)
        candidate, _, after = repacker.repack(source, kernel)
        self.assertEqual(len(candidate), len(source))
        self.assertEqual(after["offsets"]["ramdisk"] - before["offsets"]["ramdisk"], 6144)
        for name in ("ramdisk", "dtb"):
            self.assertEqual(after["parts"][name], before["parts"][name])
        self.assertEqual(after["vbmeta"], before["vbmeta"])
        digest = hashlib.sha1()
        for part in (kernel, b"private ramdisk", b"", b"", b"boot-dtb"):
            digest.update(part)
            digest.update(struct.pack("<I", len(part)))
        self.assertEqual(candidate[576:608], digest.digest() + bytes(12))
        self.assertEqual(struct.unpack_from(">QQ", candidate, len(candidate) - 52),
                         (after["vb_offset"], after["vb_offset"]))

    def test_bounds_and_unsupported_layout(self):
        source, _ = fixture()
        for offset, value in ((8, 0xFFFFFFFF), (36, 4096), (40, 3), (24, 4), (1632, 8)):
            invalid = bytearray(source)
            struct.pack_into("<I", invalid, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                repacker.parse_boot(invalid)
        with self.assertRaises(ValueError):
            repacker.repack(source, bytes(len(source)))
        with self.assertRaises(ValueError):
            repacker.parse_boot(source[:100])
        invalid = bytearray(source)
        invalid[576] ^= 1
        with self.assertRaisesRegex(ValueError, "ID"):
            repacker.parse_boot(invalid)
        for offset in (1660, 32768 - 65):
            invalid = bytearray(source)
            invalid[offset] = 1
            with self.subTest(padding=offset), self.assertRaisesRegex(ValueError, "padding"):
                repacker.parse_boot(invalid)

    def test_deterministic_gzip_and_appended_tail(self):
        source, image = fixture()
        blob = repacker.parse_boot(source)["parts"]["kernel"] + b"appended-dtb-tail"
        a, size = repacker.compress_kernel(blob, image)
        b, _ = repacker.compress_kernel(blob, image)
        self.assertEqual(a, b)
        self.assertEqual(a[:10], blob[:10])
        self.assertEqual(repacker.unpack_kernel(a), (image, b"appended-dtb-tail", size))
        with self.assertRaises(ValueError):
            repacker.unpack_kernel(a[:size - 1])
        with self.assertRaises(ValueError):
            repacker.unpack_kernel(b"not gzip")
        with patch.object(repacker, "CAPACITY", 32):
            with self.assertRaisesRegex(ValueError, "oversized"):
                repacker.unpack_kernel(a)

    def test_strict_image_pin_and_original_words(self):
        _, image = fixture()
        with self.assertRaisesRegex(ValueError, "hash"):
            repacker.patch_image(image)
        with patch.object(repacker, "IMAGE_HASH", repacker.sha(image)):
            fixed = repacker.patch_image(image)
        self.assertEqual(len(fixed), len(image))
        self.assertEqual(sum(a != b for a, b in zip(image, fixed)), 6)
        invalid = bytearray(image)
        invalid[0x15E814] ^= 1
        with patch.object(repacker, "IMAGE_HASH", repacker.sha(invalid)):
            with self.assertRaisesRegex(ValueError, "instruction"):
                repacker.patch_image(invalid)
        with patch.object(repacker, "IMAGE_HASH", repacker.sha(b"short")):
            with self.assertRaisesRegex(ValueError, "bounds"):
                repacker.patch_image(b"short")

    def test_output_refuses_overwrite_symlinks_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "existing").mkdir()
            (root / "link").symlink_to(root / "existing", target_is_directory=True)
            (root / "dangling").symlink_to(root / "missing")
            (root / "file").touch(mode=0o600)
            for output in (root / "existing", root / "link", root / "link" / "child",
                           root / "dangling", root / "file"):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    repacker.check_output_path(output)
            with self.assertRaisesRegex(ValueError, "repository"):
                repacker.check_output_path(Path(__file__).parent / "private-artifact")

    def test_negative_source_and_private_end_to_end(self):
        source, image = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path, stock_path = root / "source", root / "stock"
            for path in (source_path, stock_path):
                path.touch(mode=0o600)
                path.write_bytes(source)
            with self.assertRaisesRegex(ValueError, "source hash"):
                repacker.generate(source_path, stock_path, root / "rejected")
            self.assertFalse((root / "rejected").exists())
            with patch.object(repacker, "SOURCE_HASH", repacker.sha(source)):
                with self.assertRaisesRegex(ValueError, "stock source hash"):
                    repacker.generate(source_path, stock_path, root / "rejected")
            self.assertFalse((root / "rejected").exists())
            with patch.multiple(repacker, SOURCE_HASH=repacker.sha(source),
                                STOCK_HASH=repacker.sha(source), IMAGE_HASH=repacker.sha(image)):
                report = repacker.generate(source_path, stock_path, root / "out")
                with self.assertRaisesRegex(ValueError, "overwrite"):
                    repacker.generate(source_path, stock_path, root / "out")
            self.assertEqual(source_path.read_bytes(), source)
            self.assertEqual(report["candidate_bytes"], len(source))
            self.assertEqual(stat.S_IMODE((root / "out").stat().st_mode), 0o700)
            for path in (root / "out").iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_input_is_bounded_regular_not_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.touch(mode=0o600)
            with self.assertRaisesRegex(ValueError, "bounded regular"):
                repacker.read_input(source)
            source.write_bytes(b"abc")
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                repacker.read_input(link)
            with patch.object(repacker, "CAPACITY", 2):
                with self.assertRaisesRegex(ValueError, "bounded regular"):
                    repacker.read_input(source)
            self.assertEqual(repacker.read_input(source), b"abc")

    def test_direct_branch_scan(self):
        image = bytearray(0x15E830)
        target = 0x15E814
        for offset, base, bits in ((0, 0x14000000, 26), (4, 0x94000000, 26)):
            struct.pack_into("<I", image, offset, base | ((target - offset) // 4 & ((1 << bits) - 1)))
        self.assertEqual([entry["to"] for entry in repacker.branch_targets(image)],
                         [hex(target), hex(target)])


if __name__ == "__main__":
    unittest.main()
