import gzip
import struct
import unittest

import inspect_kernel_bpf as k


def boot_image(kernel_blob, page_size=2048):
    header = bytearray(page_size)
    header[:8] = b"ANDROID!"
    struct.pack_into("<I", header, 8, len(kernel_blob))
    struct.pack_into("<I", header, 36, page_size)
    struct.pack_into("<I", header, 40, 2)
    return bytes(header) + kernel_blob


class KernelScan(unittest.TestCase):
    def test_extracts_gzip_kernel_and_finds_unpatched_sequence(self):
        seq = bytes.fromhex(k.PATCHER_SEQUENCES["4.14"][0])
        image = b"\0" * 100 + seq + b"\0" * 50
        info, out = k.extract_kernel(boot_image(gzip.compress(image)))
        self.assertEqual(out, image)
        self.assertEqual(info["kernel_blob_format"], "gzip")
        self.assertEqual(k.find_all(out, seq), [100])

    def test_rejects_non_boot_image(self):
        with self.assertRaises(SystemExit):
            k.extract_kernel(b"not a boot image")


class Eligibility(unittest.TestCase):
    def test_kernel_and_api_ranges_are_half_open(self):
        entry = {"min_kver": k.kver("4.9"), "max_kver": k.kver("4.19"),
                 "min_api": 3300, "max_api": 3500}
        self.assertTrue(k.eligible(entry, k.kver("4.14.186"), 3400))
        self.assertFalse(k.eligible(entry, k.kver("4.14.186"), 3700))
        self.assertFalse(k.eligible(entry, k.kver("4.19"), 3400))

    def test_kver_encoding_matches_bpf_helpers(self):
        self.assertEqual(k.kver("4.14.186"), (4 << 24) + (14 << 16) + 186)
        self.assertEqual(k.kver_text(k.kver("4.14.186")), "4.14.186")


if __name__ == "__main__":
    unittest.main()
