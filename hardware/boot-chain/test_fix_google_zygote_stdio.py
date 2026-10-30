import unittest
from fix_google_zygote_stdio import remove_kernel_stdio


class Tests(unittest.TestCase):
    def test_only_experimental_option_removed(self):
        original=b'service zygote /system/bin/app_process64\n    stdio_to_kmsg\n    class main\n    user root\n'
        self.assertEqual(remove_kernel_stdio(original),b'service zygote /system/bin/app_process64\n    class main\n    user root\n')

    def test_absent_or_duplicate_option_rejected(self):
        for value in (b'service zygote\n',b'    stdio_to_kmsg\n'*2):
            with self.assertRaises(ValueError):remove_kernel_stdio(value)
