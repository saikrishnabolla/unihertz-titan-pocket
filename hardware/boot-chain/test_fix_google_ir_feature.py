import unittest
from fix_google_ir_feature import disable_ir_feature


class Tests(unittest.TestCase):
    def test_only_one_unavailable_feature_is_added(self):
        source=b'<?xml version="1.0"?>\n<permissions>\n    <group gid="net_raw" />\n</permissions>\n'
        expected=b'<?xml version="1.0"?>\n<permissions>\n    <group gid="net_raw" />\n    <unavailable-feature name="android.hardware.consumerir" />\n</permissions>\n'
        self.assertEqual(disable_ir_feature(source),expected)

    def test_existing_feature_or_other_root_rejected(self):
        for value in (b'<config/>',b'<permissions><feature name="android.hardware.consumerir"/></permissions>',
                      b'<permissions><unavailable-feature name="android.hardware.consumerir"/></permissions>'):
            with self.assertRaises(ValueError):disable_ir_feature(value)
