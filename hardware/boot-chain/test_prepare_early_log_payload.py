import hashlib
import unittest
from unittest.mock import patch

import prepare_early_log_payload as payload


class EarlyLogPayloadTests(unittest.TestCase):
    def test_rejects_unknown_baseline(self):
        with self.assertRaisesRegex(ValueError, 'baseline'):
            payload.patch_init(b'on init\n    start logd\n')

    def test_only_inserts_async_start_before_filesystems(self):
        source = b'\non init\n    start logd\n    start lmkd\n\non late-init\n    trigger early-fs\n    trigger late-fs\n'
        with patch.object(payload, 'INIT_SHA256', hashlib.sha256(source).hexdigest()):
            result = payload.patch_init(source)
        self.assertEqual(result.replace(payload.START, b''), source)
        self.assertLess(result.index(b'start titan-diag-kernel'), result.index(b'trigger early-fs'))
        self.assertIn(b'capabilities SYSLOG\n', payload.SERVICE)
        self.assertNotIn(b'exec_start', result)
        self.assertNotIn(b'snapshot', payload.SERVICE)
        self.assertNotIn(b'critical', payload.SERVICE)
        self.assertNotIn(b'reboot', payload.SERVICE)

    def test_wrong_event_order_rejected(self):
        source = b'\non init\n    start logd\n\non late-init\n    trigger late-fs\n    trigger early-fs\n'
        with patch.object(payload, 'INIT_SHA256', hashlib.sha256(source).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'event order'):
                payload.patch_init(source)


if __name__ == '__main__':
    unittest.main()
