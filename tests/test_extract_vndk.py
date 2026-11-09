# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('extract_vndk', Path(__file__).parents[1] / 'tools/extract_vndk.py')
x = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(x)


class ExtractVndkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source, self.output = self.root / 'system.img', self.root / 'out'
        self.source.write_bytes(b'source')
        for name, value in [('SOURCE_BYTES', 6), ('SOURCE_SHA256', hashlib.sha256(b'source').hexdigest()),
                            ('APEX_SHA256', hashlib.sha256(b'apex').hexdigest())]:
            mocked = patch.object(x, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.result = subprocess.CompletedProcess([], 0, stdout=b'apex', stderr=b'debugfs 1.47.4 (test)\n')

    def test_extracts_exact_apex_and_relative_payload_map(self):
        with patch.object(x.subprocess, 'run', return_value=self.result) as run:
            report = x.extract(self.source, self.output, '/usr/sbin/debugfs')
        self.assertEqual((self.output / x.FILENAME).read_bytes(), b'apex')
        self.assertEqual(json.loads((self.output / 'payloads.json').read_text()),
                         {x.APEX_SHA256: x.FILENAME})
        self.assertFalse(report['apex_modified'])
        self.assertEqual(run.call_args.args[0][2], 'cat ' + x.INSIDE)

    def test_rejects_wrong_source_before_extraction(self):
        self.source.write_bytes(b'wrong!')
        with patch.object(x.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'source size or hash'):
                x.extract(self.source, self.output, 'debugfs')
            run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_rejects_existing_output(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            x.extract(self.source, self.output, 'debugfs')

    def test_rejects_symlink_source_and_output(self):
        for source_link in [True, False]:
            link = self.root / ('source-link' if source_link else 'output-link')
            link.symlink_to(self.source if source_link else self.root / 'absent')
            with self.assertRaisesRegex(ValueError, 'Symlink'):
                x.extract(link if source_link else self.source,
                          self.output if source_link else link, 'debugfs')

    def test_rejects_malformed_or_failed_debugfs_response(self):
        for code, stdout, stderr in [(1, b'apex', b'debugfs 1.0\n'),
                                     (0, b'apex', b'debugfs 1.0\nFile not found\n'),
                                     (0, b'apex', b''), (0, b'apex', b'\xff'),
                                     (0, b'changed', b'debugfs 1.0\n')]:
            with self.assertRaises(ValueError):
                x.validate_response(subprocess.CompletedProcess([], code, stdout, stderr))

    def test_rejects_source_replacement_during_read(self):
        def replace(*args, **kwargs):
            self.source.unlink()
            self.source.write_bytes(b'source')
            return self.result
        with patch.object(x.subprocess, 'run', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'Source changed'):
                x.extract(self.source, self.output, 'debugfs')
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
