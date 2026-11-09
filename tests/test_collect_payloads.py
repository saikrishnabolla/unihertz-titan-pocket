import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import collect_payloads as c

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.file = self.root / 'payload'
        self.file.write_bytes(b'payload')
        self.digest = hashlib.sha256(b'payload').hexdigest()
        self.recipe = self.root / 'recipe.json'
        self.recipe.write_text(json.dumps({'files': [{'path': '/system/file', 'sha256': self.digest, 'size': 7}]}))
        self.mapping = self.root / 'map.json'
        self.mapping.write_text(json.dumps({self.digest: 'payload'}))

    def test_map_paths_resolve_beside_the_map(self):
        self.assertEqual(c.collect(self.recipe, [self.mapping], []), {self.digest: str(self.file)})

    def test_file_and_map_must_agree(self):
        self.assertEqual(c.collect(self.recipe, [self.mapping], [self.file]), {self.digest: str(self.file)})
        self.file.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            c.collect(self.recipe, [self.mapping], [])

    def test_missing_or_extra_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing rebuilt files'):
            c.collect(self.recipe, [], [])
        self.mapping.write_text(json.dumps({'0' * 64: 'payload'}))
        with self.assertRaisesRegex(ValueError, 'outside the pinned recipe'):
            c.collect(self.recipe, [self.mapping], [])

    def test_symlink_payload_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.file)
        self.mapping.write_text(json.dumps({self.digest: 'link'}))
        with self.assertRaisesRegex(ValueError, 'type or size'):
            c.collect(self.recipe, [self.mapping], [])

if __name__ == '__main__':
    unittest.main()
