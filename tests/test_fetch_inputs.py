import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('fetch_inputs', Path(__file__).resolve().parents[1] / 'tools/fetch_inputs.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class Response(io.BytesIO):
    def geturl(self):
        return 'https://example.org/file'


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.data = b'input fixture'
        self.entry = dict(filename='fixture.bin', bytes=len(self.data), sha256=hashlib.sha256(self.data).hexdigest(), url='https://example.org/file')

    def run_fetch(self, data=None):
        return f.fetch(self.entry, self.output, lambda *a, **k: Response(self.data if data is None else data))

    def test_verified_download_and_cache(self):
        path = self.run_fetch()
        self.assertEqual(path.read_bytes(), self.data)
        self.assertEqual(f.fetch(self.entry, self.output, lambda *a, **k: self.fail('Cache downloaded again')), path)

    def test_bad_digest_never_published(self):
        self.entry['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.run_fetch()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_size_bound_and_short_read(self):
        for data in [self.data + b'x', self.data[:-1]]:
            with self.assertRaises(ValueError):
                self.run_fetch(data)
            self.assertEqual(list(self.output.iterdir()), [])

    def test_existing_file_preserved(self):
        path = self.output / self.entry['filename']
        path.write_bytes(b'valuable input')
        with self.assertRaises(ValueError):
            self.run_fetch()
        self.assertEqual(path.read_bytes(), b'valuable input')

    def test_symlink_rejected(self):
        other = self.output / 'other'
        other.write_bytes(b'keep')
        (self.output / self.entry['filename']).symlink_to(other)
        with self.assertRaises(ValueError):
            self.run_fetch()
        self.assertEqual(other.read_bytes(), b'keep')

    def test_untrusted_filename(self):
        for name in ['../file', '/tmp/file', '.', '..', 'sub/file', 'sub\\file']:
            with self.subTest(name=name):
                self.entry['filename'] = name
                with self.assertRaises(ValueError):
                    self.run_fetch()

    def test_insecure_or_credential_url(self):
        for url in ['http://example.org/file', 'https://secret@example.org/file', 'file:///tmp/file']:
            self.entry['url'] = url
            with self.assertRaises(ValueError):
                self.run_fetch()


if __name__ == '__main__':
    unittest.main()
