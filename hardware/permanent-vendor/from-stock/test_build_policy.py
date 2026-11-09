import hashlib
import json
from pathlib import Path
import unittest
import build_policy as b
import build_stock_vendor as v
import build_mapping as m


class SourceDeltaTests(unittest.TestCase):
    def entry(self, raw, result, operations):
        return dict(source_sha256=hashlib.sha256(raw).hexdigest(),
                    intermediate_sha256=hashlib.sha256(result).hexdigest(), operations=operations)

    def test_multiple_source_edits_preserve_unrelated_lines(self):
        raw = b'one\ntwo\nthree\nfour\n'
        result = b'one\nchanged\nthree\nfour\nadded\n'
        edits = [dict(start_line_zero=1, end_line_zero=2, lines=['changed\n']),
                 dict(start_line_zero=4, end_line_zero=4, lines=['added\n'])]
        self.assertEqual(b.transform(raw, self.entry(raw, result, edits)), result)

    def test_rejects_wrong_source(self):
        entry = self.entry(b'one\n', b'two\n', [])
        with self.assertRaisesRegex(ValueError, 'input hash'):
            b.transform(b'unrelated\n', entry)

    def test_rejects_wrong_result(self):
        entry = self.entry(b'one\n', b'two\n', [])
        with self.assertRaisesRegex(ValueError, 'output hash'):
            b.transform(b'one\n', entry)

    def test_rejects_overlapping_edits(self):
        raw = b'one\ntwo\n'
        edits = [dict(start_line_zero=0, end_line_zero=2, lines=[]),
                 dict(start_line_zero=1, end_line_zero=2, lines=[])]
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            b.transform(raw, self.entry(raw, b'', edits))

    def test_comparison_keeps_metadata_and_content(self):
        entry = dict(inode=5, allocated_512_blocks=4, uid=0, permissions='0644',
                     xattrs=['label'], content_sha256='one')
        other = dict(entry, inode=8, allocated_512_blocks=8)
        self.assertEqual(v.normalize(entry), v.normalize(other))
        other['uid'] = 1
        self.assertNotEqual(v.normalize(entry), v.normalize(other))
        other = dict(entry, content_sha256='two')
        self.assertNotEqual(v.normalize(entry), v.normalize(other))


class MappingTests(unittest.TestCase):
    def test_parser_preserves_nested_forms_and_drops_comments(self):
        self.assertEqual(m.forms(b';comment\n(typeattributeset a (b c))'),
                         [['typeattributeset', 'a', ['b', 'c']]])

    def test_parser_rejects_unbalanced_forms(self):
        for raw in [b')', b'(type foo', b'type']:
            with self.assertRaises(ValueError):
                m.forms(raw)

    def test_duplicate_attributes_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            m.attribute_sets([['typeattributeset', 'a', ['b']],
                              ['typeattributeset', 'a', ['c']]])

    def test_mapping_rejects_changed_source(self):
        with self.assertRaisesRegex(ValueError, 'source hash'):
            m.build(b'changed', b'', b'', b'')


if __name__ == '__main__':
    unittest.main()
