import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('led_builder',P/'build_system.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.before=json.loads((P/'test-baseline.json').read_text())
        self.after=copy.deepcopy(self.before)
        new=copy.deepcopy(self.before[b.FINGERPRINT])
        new.update(inode=4408,content_sha256=b.APK)
        self.after[b.TARGET]=new
    def test_valid_only_addition(self): b.compare(self.before,self.after)
    def test_reject_existing_target(self):
        self.before[b.TARGET]=self.after[b.TARGET]
        with self.assertRaises(AssertionError): b.compare(self.before,self.after)
    def test_reject_missing_path(self):
        self.after.pop(b.FINGERPRINT)
        with self.assertRaises(AssertionError): b.compare(self.before,self.after)
    def test_reject_extra_path(self):
        self.after['/system/extra']=self.after[b.TARGET]
        with self.assertRaises(AssertionError): b.compare(self.before,self.after)
    def test_reject_every_existing_metadata_mutation(self):
        for path in self.before:
            for field in self.before[path]:
                after=copy.deepcopy(self.after);after[path][field]='changed'
                with self.subTest(path=path,field=field),self.assertRaises(AssertionError): b.compare(self.before,after)
    def test_reject_overlay_fields(self):
        for field in ('type','permissions','uid','gid','size','links','symlink_target','content_sha256','xattrs','inode','timestamps_debugfs'):
            after=copy.deepcopy(self.after)
            after[b.TARGET][field]=self.before[b.FINGERPRINT]['inode'] if field=='inode' else [] if field in ('xattrs','timestamps_debugfs') else 'changed'
            with self.subTest(field=field),self.assertRaises(AssertionError): b.compare(self.before,after)
    def test_reject_wrong_timestamp_epoch(self):
        self.after[b.TARGET]['timestamps_debugfs'][0]=self.after[b.TARGET]['timestamps_debugfs'][0].replace('495c0780','495c0781')
        with self.assertRaises(AssertionError): b.compare(self.before,self.after)
    def test_reject_duplicate_timestamp_field(self):
        self.after[b.TARGET]['timestamps_debugfs']=[self.after[b.TARGET]['timestamps_debugfs'][0]]*4
        with self.assertRaises(AssertionError): b.compare(self.before,self.after)
    def test_exact_new_inode(self): self.assertEqual(b.check_inode_diff({1:b'a',2:b'b'},{1:b'a',2:b'c'},2),[2])
    def test_reject_second_inode(self):
        with self.assertRaises(AssertionError): b.check_inode_diff({1:b'a',2:b'b'},{1:b'c',2:b'c'},2)
    def test_reject_wrong_inode(self):
        with self.assertRaises(AssertionError): b.check_inode_diff({1:b'a',2:b'b'},{1:b'c',2:b'b'},2)
    def test_reject_no_inode_change(self):
        with self.assertRaises(AssertionError): b.check_inode_diff({1:b'a'},{1:b'a'},1)
    def test_reject_different_inode_set(self):
        with self.assertRaises(AssertionError): b.check_inode_diff({1:b'a'},{2:b'b'},2)
    def test_derivation_pin_mode(self): b.output_pin_mode(True,None)
    def test_reproduction_pin_mode(self): b.output_pin_mode(False,'a'*64)
    def test_reject_bad_pin_modes(self):
        for derive,expected in [(False,None),(True,'a'*64),(False,'a'*63),(False,'A'*64),(False,'z'*64)]:
            with self.subTest(derive=derive,expected=expected),self.assertRaises(ValueError): b.output_pin_mode(derive,expected)
    def test_bundle_and_asset_pins(self):
        b.verify_bundle();self.assertEqual(b.sha(P/'TitanPocketNotificationLight.apk'),b.APK)
        self.assertEqual((P/'TitanPocketNotificationLight.apk').stat().st_size,b.APK_SIZE)
    def test_reused_helpers_unchanged(self):
        upstream=json.loads((P/'upstream-source-manifest.json').read_text())
        for entry in upstream['bundle_files']:
            if entry['path'].startswith(('helpers/','tools/')):
                with self.subTest(path=entry['path']):self.assertEqual(b.sha(P/entry['path']),entry['sha256'])

if __name__=='__main__': unittest.main()
