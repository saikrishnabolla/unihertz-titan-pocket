import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sign_google_cgroup_system as signer
import sign_google_dsu_pair as pair
import sign_google_virt_system as virt

AVBTOOL=Path('/tmp/opencode/titan-pocket-stock-2023010520/verify-tools/avbtool-android13.py')


class CgroupSignerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='google-cgroup-sign-test-',)
        self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)
        self.prepared=self.root/'prepared'; self.prepared.mkdir(mode=0o700)
        self.image=self.prepared/'system.ext4'
        with self.image.open('wb') as stream: stream.truncate(4*1024**2)
        self.image.chmod(0o600)
        subprocess.run(['/usr/sbin/mke2fs','-q','-t','ext4','-b','4096','-F',str(self.image)],check=True,capture_output=True)
        self.key=self.root/'fixture.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(self.key)],check=True,capture_output=True)
        self.key.chmod(0o600)
        public=subprocess.check_output(['openssl','pkey','-in',str(self.key),'-pubout'])
        self.digest=pair.sha(self.image)
        for obj,name,value in [(signer,'FS_BYTES',4*1024**2),(signer,'PARTITION_BYTES',8*1024**2),
                               (signer,'FILESYSTEM_SHA',self.digest),(pair,'PUBLIC_KEY_PEM_SHA',hashlib.sha256(public).hexdigest())]:
            p=patch.object(obj,name,value);p.start();self.addCleanup(p.stop)

    def run_sign(self,**changes):
        args={'prepared':self.prepared,'key':self.key,'avbtool':AVBTOOL};args.update(changes)
        return signer.build(**args)

    def test_real_crypto_prefix_and_no_second_full_copy(self):
        identity=self.image.stat().st_ino
        result=self.run_sign(); final=self.prepared/'system.img'
        self.assertEqual(final.stat().st_ino,identity)
        self.assertEqual(pair.sha(final,4*1024**2),self.digest)
        self.assertEqual(final.stat().st_size,8*1024**2)
        self.assertEqual(final.stat().st_mode&0o777,0o600)
        self.assertFalse(self.image.exists())
        self.assertEqual(json.loads((self.prepared/'signing-report.json').read_text()),result)
        pair.run(['python3',AVBTOOL,'verify_image','--image',final,'--key',self.prepared/'public.pem'])

    def test_wrong_prefix_refused_before_marker_or_writes(self):
        with patch.object(signer,'FILESYSTEM_SHA','0'*64),self.assertRaisesRegex(ValueError,'literal'):
            self.run_sign()
        self.assertFalse((self.prepared/'signing-intent.json').exists())
        self.assertEqual(pair.sha(self.image),self.digest)

    def test_virt_wrapper_keeps_its_own_literal_pin(self):
        self.assertEqual(virt.FILESYSTEM_SHA,'adc85169c29e968ad4c5a4be95b1b36327a952dc51b63323c3edf3c16888249f')
        with self.assertRaisesRegex(ValueError,'literal virt-EXT4'):
            virt.build(self.prepared,self.key,AVBTOOL)
        self.assertFalse((self.prepared/'signing-intent.json').exists())
        self.assertEqual(pair.sha(self.image),self.digest)

    def test_explicit_variant_signs_real_tiny_fixture(self):
        with patch.object(virt,'FILESYSTEM_SHA',self.digest):
            report=virt.build(self.prepared,self.key,AVBTOOL)
        self.assertIn('virt-EXT4',report['scope'])
        self.assertEqual(pair.sha(self.prepared/'system.img',4*1024**2),self.digest)

    def test_wrong_key_identity_refused_before_image_write(self):
        with patch.object(pair,'PUBLIC_KEY_PEM_SHA','0'*64),self.assertRaisesRegex(ValueError,'retained guest-image key'):
            self.run_sign()
        self.assertEqual(pair.sha(self.image),self.digest)
        self.assertFalse((self.prepared/'signing-intent.json').exists())

    def test_capacity_and_low_space_refused_before_marker(self):
        with patch.object(signer,'PARTITION_BYTES',4*1024**2),self.assertRaisesRegex(ValueError,'capacity'):
            self.run_sign()
        usage=shutil.disk_usage(self.root)
        with patch.object(signer.shutil,'disk_usage',return_value=usage._replace(free=0)),self.assertRaisesRegex(ValueError,'budget'):
            self.run_sign()
        self.assertFalse((self.prepared/'signing-intent.json').exists())
        self.assertEqual(pair.sha(self.image),self.digest)

    def test_marker_and_existing_output_refuse_repetition(self):
        marker=self.prepared/'signing-intent.json';marker.write_text('prior operation')
        with self.assertRaisesRegex(ValueError,'prior intent'):
            self.run_sign()
        self.assertEqual(marker.read_text(),'prior operation')

    def test_image_host_hardlink_refused(self):
        alias=self.prepared/'alias';alias.hardlink_to(self.image)
        with self.assertRaisesRegex(ValueError,'one host link'):
            self.run_sign()

    def test_image_and_key_modes_refused(self):
        self.image.chmod(0o640)
        with self.assertRaisesRegex(ValueError,'0600'):
            self.run_sign()
        self.image.chmod(0o600);self.key.chmod(0o640)
        with self.assertRaisesRegex(ValueError,'0600'):
            self.run_sign()

    def test_wrong_tool_refused_before_marker(self):
        bad=self.root/'wrong.py';bad.write_text('raise RuntimeError("never run")')
        with self.assertRaisesRegex(ValueError,'avbtool'):
            self.run_sign(avbtool=bad)
        self.assertFalse((self.prepared/'signing-intent.json').exists())

    def test_final_rename_failure_retains_candidate_and_marker(self):
        with patch.object(pair,'publish',side_effect=OSError('fixture publication failure')),self.assertRaises(OSError):
            self.run_sign()
        self.assertTrue(self.image.exists())
        self.assertTrue((self.prepared/'signing-intent.json').exists())
        self.assertFalse((self.prepared/'system.img').exists())
        with self.assertRaisesRegex(ValueError,'prior intent'):
            self.run_sign()


class LiteralPins(unittest.TestCase):
    def test_production_cgroup_filesystem_identity(self):
        self.assertEqual(signer.FILESYSTEM_SHA,'eddcbe56c9c32e21ab75dfea04c998b6d4044923fd60b3763dfaa85abf3ff589')
        self.assertEqual((signer.FS_BYTES,signer.PARTITION_BYTES),(3221225472,3288334336))
