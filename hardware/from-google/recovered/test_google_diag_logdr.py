import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import unittest


def packet(message=b'fatal fixture', priority=7, log_id=4):
    body=bytes([priority])+b'zygote\0'+message+b'\0'
    return struct.pack('<H H i i I I I I',len(body),28,123,124,100,200,log_id,0)+body


class LogdrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('aarch64-linux-gnu-gcc') or not shutil.which('qemu-aarch64'):
            raise unittest.SkipTest('Requires ARM64 Linux cross GCC and qemu-aarch64')
        cls.build=tempfile.TemporaryDirectory(prefix='logdr-build-')
        cls.binary=Path(cls.build.name)/'reader'
        subprocess.run(['aarch64-linux-gnu-gcc','-DGOOGLE_DIAG_TEST','-Os','-Wall','-Wextra','-Werror',
                        '-Wno-misleading-indentation','-Wno-unused-function','-nostdlib','-static',
                        '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie',
                        '-Wl,--build-id=none','-Wl,-e,_start','-Wl,-z,max-page-size=4096',
                        '-I'+str(Path(__file__).resolve().parents[2]/'boot-chain'),
                        str(Path(__file__).with_name('google_diag_logdr.c')),'-o',str(cls.binary)],check=True)

    @classmethod
    def tearDownClass(cls): cls.build.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ldr-', dir='/tmp')
        self.root=Path(self.temp.name)
        (self.root/'dev/socket').mkdir(parents=True)
        self.parent=self.root/'metadata/titan-pocket-diag'
        self.parent.mkdir(mode=0o700,parents=True)
        self.parent.chmod(0o700)
        (self.root/'test-metadata-facts').write_bytes(struct.pack('=5Q',1,2,2,0xef53,0))
        self.out=self.parent/'logdr-v1'

    def tearDown(self): self.temp.cleanup()

    def run_reader(self,packets=None,delay=0):
        errors=[]
        def server():
            try:
                time.sleep(delay)
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
                    listener.settimeout(4)
                    listener.bind(str(self.root/'dev/socket/logdr')); listener.listen(1)
                    with listener.accept()[0] as peer:
                        self.assertEqual(peer.recv(100),b'stream lids=0,3,4')
                        for value in packets or []:
                            try:peer.sendall(value)
                            except (BrokenPipeError,ConnectionResetError):break
                        time.sleep(2.2)
            except Exception as error: errors.append(error)
        worker=threading.Thread(target=server); worker.start()
        try:
            result=subprocess.run(['qemu-aarch64',str(self.binary),str(self.root),'--logdr'],capture_output=True,timeout=5)
        finally: worker.join(timeout=5)
        if errors: raise errors[0]
        return result

    def test_actual_seqpacket_request_and_exact_packets(self):
        values=[packet(),packet(b'second record')]
        self.assertEqual(self.run_reader(values).returncode,0)
        self.assertEqual((self.out/'android.bin').read_bytes(),b''.join(struct.pack('<I',len(v))+v for v in values))
        self.assertIn('packets=2', (self.out/'status.txt').read_text())
        self.assertEqual(self.out.stat().st_mode&0o777,0o700)
        self.assertEqual((self.out/'android.bin').stat().st_mode&0o777,0o600)

    def test_socket_not_ready_is_retried(self):
        self.assertEqual(self.run_reader([packet()],delay=.3).returncode,0)
        self.assertIn(b'fatal fixture',(self.out/'android.bin').read_bytes())

    def test_low_priority_noise_cannot_fill_capture(self):
        values=[packet(b'noise',3,0),packet(b'info',4,3),packet(b'warning',5,0),packet(b'crash detail',3,4)]
        self.assertEqual(self.run_reader(values).returncode,0)
        expected=b''.join(struct.pack('<I',len(v))+v for v in values[2:])
        self.assertEqual((self.out/'android.bin').read_bytes(),expected)
        self.assertIn('skipped=2',(self.out/'status.txt').read_text())

    def test_malformed_record_is_rejected(self):
        self.assertEqual(self.run_reader([b'bad']).returncode,92)
        self.assertEqual((self.out/'android.bin').read_bytes(),b'')
        self.assertIn('record-short',(self.out/'status.txt').read_text())

    def test_wrong_header_length_is_rejected(self):
        self.assertEqual(self.run_reader([packet()[:-1]]).returncode,92)
        self.assertEqual((self.out/'android.bin').read_bytes(),b'')

    def test_capture_cap_keeps_only_complete_records(self):
        value=packet(b'x'*4000)
        self.assertEqual(self.run_reader([value]*600).returncode,0)
        data=(self.out/'android.bin').read_bytes()
        framed=struct.pack('<I',len(value))+value
        self.assertLessEqual(len(data),2096128)
        self.assertEqual(data,framed*(2096128//len(framed)))
        self.assertIn('capped',(self.out/'status.txt').read_text())

    def test_existing_run_is_not_overwritten(self):
        self.out.mkdir(mode=0o700)
        (self.out/'android.bin').write_bytes(b'retained')
        result=subprocess.run(['qemu-aarch64',str(self.binary),str(self.root),'--logdr'],capture_output=True,timeout=3)
        self.assertEqual(result.returncode,74)
        self.assertEqual((self.out/'android.bin').read_bytes(),b'retained')

    def test_metadata_symlink_is_rejected(self):
        (self.root/'metadata').rename(self.root/'outside')
        (self.root/'metadata').symlink_to(self.root/'outside')
        result=subprocess.run(['qemu-aarch64',str(self.binary),str(self.root),'--logdr'],capture_output=True,timeout=3)
        self.assertEqual(result.returncode,72)
        self.assertFalse((self.root/'outside/titan-pocket-diag/logdr-v1').exists())

    def test_nonmetadata_filesystem_is_rejected(self):
        (self.root/'test-metadata-facts').write_bytes(struct.pack('=5Q',1,1,2,0xef53,0))
        result=subprocess.run(['qemu-aarch64',str(self.binary),str(self.root),'--logdr'],capture_output=True,timeout=3)
        self.assertEqual(result.returncode,87)
        self.assertFalse(self.out.exists())

    def test_no_socket_still_exits_at_deadline(self):
        started=time.monotonic()
        result=subprocess.run(['qemu-aarch64',str(self.binary),str(self.root),'--logdr'],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,90)
        self.assertLess(time.monotonic()-started,4)


if __name__=='__main__': unittest.main()
