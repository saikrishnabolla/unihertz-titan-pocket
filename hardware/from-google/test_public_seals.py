import hashlib,json,struct,tempfile,unittest,zipfile
from pathlib import Path
import public_seals as s
from build_source_edits import patch

class SealTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.r=Path(self.temp.name)
 def zip(self,name,payload=b'abc'*100):
  p=self.r/name
  with zipfile.ZipFile(p,'w') as z:
   z.writestr('classes.dex',payload,compress_type=zipfile.ZIP_DEFLATED)
   z.writestr('META-INF/CERT.RSA',b'public certificate and signature')
  return p
 def test_zip_repacked_unsigned_restores_exact_bytes(self):
  signed=self.zip('signed.zip');seal=self.r/'seal.json';s.export_zip(signed,seal)
  unsigned=self.r/'unsigned.zip'
  with zipfile.ZipFile(unsigned,'w') as z:z.writestr('classes.dex',b'abc'*100)
  result=self.r/'result.zip';s.apply_zip(unsigned,seal,result)
  self.assertEqual(result.read_bytes(),signed.read_bytes())
 def test_changed_code_rejected(self):
  signed=self.zip('signed.zip');seal=self.r/'seal.json';s.export_zip(signed,seal)
  bad=self.zip('bad.zip',b'changed code')
  with self.assertRaisesRegex(ValueError,'entry differs'):s.apply_zip(bad,seal,self.r/'result')
  self.assertFalse((self.r/'result').exists())
 def test_non_signature_payload_embedding_rejected(self):
  signed=self.zip('signed.zip');seal=self.r/'seal.json';v=s.export_zip(signed,seal)
  v['entries'][0]['public_bytes_b64']=s.b64(b'abc'*100);seal.write_text(json.dumps(v))
  with self.assertRaisesRegex(ValueError,'non-signature'):s.apply_zip(signed,seal,self.r/'result')
 def test_bad_final_seal_hash_rejected(self):
  signed=self.zip('signed.zip');seal=self.r/'seal.json';v=s.export_zip(signed,seal)
  v['sha256']='0'*64;seal.write_text(json.dumps(v))
  with self.assertRaisesRegex(ValueError,'hash differs'):s.apply_zip(signed,seal,self.r/'result')
 def test_extra_unsigned_entry_rejected(self):
  signed=self.zip('signed.zip');seal=self.r/'seal.json';s.export_zip(signed,seal)
  extra=self.zip('extra.zip')
  with zipfile.ZipFile(extra,'a') as z:z.writestr('extra-code.dex',b'code')
  with self.assertRaisesRegex(ValueError,'Extra unsigned'):s.apply_zip(extra,seal,self.r/'result')
 def avb(self):
  raw=bytearray(4096);raw[1080:1082]=b'\x53\xef';struct.pack_into('<I',raw,1028,4);struct.pack_into('<I',raw,1048,0)
  raw.extend(b'AVB0'+bytes(252));raw.extend(struct.pack('>4sIIQQQ28s',b'AVBf',1,0,4096,4096,256,bytes(28)))
  p=self.r/'avb.img';p.write_bytes(raw);return p
 def test_avb_rebuilt_filesystem_restores_exact_bytes(self):
  source=self.avb();seal=self.r/'seal.json';s.export_avb(source,seal);fs=self.r/'fs';fs.write_bytes(source.read_bytes()[:4096])
  out=self.r/'result';s.apply_avb(fs,seal,out);self.assertEqual(source.read_bytes(),out.read_bytes())
 def test_changed_filesystem_rejected(self):
  source=self.avb();seal=self.r/'seal.json';s.export_avb(source,seal);fs=self.r/'fs';data=bytearray(source.read_bytes()[:4096]);data[50]=1;fs.write_bytes(data)
  with self.assertRaisesRegex(ValueError,'filesystem differs'):s.apply_avb(fs,seal,self.r/'result')
 def test_avb_split_cannot_embed_filesystem_payload(self):
  source=self.avb();data=bytearray(source.read_bytes());struct.pack_into('>Q',data,len(data)-52,2048);source.write_bytes(data)
  with self.assertRaisesRegex(ValueError,'EXT4 geometry'):s.export_avb(source,self.r/'seal')
 def test_existing_output_untouched(self):
  p=self.r/'exists';p.write_bytes(b'keep')
  with self.assertRaises(ValueError):s.new_file(p,b'bad')
  self.assertEqual(p.read_bytes(),b'keep')

class PatchTests(unittest.TestCase):
 def spec(self):
  return {'path':'/system/file','source_sha256':s.sha(b'abc'),'sha256':s.sha(b'aXYZc'),'size':5,
   'edits':[{'offset':1,'remove':1,'old_sha256':s.sha(b'b'),'hex':b'XYZ'.hex()}]}
 def test_patch_changes_only_reviewed_span(self):self.assertEqual(patch(b'abc',self.spec()),b'aXYZc')
 def test_wrong_original_rejected(self):
  with self.assertRaisesRegex(ValueError,'Source hash'):patch(b'abd',self.spec())
 def test_span_out_of_bounds_rejected(self):
  v=self.spec();v['edits'][0]['offset']=4
  with self.assertRaisesRegex(ValueError,'overlapping edit'):patch(b'abc',v)
 def test_hash_cannot_be_a_path(self):
  v=self.spec();v['sha256']='../outside'
  with self.assertRaisesRegex(ValueError,'Invalid SHA256'):patch(b'abc',v)
 def test_corrupt_patch_rejected(self):
  v=self.spec();v['edits'][0]['hex']='00'
  with self.assertRaisesRegex(ValueError,'Rebuilt hash'):patch(b'abc',v)
if __name__=='__main__':unittest.main()
