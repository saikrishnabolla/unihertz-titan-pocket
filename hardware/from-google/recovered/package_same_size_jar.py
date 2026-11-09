"""Package one reviewed DEX in a new JAR of the original byte length."""
from pathlib import Path
import copy,hashlib,io,json,struct,sys,zipfile,zlib
SOURCE_SHA='bb8c1100ede1f5c0c310a5818e5d6cc7ebd0d68d427b374fa6b0b0e1f3c10a62'
def require(ok,message):
 if not ok:raise ValueError(message)
def dex_check(b):
 require(b[:8]==b'dex\n039\0','Unexpected DEX version')
 require(struct.unpack_from('<I',b,32)[0]==len(b),'DEX size mismatch')
 require(b[12:32]==hashlib.sha1(b[32:]).digest(),'DEX SHA1 mismatch')
 require(struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff,'DEX Adler32 mismatch')
def build(source,dex,output):
 original=source.read_bytes();require(hashlib.sha256(original).hexdigest()==SOURCE_SHA,'Unreviewed original JAR')
 b=dex.read_bytes();dex_check(b);buf=io.BytesIO()
 with zipfile.ZipFile(io.BytesIO(original)) as old,zipfile.ZipFile(buf,'w') as new:
  names=old.namelist();require(len(names)==len(set(names)) and 'classes.dex' in names,'Bad entry inventory')
  new.comment=old.comment
  for e in old.infolist():
   n=copy.copy(e);data=b if e.filename=='classes.dex' else old.read(e)
   if e.filename=='classes.dex':n.compress_type=zipfile.ZIP_DEFLATED
   new.writestr(n,data,compresslevel=9)
 raw=buf.getvalue();require(len(raw)<=len(original),'New JAR exceeds original file size')
 eocd=raw.rfind(b'PK\x05\x06');require(eocd>=0 and eocd+22+struct.unpack_from('<H',raw,eocd+20)[0]==len(raw),'Bad EOCD')
 cd_size,cd_off=struct.unpack_from('<II',raw,eocd+12);require(cd_off+cd_size==eocd,'Unexpected ZIP layout')
 pad=len(original)-len(raw);result=bytearray(raw[:cd_off]+b'\0'*pad+raw[cd_off:]);struct.pack_into('<I',result,eocd+pad+16,cd_off+pad)
 require(len(result)==len(original),'Padded size differs')
 with zipfile.ZipFile(io.BytesIO(original)) as old,zipfile.ZipFile(io.BytesIO(result)) as new:
  require(old.namelist()==new.namelist() and new.testzip() is None,'ZIP inventory/CRC differs')
  for name in old.namelist():require(new.read(name)==(b if name=='classes.dex' else old.read(name)),'Unexpected entry delta')
 with output.open('xb') as f:f.write(result)
 return {'source_sha256':SOURCE_SHA,'output_sha256':hashlib.sha256(result).hexdigest(),'dex_sha256':hashlib.sha256(b).hexdigest(),'bytes':len(result),'changed_entry':'classes.dex','dex_compression':'DEFLATE; official ART17r1 loader ExtractToMemMap path','padding_before_central_directory_bytes':pad,'other_entry_data_unchanged':True}
if __name__=='__main__':
 r=build(*(Path(x) for x in sys.argv[1:]));print(json.dumps(r,indent=2))
