#!/usr/bin/env python3
"""Restore public signatures only when rebuilt firmware bytes match exactly."""
import argparse,base64,hashlib,json,os,re,struct,zipfile,zlib
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()
def b64(data):return base64.b64encode(data).decode('ascii')
def unb64(data):return base64.b64decode(data,validate=True)
def regular(path):
 if path.is_symlink() or not path.is_file():raise ValueError('Expected a regular file: '+str(path))
def new_file(path,data):
 if path.exists() or path.is_symlink() or not path.parent.is_dir():raise ValueError('Output must be new')
 with path.open('xb') as f:f.write(data)
def public_entry(name):
 return name=='apex_pubkey' or bool(re.fullmatch(r'META-INF/[^/]+\.(?:MF|SF|RSA|DSA|EC)',name,re.I))

def export_zip(source,output):
 regular(source);raw=source.read_bytes()
 if raw[:4]!=b'PK\x03\x04':raise ValueError('Expected a plain ZIP without leading executable')
 parts=[];cursor=0;gap_total=0
 with zipfile.ZipFile(source) as z:
  infos=sorted(z.infolist(),key=lambda i:i.header_offset)
  if len(infos)!=len(set(i.filename for i in infos)) or z.testzip() is not None:raise ValueError('Invalid or duplicate ZIP entries')
  for i in infos:
   pos=i.header_offset
   if raw[pos:pos+4]!=b'PK\x03\x04' or i.flag_bits&1:raise ValueError('Invalid local header or encrypted entry')
   name_size,extra_size=struct.unpack_from('<HH',raw,pos+26);start=pos+30+name_size+extra_size;end=start+i.compress_size
   if pos<cursor or not start<=end<=len(raw):raise ValueError('Overlapping ZIP payloads')
   gap=raw[cursor:start];gap_total+=len(gap)
   if gap_total>2*1024**2:raise ValueError('Unexpectedly large ZIP metadata')
   data=z.read(i);compressed=raw[start:end]
   entry={'name':i.filename,'method':i.compress_type,'size':len(data),'sha256':sha(data),
    'compressed_size':len(compressed),'compressed_sha256':sha(compressed),'before_b64':b64(gap)}
   if public_entry(i.filename):entry['public_bytes_b64']=b64(data)
   parts.append(entry);cursor=end
  tail=raw[cursor:];gap_total+=len(tail)
  if gap_total>2*1024**2:raise ValueError('Unexpectedly large ZIP metadata')
 result={'format':'titan-public-zip-seal-v1','sha256':sha(raw),'size':len(raw),'entries':parts,'tail_b64':b64(tail)}
 new_file(output,(json.dumps(result,indent=2)+'\n').encode());return result

def compress(data,method,expected):
 if method==zipfile.ZIP_STORED:
  if sha(data)==expected:return data
 elif method==zipfile.ZIP_DEFLATED:
  for level in (6,9,1,2,3,4,5,7,8,0):
   c=zlib.compressobj(level,zlib.DEFLATED,-15);out=c.compress(data)+c.flush()
   if sha(out)==expected:return out
 raise ValueError('Cannot reproduce exact compressed bytes; use matching zlib/toolchain')

def apply_zip(source,seal_path,output,overrides=None):
 regular(source);regular(seal_path);seal=json.loads(seal_path.read_text())
 if seal['format']!='titan-public-zip-seal-v1':raise ValueError('Unknown ZIP seal format')
 overrides=overrides or {};out=bytearray()
 with zipfile.ZipFile(source) as z:
  if len(z.namelist())!=len(set(z.namelist())):raise ValueError('Duplicate unsigned ZIP entries')
  permitted={e['name'] for e in seal['entries']}
  extra=set(z.namelist())-permitted
  if extra:raise ValueError('Extra unsigned ZIP entries: '+', '.join(sorted(extra)))
  for e in seal['entries']:
   name=e['name']
   if 'public_bytes_b64' in e:
    if not public_entry(name):raise ValueError('Seal embeds a non-signature payload')
    data=unb64(e['public_bytes_b64'])
   elif name in overrides:
    p=Path(overrides[name]);regular(p);data=p.read_bytes()
   else:data=z.read(name)
   if len(data)!=e['size'] or sha(data)!=e['sha256']:raise ValueError('Rebuilt ZIP entry differs: '+name)
   compressed=compress(data,e['method'],e['compressed_sha256'])
   if len(compressed)!=e['compressed_size']:raise ValueError('Compressed size differs')
   out.extend(unb64(e['before_b64']));out.extend(compressed)
  out.extend(unb64(seal['tail_b64']))
 if len(out)!=seal['size'] or sha(out)!=seal['sha256']:raise ValueError('Sealed ZIP hash differs')
 new_file(output,out);return {'sha256':seal['sha256'],'size':len(out),'private_key_used':False}

def avb_parts(raw):
 if len(raw)<64 or raw[-64:-60]!=b'AVBf':raise ValueError('Missing AVB footer')
 major,minor,size,offset,vbsize=struct.unpack_from('>IIQQQ',raw,len(raw)-60)
 if major!=1 or not 0<size<=offset<len(raw)-64 or offset+vbsize>len(raw)-64:raise ValueError('Invalid AVB footer geometry')
 if raw[offset:offset+4]!=b'AVB0':raise ValueError('Missing public vbmeta')
 # The prefix must be precisely the complete EXT4 filesystem, not a loose split.
 if len(raw)<2048 or raw[1080:1082]!=b'\x53\xef':raise ValueError('Expected EXT4 payload')
 log=struct.unpack_from('<I',raw,1048)[0]
 if log>6:raise ValueError('Invalid EXT4 block size')
 blocks=struct.unpack_from('<I',raw,1028)[0]|struct.unpack_from('<I',raw,1360)[0]<<32
 if blocks*(1024<<log)!=size:raise ValueError('AVB original image size differs from EXT4 geometry')
 return raw[:size],raw[size:]

def export_avb(source,output):
 regular(source);raw=source.read_bytes();fs,tail=avb_parts(raw)
 result={'format':'titan-public-avb-seal-v1','sha256':sha(raw),'size':len(raw),'filesystem_sha256':sha(fs),'filesystem_size':len(fs),'tail_b64':b64(tail)}
 new_file(output,(json.dumps(result,indent=2)+'\n').encode());return result

def apply_avb(filesystem,seal_path,output):
 regular(filesystem);regular(seal_path);seal=json.loads(seal_path.read_text());data=filesystem.read_bytes()
 if seal['format']!='titan-public-avb-seal-v1':raise ValueError('Unknown AVB seal format')
 if len(data)!=seal['filesystem_size'] or sha(data)!=seal['filesystem_sha256']:raise ValueError('Rebuilt filesystem differs; signature cannot be reused')
 raw=data+unb64(seal['tail_b64'])
 if len(raw)!=seal['size'] or sha(raw)!=seal['sha256']:raise ValueError('Sealed AVB image differs')
 avb_parts(raw);new_file(output,raw);return {'sha256':seal['sha256'],'size':len(raw),'private_key_used':False}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['export-zip','apply-zip','export-avb','apply-avb'])
 for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--seal',type=Path);p.add_argument('--overrides',type=Path);a=p.parse_args()
 if a.operation.startswith('apply') and not a.seal:p.error('--seal required')
 os.umask(0o077)
 if a.operation=='export-zip':r=export_zip(a.source,a.output)
 elif a.operation=='export-avb':r=export_avb(a.source,a.output)
 elif a.operation=='apply-avb':r=apply_avb(a.source,a.seal,a.output)
 else:r=apply_zip(a.source,a.seal,a.output,json.loads(a.overrides.read_text()) if a.overrides else None)
 print(json.dumps({k:v for k,v in r.items() if k in ('sha256','size','private_key_used')},indent=2))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
