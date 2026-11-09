#!/usr/bin/env python3
"""Apply reviewed byte edits to files extracted from the clean Google GSI."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
from clean_system import SOURCE_SHA,SOURCE_BYTES,digest,regular,image_path,h

def validate(spec):
 for name in ('source_sha256','sha256'):
  if not isinstance(spec.get(name),str) or not re.fullmatch('[0-9a-f]{64}',spec[name]):raise ValueError('Invalid SHA256')
 if type(spec.get('size'))!=int or not 0<=spec['size']<=64*1024**2:raise ValueError('Invalid file size')
 if spec.get('kind','file') not in ('new','file'):raise ValueError('Invalid edit kind')
 image_path(spec['path'])
 for e in spec['edits']:
  if not isinstance(e.get('old_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',e['old_sha256']):raise ValueError('Invalid edit SHA256')
  if not isinstance(e.get('hex'),str):raise ValueError('Invalid edit bytes')

def patch(data,spec):
 validate(spec)
 if hashlib.sha256(data).hexdigest()!=spec['source_sha256']:raise ValueError('Source hash differs: '+spec['path'])
 last=0
 for e in spec['edits']:
  i=e['offset'];n=e['remove']
  if type(i)!=int or type(n)!=int or i<last or n<0 or i+n>len(data):raise ValueError('Invalid or overlapping edit')
  if hashlib.sha256(data[i:i+n]).hexdigest()!=e['old_sha256']:raise ValueError('Original edit span differs')
  last=i+n
 for e in reversed(spec['edits']):
  i=e['offset'];data=data[:i]+bytes.fromhex(e['hex'])+data[i+e['remove']:]
 if len(data)!=spec['size'] or hashlib.sha256(data).hexdigest()!=spec['sha256']:raise ValueError('Rebuilt hash differs: '+spec['path'])
 return data

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','edits','debugfs','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();regular(a.source);regular(a.edits)
 if a.source.stat().st_size!=SOURCE_BYTES or digest(a.source)!=SOURCE_SHA:raise ValueError('Google GSI differs')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700);payloads={}
 for spec in json.loads(a.edits.read_text()):
  validate(spec)
  target=out/spec['sha256']
  if spec['kind']=='new':data=b''
  else:
   original=out/(spec['sha256']+'.original')
   command='dump '+image_path(spec['path'])+' '+h.quote(str(original))
   r=subprocess.run([str(a.debugfs),'-R',command,str(a.source)],capture_output=True,text=True,timeout=60,check=True)
   errors=[s for s in r.stderr.splitlines() if s and not re.fullmatch(r'debugfs \d[^\n]*',s)]
   if errors:raise ValueError('Extraction failed: '+'; '.join(errors))
   data=original.read_bytes()
  with target.open('xb') as f:f.write(patch(data,spec))
  payloads[spec['sha256']]=str(target)
 (out/'payloads.json').write_text(json.dumps(payloads,indent=2)+'\n');print('Rebuilt '+str(len(payloads))+' files')
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError) as e:raise SystemExit(str(e))
