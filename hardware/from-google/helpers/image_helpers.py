from pathlib import Path
import argparse,hashlib,json,os,re,shutil,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
from inventory_helpers import split_batch,parse_listing,parse_stat,quote
D=E=None
RUN_ENV=None
FS=3221225472;SIZE=3288334336
SOURCESHA='59e6991b0a9e96483fff5c6348ab0b0ff7474be07a959623d6105fcbc5185d4b'

def sha(path,limit=None):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  left=Path(path).stat().st_size if limit is None else limit
  while left:
   b=f.read(min(left,4*1024**2));assert b;h.update(b);left-=len(b)
 return h.hexdigest()
def validate_paths(source,output):
 if source.resolve()==output.resolve():raise ValueError('Output aliases source')
 if output.exists() or output.is_symlink():raise ValueError('Output already exists')
 if not source.is_file():raise ValueError('Source not a file')
def validate_pin(path,size,digest):
 if path.stat().st_size!=size:raise ValueError('Input size differs: '+str(path))
 if sha(path)!=digest:raise ValueError('Input hash differs: '+str(path))
def run(args,stdin=None,timeout=600):
 r=subprocess.run(list(map(str,args)),input=stdin,text=True,capture_output=True,timeout=timeout,env=RUN_ENV)
 if r.returncode:raise ValueError(str(args[0])+': '+r.stderr+r.stdout)
 return r.stdout,r.stderr
def batch(image,commands,write=False):
 a=[D]+(['-w'] if write else [])+['-f','/dev/stdin',str(image)]
 out,err=run(a,'\n'.join(commands)+'\n')
 return split_batch(commands,out,err)
def file_digest(image,inode,size):
 proc=subprocess.Popen([D,'-R',f'cat <{inode}>',str(image)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 h=hashlib.sha256();n=0
 while True:
  b=proc.stdout.read(1024**2)
  if not b:break
  h.update(b);n+=len(b)
 err=proc.stderr.read().decode();rc=proc.wait()
 if rc or n!=size or any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in err.splitlines()):raise ValueError('Unverified file read '+str(inode)+': '+err)
 return h.hexdigest()
def parse_directory_listing(parent,text):
 # Deleted EXT4 directory slots are not live filesystem entries.
 lines=[line for line in text.splitlines() if not line.startswith('/0/000000/0/0/')]
 return parse_listing('\n'.join(lines))

def inventory(image,output):
 identity=image.stat();entries={'/':parse_stat(batch(image,['stat /'])[0])};pending=['/'];listed={}
 while pending:
  current,pending=pending,[]
  for parent,text in zip(current,batch(image,['ls -l -p '+quote(x) for x in current])):
   for entry in parse_directory_listing(parent,text):
    path=(parent.rstrip('/')+'/'+entry['name']);listed[path]=entry
    if stat.S_ISDIR(int(entry['mode'],8)):pending.append(path)
 paths=sorted(listed)
 for start in range(0,len(paths),128):
  chunk=paths[start:start+128]
  for path,text in zip(chunk,batch(image,['stat '+quote(x) for x in chunk])):
   v=parse_stat(text);l=listed[path]
   if any(v[k]!=l[k] for k in ('inode','uid','gid')):raise ValueError('Listing/stat mismatch')
   expected={stat.S_IFREG:'regular',stat.S_IFDIR:'directory',stat.S_IFLNK:'symlink'}.get(stat.S_IFMT(int(l['mode'],8)))
   if v['type']!=expected or int(v['permissions'],8)!=stat.S_IMODE(int(l['mode'],8)):raise ValueError('Unsupported type/mode '+path)
   if l['listed_size'] is not None and v['size']!=l['listed_size']:raise ValueError('Size mismatch '+path)
   if v['type']=='symlink' and v['symlink_target'] is None:
    if not 0<v['size']<=4096:raise ValueError('Unbounded symlink '+path)
    target,err=run([D,'-R',f"cat <{v['inode']}>",str(image)])
    if len(target.encode())!=v['size'] or any(x in target for x in ('\0','\n','\r')):raise ValueError('Unverified symlink '+path)
    if any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in err.splitlines()):raise ValueError(err)
    v['symlink_target']=target
   entries[path]=v
 hashes={}
 for v in entries.values():
  if v['type']=='regular':
   if v['inode'] not in hashes:hashes[v['inode']]=file_digest(image,v['inode'],v['size'])
   v['content_sha256']=hashes[v['inode']]
 if (identity.st_size,identity.st_ino,identity.st_mtime_ns)!=(image.stat().st_size,image.stat().st_ino,image.stat().st_mtime_ns):raise ValueError('Image changed during inventory')
 output.write_text(json.dumps(entries,indent=2)+'\n')
 return entries
