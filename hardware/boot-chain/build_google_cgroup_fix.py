#!/usr/bin/env python3
"""Build a separate offline SYSTEM with only blkio made optional.

The fixed-length payload edit preserves every filesystem metadata byte. No
device access, signing, original-image mutation or controller-success spoofing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from inventory_candidate_product import parse_stat, quote, split_batch
from sign_google_dsu_pair import publish

SOURCE_SHA = '9de56e44a4dcade6386a225f1366bdab29dc814fb85418563d40b0f154c912fa'
SOURCE_BYTES = 3221225472
CONFIG_SHA = 'c400e39dca40b6250283e11346b4358f0afaaf3a736e288c5157f88a21e608d4'
TARGET = '/system/etc/cgroups.json'
BLOCK = 104137
BLOCK_BYTES = 4096
RESERVE = 2 * 1024**3
CHUNK = 1024**2


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda:stream.read(CHUNK), b''):
            h.update(data)
    return h.hexdigest()


def replacement(data):
    if len(data)!=771 or hashlib.sha256(data).hexdigest()!=CONFIG_SHA:
        raise ValueError('Unexpected pinned configuration')
    parsed=json.loads(data)
    controller=parsed['Cgroups'][0]
    if controller!={'Controller':'blkio','Path':'/dev/blkio','Mode':'0775','UID':'system','GID':'system'}:
        raise ValueError('Unexpected blkio descriptor')
    controller['Optional']=True
    start=data.index(b'    {')
    end=data.index(b'    },')+5
    encoded=b'    '+json.dumps(controller,separators=(',',':')).encode()
    if len(encoded)>end-start:
        raise ValueError('Replacement exceeds fixed payload span')
    result=data[:start]+encoded.ljust(end-start,b' ')+data[end:]
    if len(result)!=len(data) or json.loads(result)!=parsed:
        raise ValueError('Unexpected replacement semantics or length')
    return result


def regular(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Expected a regular non-symlink image')
    return info


def fingerprint(path):
    s=regular(path)
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode)


def sparse_copy(source,target):
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    zero=bytes(BLOCK_BYTES)
    with source.open('rb') as original,os.fdopen(fd,'wb') as output:
        for chunk in iter(lambda:original.read(CHUNK),b''):
            for start in range(0,len(chunk),BLOCK_BYTES):
                data=chunk[start:start+BLOCK_BYTES]
                if data==zero[:len(data)]:
                    output.seek(len(data),1)
                else:
                    output.write(data)
        output.truncate(output.tell())
        output.flush()
        os.fsync(output.fileno())


def compare_all(source,candidate,old,new):
    if source.stat().st_size!=SOURCE_BYTES or candidate.stat().st_size!=SOURCE_BYTES:
        raise ValueError('Unexpected image lengths during comparison')
    offset=BLOCK*BLOCK_BYTES
    h=hashlib.sha256(); original_hash=hashlib.sha256(); count=0
    with source.open('rb') as a,candidate.open('rb') as b:
        for original in iter(lambda:a.read(CHUNK),b''):
            actual=b.read(len(original)); expected=original
            if count<=offset<count+len(original):
                local=offset-count
                if original[local:local+len(old)]!=old:
                    raise ValueError('Original block payload changed')
                expected=original[:local]+new+original[local+len(old):]
                if actual[local:local+len(new)]!=new:
                    raise ValueError('Wrong replacement payload')
            if actual!=expected:
                raise ValueError('Image bytes changed outside configuration')
            original_hash.update(original); h.update(actual); count+=len(original)
    return {'compared_bytes':count,'source_sha256':original_hash.hexdigest(),
            'image_sha256':h.hexdigest(),'only_changed_file':TARGET,
            'payload_bytes':len(new),'filesystem_metadata_byte_identical':True,
            'changed_bytes':sum(a!=b for a,b in zip(old,new))}


def build(source,output):
    source,output=Path(source).absolute(),Path(output).absolute()
    info=regular(source)
    if info.st_size!=SOURCE_BYTES or sha(source)!=SOURCE_SHA:
        raise ValueError('Unexpected pinned source image')
    before=fingerprint(source)
    if output.exists() or output.is_symlink():
        raise ValueError('Output must not exist')
    parent=output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode)!=0o700:
        raise ValueError('Output parent must be private non-symlink directory')
    if output.resolve() in source.resolve().parents:
        raise ValueError('Output aliases source ancestry')
    if shutil.disk_usage(output.parent).free<SOURCE_BYTES+RESERVE+64*1024**2:
        raise ValueError('Insufficient image space including 2GiB reserve')
    stage=Path(tempfile.mkdtemp(prefix='.'+output.name+'.partial-',dir=output.parent))
    commands=[]
    def run(args,stdin=None):
        result=subprocess.run([str(x) for x in args],input=stdin,capture_output=True,text=True,timeout=600,
                              env={**os.environ,'LC_ALL':'C','TZ':'UTC'})
        commands.append({'command':[str(x) for x in args],'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        (stage/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:
            raise ValueError('Read-only tool failed; see staging commands')
        return result
    def inspect(image):
        script=['stat '+quote(TARGET),'blocks '+quote(TARGET),'bmap '+quote(TARGET)+' 0']
        result=run(['/usr/sbin/debugfs','-f','/dev/stdin',image],'\n'.join(script)+'\n')
        sections=split_batch(script,result.stdout,result.stderr,result.returncode)
        item=parse_stat(sections[0])
        if (item['type'],item['links'],item['size'],item['allocated_512_blocks'])!=('regular',1,771,8):
            raise ValueError('Configuration must be single-link, single-block regular file')
        if sections[1].split()!=[str(BLOCK)] or sections[2].strip()!=str(BLOCK):
            raise ValueError('Unexpected pinned configuration block mapping')
        return sections
    previous_umask=os.umask(0o077)
    try:
        run(['/usr/sbin/e2fsck','-fn',source])
        original_stat=inspect(source)
        with source.open('rb') as stream:
            stream.seek(BLOCK*BLOCK_BYTES); original_block=stream.read(BLOCK_BYTES)
        old=original_block[:771]; new=replacement(old)
        image=stage/'system.ext4'
        sparse_copy(source,image)
        with image.open('r+b') as stream:
            stream.seek(BLOCK*BLOCK_BYTES)
            if stream.read(BLOCK_BYTES)!=original_block:
                raise ValueError('Copied block differs before edit')
            stream.seek(BLOCK*BLOCK_BYTES); stream.write(new); stream.flush(); os.fsync(stream.fileno())
        delta=compare_all(source,image,old,new)
        if delta['source_sha256']!=SOURCE_SHA or fingerprint(source)!=before:
            raise ValueError('Source changed during preparation')
        run(['/usr/sbin/e2fsck','-fn',image])
        if inspect(image)!=original_stat:
            raise ValueError('Filesystem inode metadata changed')
        dest=stage/'cgroups-readback.json'
        script=['dump '+quote(TARGET)+' '+quote(str(dest))]
        result=run(['/usr/sbin/debugfs','-f','/dev/stdin',image],script[0]+'\n')
        split_batch(script,result.stdout,result.stderr,result.returncode)
        if dest.read_bytes()!=new:
            raise ValueError('Actual filesystem readback differs')
        if shutil.disk_usage(stage).free<RESERVE:
            raise ValueError('Reserve lost during preparation')
        report={'scope':'Unsigned offline cgroup compatibility candidate; no device access or boot proof',
                'source_sha256':SOURCE_SHA,'image_bytes':SOURCE_BYTES,'image_sha256':delta['image_sha256'],
                'config_before_sha256':CONFIG_SHA,'config_after_sha256':hashlib.sha256(new).hexdigest(),
                'semantic_change':'Only blkio.Optional boolean true; all other descriptors/profiles unchanged',
                'encoding':'First descriptor compacted and whitespace-padded to keep original771byte length',
                'delta':delta,'allocated_bytes':image.stat().st_blocks*512,'reserve_bytes':RESERVE,
                'source_identity_stable':True,'source_unchanged':True,'fsck':'read-only exit0',
                'limits':'Subsequent mandatory controllers, APEX/BPF/networking and usability untested; signing/archive not performed'}
        (stage/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        publish(stage,output)
        return report
    finally:
        os.umask(previous_umask)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    print(json.dumps(build(**vars(parser.parse_args())),indent=2))
