#!/usr/bin/env python3
"""Sign only the new task-owned cgroup SYSTEM, appending AVB in place.

Never mutates the original baseline or VENDOR. A failed attempt is retained and
its exclusive intent marker prevents an automatic retry on ambiguous state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

import sign_google_dsu_pair as pair
from check_google_dsu_pair_avb import check, SYSTEM_PROPERTIES, SYSTEM_ROLLBACK

FS_BYTES=3221225472
PARTITION_BYTES=3288334336
FILESYSTEM_SHA='eddcbe56c9c32e21ab75dfea04c998b6d4044923fd60b3763dfaa85abf3ff589'


def write_json(path,data):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
        json.dump(data,stream,indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())


def build(prepared,key,avbtool):
    return sign_prepared(prepared,key,avbtool,FILESYSTEM_SHA,'cgroup')


def sign_prepared(prepared,key,avbtool,filesystem_sha,variant):
    pair.private_directory(prepared)
    image=prepared/'system.ext4'; final=prepared/'system.img'; public=prepared/'public.pem'
    marker=prepared/'signing-intent.json'; report_path=prepared/'signing-report.json'
    if any(p.exists() or p.is_symlink() for p in (final,public,marker,report_path)):
        raise ValueError('Signing output or prior intent already exists; reconcile before proceeding')
    inputs=[image,key,avbtool]
    infos=[pair.regular(p) for p in inputs]
    if len({(s.st_dev,s.st_ino) for s in infos})!=3 or infos[0].st_nlink!=1:
        raise ValueError('Inputs must be distinct and candidate image must have one host link')
    if stat.S_IMODE(infos[0].st_mode)!=0o600:
        raise ValueError('Candidate image must be private mode0600')
    if infos[0].st_size!=FS_BYTES or pair.sha(image)!=filesystem_sha:
        raise ValueError('Candidate differs from literal '+variant+' filesystem pin')
    if pair.sha(avbtool)!=pair.AVBTOOL_SHA:
        raise ValueError('Unexpected avbtool')
    key_sha=pair.sha(key)
    public_bytes=pair.retained_public_key(key)
    tool=[sys.executable,avbtool]
    maximum=int(pair.run([*tool,'add_hashtree_footer',*pair.settings(PARTITION_BYTES),'--calc_max_image_size']).strip())
    if FS_BYTES>maximum:
        raise ValueError('Filesystem exceeds authoritative AVB capacity')
    if shutil.disk_usage(prepared).free<PARTITION_BYTES-FS_BYTES+pair.RESERVE_BYTES:
        raise ValueError('Insufficient append budget including 2GiB reserve')
    pair.run(['/usr/sbin/e2fsck','-fn',image])
    for p,s in zip(inputs,infos):
        after=pair.regular(p)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns,after.st_ctime_ns)!=(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns):
            raise ValueError('Input changed before signing')
    write_json(marker,{'scope':'Append AVB only to new pinned task candidate; no source/VENDOR/device writes',
                        'filesystem_sha256':filesystem_sha,'filesystem_bytes':FS_BYTES,'partition_bytes':PARTITION_BYTES,
                       'public_key_pem_sha256':pair.PUBLIC_KEY_PEM_SHA})
    with os.fdopen(os.open(public,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:
        stream.write(public_bytes)
    pair.run([*tool,'add_hashtree_footer','--image',image,'--partition_name','system',
              *pair.settings(PARTITION_BYTES),'--algorithm','SHA256_RSA2048','--key',key,
              '--salt',filesystem_sha,'--rollback_index',SYSTEM_ROLLBACK,'--rollback_index_location',0,
              *[arg for k,v in SYSTEM_PROPERTIES.items() for arg in ('--prop',k+':'+v)]])
    signed_info=pair.regular(image)
    pair.run([*tool,'verify_image','--image',image,'--key',public])
    structure=check(image,'system',FS_BYTES,PARTITION_BYTES,filesystem_sha)
    pair.run(['/usr/sbin/e2fsck','-fn',image])
    if pair.sha(image,FS_BYTES)!=filesystem_sha:
        raise ValueError('Signing changed filesystem prefix')
    if pair.sha(key)!=key_sha or pair.sha(avbtool)!=pair.AVBTOOL_SHA:
        raise ValueError('Key or tool changed during signing')
    if pair.sha(public)!=pair.PUBLIC_KEY_PEM_SHA:
        raise ValueError('Public key export changed')
    for p,s in zip((key,avbtool),infos[1:]):
        after=pair.regular(p)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns,after.st_ctime_ns)!=(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns):
            raise ValueError('Key or tool identity changed')
    current=pair.regular(image)
    if (current.st_dev,current.st_ino,current.st_mode)!=(infos[0].st_dev,infos[0].st_ino,infos[0].st_mode):
        raise ValueError('Candidate identity or mode changed')
    if shutil.disk_usage(prepared).free<pair.RESERVE_BYTES:
        raise ValueError('Signing reserve lost')
    pair.private_directory(prepared); pair.private_directory(key.parent)
    signed_hash=pair.sha(image)
    current=pair.regular(image)
    if (current.st_dev,current.st_ino,current.st_size,current.st_mode,current.st_mtime_ns,current.st_ctime_ns)!=(signed_info.st_dev,signed_info.st_ino,signed_info.st_size,signed_info.st_mode,signed_info.st_mtime_ns,signed_info.st_ctime_ns):
        raise ValueError('Candidate changed during signed verification')
    with image.open('rb') as stream:
        os.fsync(stream.fileno())
    # No-replace publication, same inode, no second full-size image copy.
    pair.publish(image,final)
    if pair.sha(final)!=signed_hash:
        raise ValueError('Signed candidate changed during publication')
    report={'scope':'Signed offline '+variant+' SYSTEM only; no installation or boot proof',
            'filesystem_sha256':filesystem_sha,'filesystem_bytes':FS_BYTES,'system_sha256':signed_hash,
            'system_bytes':PARTITION_BYTES,'public_key_pem_sha256':pair.sha(public),'structure':structure,
            'vendor':'Reuse unchanged independently verified signed VENDOR315b2b5330b1c4788a2a3e86f8abfe6c863ef4276396c3a24deab01612a8d922',
            'signed_in_place':'Only new task candidate mutated; original baseline untouched; every filesystem byte unchanged by signing'}
    write_json(report_path,report)
    fd=os.open(prepared,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('prepared','key','avbtool'):
        parser.add_argument('--'+name,type=Path,required=True)
    print(json.dumps(build(**vars(parser.parse_args())),indent=2))
