#!/usr/bin/env python3
"""Offline filesystem conversion for the pinned virt APEX; no device access."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import shutil
import zipfile

from compare_vendor_trees import inventory, quote, split_batch

SOURCE_APEX_SHA='3d103094c71d006b09c302ae1e45d9e1fe9c681487cac0983e50bcdd25a04f28'
MANIFEST_SHA='2e5cb21d9824edaff1c06394a94446ee48b871c32868801bd4453234f4c38cf2'

TOOL_DIR=Path(os.environ.get('TITAN_E2FSPROGS','/usr/sbin'))

FEATURES='ext_attr,dir_index,filetype,extent,sparse_super,large_file,huge_file,uninit_bg,dir_nlink,extra_isize'
UUID='7d1522e1-9dfa-5edb-a43e-98e3a4d20250'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tree_inventory(tree, metadata):
    require(tree.is_dir() and not tree.is_symlink(), 'Expected extracted directory')
    actual={'/':tree}
    actual.update(('/'+p.relative_to(tree).as_posix(),p) for p in tree.rglob('*'))
    require(actual.keys()==metadata.keys(), 'Extracted path set differs from EROFS')
    result={}
    groups={}
    for path, m in metadata.items():
        require(path=='/' or (path.startswith('/') and all(x not in ('.','..') for x in path.split('/')[1:])
                             and str(PurePosixPath(path))==path), 'Unsafe payload path')
        require(stat.S_IFMT(m['mode']) in (stat.S_IFDIR,stat.S_IFREG,stat.S_IFLNK), 'Unsupported payload type')
        p=actual[path];s=p.lstat()
        require(stat.S_IFMT(s.st_mode)==stat.S_IFMT(m['mode']) and
                (stat.S_ISLNK(s.st_mode) or s.st_mode==m['mode']), 'Extracted type/mode differs: '+path)
        require(m['mtime_ns']==0, 'Expected original epoch timestamp')
        item={'mode':m['mode'],'uid':m['uid'],'gid':m['gid'],'nlink':m['nlink'],
              'mtime_ns':m['mtime_ns'],'xattrs':m['xattrs']}
        if stat.S_ISREG(s.st_mode):
            require(s.st_size==m['size'], 'Extracted size differs: '+path)
            item.update(size=s.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
        elif stat.S_ISLNK(s.st_mode):
            require(os.readlink(p)==m['target'], 'Extracted symlink differs: '+path)
            item.update(target=m['target'],size=m['size'])
        groups.setdefault(m['nid'],[]).append(path)
        result[path]=item
    for paths in groups.values():
        if not stat.S_ISDIR(metadata[paths[0]]['mode']):
            require(len(paths)==metadata[paths[0]]['nlink'], 'Missing hardlink path')
            require(len({(actual[p].lstat().st_dev,actual[p].lstat().st_ino) for p in paths})==1,
                    'Extraction lost hardlink identity')
        for path in paths:
            result[path]['same_inode_paths']=sorted(paths)
    return result


def make_ext4(tree, metadata, output):
    tree,output=Path(tree),Path(output)
    require(not output.resolve().is_relative_to(tree.resolve()), 'Output overlaps extracted input')
    expected=tree_inventory(tree,metadata)
    require(not output.exists() and not output.is_symlink(), 'Output must not exist')
    require(output.parent.stat().st_mode&0o077==0, 'Output parent must be private')
    os.umask(0o077);output.mkdir(mode=0o700)
    image=output/'payload.ext4'
    config=output/'mke2fs.conf'
    config.write_text('[defaults]\nbase_features = '+FEATURES+'\nblocksize = 4096\ninode_size = 256\ninode_ratio = 16384\n')
    logs=[]
    def run(args,stdin=None):
        p=subprocess.run(list(map(str,args)),input=stdin,capture_output=True,text=True,timeout=120,
                         env={**os.environ,'MKE2FS_CONFIG':str(config),'E2FSPROGS_FAKE_TIME':'1','LC_ALL':'C','TZ':'UTC'})
        logs.append({'command':list(map(str,args)),'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        (output/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
        require(p.returncode==0,'Filesystem tool failed; see private command log')
        return p
    blocks=(sum(m.get('size',0) for m in expected.values())+16*1024**2+4095)//4096
    run([TOOL_DIR/'mke2fs','-q','-F','-t','ext4','-O',FEATURES,'-b','4096','-I','256',
         '-N',str(max(256,len(expected)*2)),'-m','0','-U',UUID,'-E','hash_seed='+UUID,
         '-d',tree,image,str(blocks)])
    image.chmod(0o600)
    commands=['rmdir /lost+found']
    for number,(path,m) in enumerate(metadata.items()):
        q=quote(path)
        for field,value in [('mode','0'+format(m['mode'],'o')),('uid',m['uid']),('gid',m['gid']),
                            ('mtime',0),('atime',0),('ctime',0),('crtime',0),
                            ('mtime_extra',0),('atime_extra',0),('ctime_extra',0),('crtime_extra',0)]:
            commands.append(f'set_inode_field {q} {field} {value}')
        for index,(name,value) in enumerate(m['xattrs'].items()):
            raw=output/f'xattr-{number}-{index}';raw.write_bytes(bytes.fromhex(value))
            commands.append('ea_set -f '+quote(str(raw))+' '+q+' '+quote(name))
    p=run([TOOL_DIR/'debugfs','-w','-f','/dev/stdin',image],stdin='\n'.join(commands)+'\n')
    split_batch(commands,p.stdout,p.stderr,p.returncode)
    run([TOOL_DIR/'e2fsck','-fn',image])
    run([TOOL_DIR/'resize2fs','-M',image])
    run([TOOL_DIR/'e2fsck','-fn',image])
    header=run([TOOL_DIR/'dumpe2fs','-h',image]).stdout
    feature_line=re.search(r'^Filesystem features:\s*(.*)$',header,re.M)
    require(feature_line and set(feature_line[1].split())==set(FEATURES.split(',')), 'Unexpected EXT4 feature set')
    actual=inventory(image,output/'readback',allow_external_symlinks=True)
    require(actual.keys()==expected.keys(),'EXT4 path set differs')
    for path,m in expected.items():
        a=actual[path]
        require(int(a['permissions'],8)==stat.S_IMODE(m['mode']) and
                (a['uid'],a['gid'],a['links'],a['xattrs'],a['same_inode_paths'])==
                (m['uid'],m['gid'],m['nlink'],m['xattrs'],m['same_inode_paths']),
                'EXT4 metadata differs: '+path)
        require(any(re.match(r'mtime:\s+0x00000000:00000000\s',x) for x in a['timestamps_debugfs']),
                'EXT4 modification time differs: '+path)
        if 'sha256' in m:
            require((a['size'],a['sha256'])==(m['size'],m['sha256']), 'EXT4 data differs: '+path)
        elif 'target' in m:
            require(a['symlink_target']==m['target'], 'EXT4 symlink differs: '+path)
    require(tree_inventory(tree,metadata)==expected,'Extracted input changed during conversion')
    result={'image':str(image),'bytes':image.stat().st_size,'sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
            'paths':len(expected),'all_content_and_metadata_verified':True,'expected':expected}
    (output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
