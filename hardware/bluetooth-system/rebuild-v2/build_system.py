"""Rebuild the reviewed Bluetooth-only Titan SYSTEM image offline."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, sys

sys.dont_write_bytecode = True
P = Path(__file__).resolve().parent
sys.path.insert(0,str(P/'helpers'))
import image_helpers as b

if not __debug__:
    raise RuntimeError('Python optimization disables required checks')
OLD = '/system/apex/com.android.bt.capex'
NEW = '/system/apex/com.android.bt.apex'
OLD_SHA = '0563f0fb1f5b31b7cb91b64b78d9674c2fcbc01ad7b52d9c6d0ad12e5d43872a'
APEX_SHA = '0d943a6d22c27440f568f8d1107b9db5cd085b7c44e7d7593a880f8d06fc05e7'
REFERENCE_SHA = '59cd8ee93ac73b16c58e5ce62eed875f73fec18d8f109dfa41a810c626a1c4e9'
PUBLIC_SHA = '4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
EPOCH = '1793242775'

def compare(before, after):
    assert set(before)-set(after) == {OLD}
    assert set(after)-set(before) == {NEW}
    assert all(before[p] == after[p] for p in set(before)&set(after))
    old,new = before[OLD],after[NEW]
    assert old['content_sha256'] == OLD_SHA and new['content_sha256'] == APEX_SHA
    for key in ['inode','permissions','uid','gid','links','xattrs','timestamps_debugfs']:
        assert old[key] == new[key], key

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['base-system','apex','key','tools','avbtool','openssl','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() or args.output.is_symlink():
        raise ValueError('Output already exists')
    if not out.parent.is_dir():
        raise ValueError('Output parent does not exist')
    base = args.base_system.resolve()
    apex = args.apex.resolve()
    key = args.key.resolve()
    avb = args.avbtool.resolve()
    openssl = args.openssl.resolve()
    b.D = (args.tools/'debugfs').resolve()
    b.E = (args.tools/'e2fsck').resolve()
    pins = json.loads((P/'source-manifest.json').read_text())
    for entry in pins['bundle_files']:
        assert b.sha(P/entry['path']) == entry['sha256'], entry['path']
    for name,path in [('debugfs',b.D),('e2fsck',b.E),('openssl',openssl),('avbtool',avb)]:
        assert path.is_file() and b.sha(path) == pins['tools'][name]['sha256'], name
    for path in [base,apex,key,avb,openssl,b.D,b.E]:
        if not path.is_file() or path.is_relative_to(out):
            raise ValueError('Missing input or input inside output')
    b.quote(str(out)); b.quote(str(apex))
    b.validate_pin(base,b.SIZE,b.SOURCESHA)
    b.validate_pin(apex,28217344,APEX_SHA)
    public = b.run([openssl,'pkey','-in',key,'-pubout'])[0]
    assert hashlib.sha256(public.encode()).hexdigest() == PUBLIC_SHA
    if shutil.disk_usage(out.parent).free < b.SIZE*2:
        raise ValueError('Insufficient working disk')
    out.mkdir(mode=0o700)
    tool_bin = out/'tool-bin'; tool_bin.mkdir(mode=0o700)
    (tool_bin/'openssl').symlink_to(openssl)
    b.RUN_ENV = {**os.environ,'PATH':str(tool_bin),'E2FSPROGS_FAKE_TIME':EPOCH}
    b.RUN_ENV.pop('AVB_INVOCATION_LOGFILE',None)
    (out/'system-public.pem').write_text(public)
    tool = [sys.executable,str(avb)]
    b.run(tool+['verify_image','--image',base,'--key',out/'system-public.pem'])
    b.run([b.E,'-fn',base])
    before = b.inventory(base,out/'source-tree.json')
    raw_before = b.inode_bytes(base)
    assert OLD in before and NEW not in before and before[OLD]['inode'] == 59
    assert before[OLD]['content_sha256'] == OLD_SHA
    image = out/'system.img'
    shutil.copyfile(base,image)
    b.run(tool+['erase_footer','--image',image])
    assert image.stat().st_size == b.FS
    label = out/'system-file-label.bin'
    label.write_bytes(b'u:object_r:system_file:s0\0')
    commands = ['rm '+OLD,'write '+b.quote(str(apex))+' '+NEW,
        'set_inode_field '+NEW+' uid 0','set_inode_field '+NEW+' gid 0',
        'set_inode_field '+NEW+' mode 0100644',
        'ea_set -f '+b.quote(str(label))+' '+NEW+' security.selinux']
    for path in [NEW,'/system/apex']:
        for name in ['atime','mtime','ctime','crtime']:
            commands.append('set_inode_field '+path+' '+name+' 0x495c0780')
    outputs = b.batch(image,commands,write=True)
    (out/'debugfs-write-commands.json').write_text(json.dumps({'commands':commands,'outputs':outputs},indent=2)+'\n')
    b.run([b.E,'-fn',image])
    after = b.inventory(image,out/'candidate-tree-before-avb.json')
    compare(before,after)
    raw_after = b.inode_bytes(image)
    changed = [i for i in raw_before if raw_before[i] != raw_after[i]]
    assert changed == [59], changed
    readback = out/'com.android.bt.readback.apex'
    b.batch(image,['dump '+NEW+' '+b.quote(str(readback))])
    assert b.sha(readback) == APEX_SHA
    fs_sha = b.sha(image)
    b.run(tool+['add_hashtree_footer','--image',image,'--partition_name','system',
        '--partition_size',b.SIZE,'--hash_algorithm','sha256','--block_size','4096',
        '--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',key,
        '--salt',fs_sha,'--rollback_index',b.SYSTEM_ROLLBACK,'--rollback_index_location','0',
        *[v for k,value in b.SYSTEM_PROPERTIES.items() for v in ['--prop',k+':'+value]]])
    assert image.stat().st_size == b.SIZE and b.sha(image,b.FS) == fs_sha
    b.run(tool+['verify_image','--image',image,'--key',out/'system-public.pem'])
    structure = b.check(image,'system',b.FS,b.SIZE,fs_sha)
    b.run([b.E,'-fn',image])
    final = b.inventory(image,out/'candidate-tree-final.json')
    assert final == after and b.sha(base) == b.SOURCESHA and b.sha(apex) == APEX_SHA
    candidate_sha = b.sha(image)
    report = {'status':'OFFLINE BLUETOOTH-ONLY SYSTEM REBUILD; NOT INSTALLED OR BOOTED',
        'source_sha256':b.SOURCESHA,'apex_sha256':APEX_SHA,'candidate_sha256':candidate_sha,
        'reference_sha256':REFERENCE_SHA,'byte_identical_to_reference':candidate_sha == REFERENCE_SHA,
        'changed_inode_bytes':changed,'removed_paths':[OLD],'added_paths':[NEW],
        'all_other_paths_and_metadata_unchanged':True,'all_regular_file_hashes_checked':True,
        'source_inputs_unchanged':True,'e2fsck_passed':True,'avb_verified':True,
        'avb_structure':structure,'fixed_reference_epoch':int(EPOCH),
        'runtime_hardware_guard':False,
        'scope':'Exact Titan trial only. Package activation and Bluetooth functions require a recorded guest trial.'}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    assert candidate_sha == REFERENCE_SHA, 'Whole-image byte identity differs; inspect report before using'
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
