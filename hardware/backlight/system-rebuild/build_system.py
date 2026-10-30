"""Build an offline backlight-only SYSTEM candidate. Never accesses a phone."""
from pathlib import Path
import hashlib, importlib.util, json, os, re, shutil, sys
sys.dont_write_bytecode = True
P = Path(__file__).resolve().parent
sys.path.insert(0,str(P/'helpers'))
import image_helpers as b
import argparse
if not __debug__: raise RuntimeError('Python optimization is unsupported; checks must remain enabled')
JAR = '/system/framework/services.jar'
REMOVED = [JAR+'.fsv_meta', JAR+'.prof', JAR+'.prof.fsv_meta'] + [
    '/system/framework/oat/arm64/services.'+kind+suffix
    for kind in ['art','odex','vdex'] for suffix in ['', '.fsv_meta']]
PATCHSHA = '6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54'
original_parse_listing = b.parse_listing
deleted_slots = []
def parse_listing(text):
    kept = []
    for line in text.splitlines():
        match = re.fullmatch(r'/0/000000/0/0/([^/]+)/0/', line)
        if match:
            assert match[1] in {Path(p).name for p in REMOVED}, line
            deleted_slots.append(line)
        else:
            kept.append(line)
    return original_parse_listing('\n'.join(kept))
b.parse_listing = parse_listing

def compare(before, after):
    assert set(before)-set(after) == set(REMOVED) and not set(after)-set(before)
    changed = sorted(p for p in after if before[p] != after[p])
    assert changed == [JAR], changed
    for key in ['permissions','uid','gid','links','xattrs','timestamps_debugfs']:
        assert before[JAR][key] == after[JAR][key], key
    assert after[JAR]['content_sha256'] == PATCHSHA

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['base-system','jar','key','tools','avbtool','openssl','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--derive-new-output-pin',action='store_true')
    parser.add_argument('--expected-image-sha256')
    args=parser.parse_args()
    if args.derive_new_output_pin == bool(args.expected_image_sha256): raise ValueError('Choose first-build derivation OR a reviewed exact image pin')
    if args.expected_image_sha256 and not re.fullmatch('[a-f0-9]{64}',args.expected_image_sha256): raise ValueError('Invalid image pin')
    out=args.output.resolve()
    if out.exists() or args.output.is_symlink(): raise ValueError('Output already exists')
    if not out.parent.is_dir(): raise ValueError('Output parent does not exist')
    patch=args.jar.resolve()
    b.SOURCE=args.base_system.resolve(); b.KEY=args.key.resolve(); b.AVB=args.avbtool.resolve()
    b.D=(args.tools/'debugfs').resolve(); b.E=(args.tools/'e2fsck').resolve()
    openssl=args.openssl.resolve()
    manifest=json.loads((P/'source-manifest.json').read_text())
    for entry in manifest['bundle_files']:
        if b.sha(P/entry['path'])!=entry['sha256']: raise ValueError('Bundle source pin differs: '+entry['path'])
    for name,path in [('debugfs',b.D),('e2fsck',b.E),('openssl',openssl),('avbtool',b.AVB)]:
        if b.sha(path)!=manifest['tools'][name]['sha256']: raise ValueError('Tool pin differs: '+name)
    for path in [patch,b.SOURCE,b.KEY,b.AVB,b.D,b.E,openssl]:
        if not path.is_file(): raise ValueError('Missing input')
        if path.is_relative_to(out): raise ValueError('Input falls inside output')
    b.quote(str(patch));b.quote(str(out))
    b.validate_pin(b.SOURCE, b.SIZE, b.SOURCESHA)
    assert b.sha(patch) == PATCHSHA
    assert b.sha(b.AVB) == '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'
    assert shutil.disk_usage(out.parent).free > b.SIZE*2
    out.mkdir(mode=0o700)
    tool_bin=out/'tool-bin';tool_bin.mkdir(mode=0o700)
    (tool_bin/'openssl').symlink_to(openssl)
    b.RUN_ENV=os.environ.copy()
    b.RUN_ENV['PATH']=str(tool_bin)
    b.RUN_ENV.pop('AVB_INVOCATION_LOGFILE',None)
    b.RUN_ENV.pop('SOURCE_DATE_EPOCH',None)
    b.RUN_ENV['E2FSPROGS_FAKE_TIME']='1793248389'
    public = b.run([openssl,'pkey','-in',b.KEY,'-pubout'])[0]
    assert hashlib.sha256(public.encode()).hexdigest() == '4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
    (out/'system-public.pem').write_text(public)
    tool = [sys.executable, str(b.AVB)]
    b.run(tool+['verify_image','--image',b.SOURCE,'--key',out/'system-public.pem'])
    b.run([b.E,'-fn',b.SOURCE])
    before = b.inventory(b.SOURCE, out/'source-tree.json')
    raw_before = b.inode_bytes(b.SOURCE)
    pins = json.loads((P/'packaging-pins.json').read_text())
    assert {JAR, *REMOVED} <= {x['source'] for x in pins}
    for pin in pins:
        assert before[pin['source']]['content_sha256'] == pin['sha256']
    image = out/'system.img'
    shutil.copyfile(b.SOURCE, image)
    b.run(tool+['erase_footer','--image',image])
    assert image.stat().st_size == b.FS
    label = out/'system-file-label.bin'
    label.write_bytes(b'u:object_r:system_file:s0\0')
    commands = ['rm '+JAR] + ['rm '+path for path in REMOVED] + [
        'write '+b.quote(str(patch))+' '+JAR,
        'set_inode_field '+JAR+' uid 0', 'set_inode_field '+JAR+' gid 0',
        'set_inode_field '+JAR+' mode 0100644',
        'ea_set -f '+b.quote(str(label))+' '+JAR+' security.selinux']
    for path in [JAR, '/system/framework', '/system/framework/oat/arm64']:
        for name in ['atime','mtime','ctime','crtime']:
            commands.append('set_inode_field '+path+' '+name+' 0x495c0780')
    outputs = b.batch(image, commands, write=True)
    (out/'debugfs-write-commands.json').write_text(json.dumps({'commands':commands,'outputs':outputs},indent=2)+'\n')
    b.run([b.E,'-fn',image])
    after = b.inventory(image, out/'candidate-tree-before-avb.json')
    compare(before, after)
    raw_after = b.inode_bytes(image)
    changed_inodes = [i for i in raw_before if raw_before[i] != raw_after[i]]
    allowed_inodes = {before[x]['inode'] for x in [JAR, *REMOVED]}
    assert set(changed_inodes) <= allowed_inodes, changed_inodes
    readback = out/'services-readback.jar'
    b.batch(image, ['dump '+JAR+' '+b.quote(str(readback))])
    assert b.sha(readback) == PATCHSHA
    filesystem_sha = b.sha(image)
    b.run(tool+['add_hashtree_footer','--image',image,'--partition_name','system',
        '--partition_size',b.SIZE,'--hash_algorithm','sha256','--block_size','4096',
        '--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',b.KEY,
        '--salt',filesystem_sha,'--rollback_index',b.SYSTEM_ROLLBACK,'--rollback_index_location','0',
        *[arg for k,v in b.SYSTEM_PROPERTIES.items() for arg in ['--prop',k+':'+v]]])
    assert image.stat().st_size == b.SIZE and b.sha(image,b.FS) == filesystem_sha
    b.run(tool+['verify_image','--image',image,'--key',out/'system-public.pem'])
    structure = b.check(image,'system',b.FS,b.SIZE,filesystem_sha)
    b.run([b.E,'-fn',image])
    final = b.inventory(image,out/'candidate-tree-final.json')
    assert final == after and b.sha(b.SOURCE) == b.SOURCESHA and b.sha(patch) == PATCHSHA
    if args.expected_image_sha256:
        assert b.sha(image)==args.expected_image_sha256, 'Image differs from reviewed v3 pin'
    report = {'status':'OFFLINE VERIFIED BACKLIGHT-ONLY CANDIDATE; NOT INSTALLED OR BOOTED',
        'source_system_sha256':b.SOURCESHA,'candidate_system_sha256':b.sha(image),
        'candidate_jar_sha256':PATCHSHA,'changed_paths':[JAR],'removed_paths':REMOVED,
        'changed_inode_bytes':changed_inodes,'metadata_and_other_paths_unchanged':True,
        'all_regular_file_hashes_checked':True,'e2fsck_passed':True,'avb_verified':True,
        'avb_structure':structure,'source_unchanged':True,
        'reference_candidate_sha256':args.expected_image_sha256,
        'byte_identical_to_reference':bool(args.expected_image_sha256) and b.sha(image)==args.expected_image_sha256,
        'output_pin_pending_review':args.derive_new_output_pin,
        'tools_sha256':{k:v['sha256'] for k,v in manifest['tools'].items()},
        'avb_openssl_path_constrained':True,
        'filesystem_epoch':1793248389,
        'epoch_provenance':'Reference superblock write time and nine deleted inode dtimes, observed from pinned reference image',
        'remaining':['Independent image review','Recorded guest boot trial when owner present','Physical light/timeout tests'],
        'excluded':['Bluetooth update','Touchpad service','Camera update','Navigation overlay']}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
