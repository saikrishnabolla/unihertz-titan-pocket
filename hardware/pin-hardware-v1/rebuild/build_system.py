"""Offline Titan guest builder: physical Titan PIN digits only."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError('Optimization disables required checks')
P = Path(__file__).resolve().parent
BASE = '41df9405a5b59bbdb62d0f7903e5f9fbeb2172cccd1e3e8f8091ba4802d61e29'
PUBLIC = '4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
OLD_SYS_SHA = '73bd53387659f11e981420d2c2b7e709778871819628959fc930785f0683bc77'
OLD_SYS_SIZE = 43550007
SYS_SHA = '0c7b88f96d4e895b8431a3808191602b32a36cc1f9415a3cfc86820ed455803e'
SYS_SIZE = 43623735
SYS = '/system/system_ext/priv-app/SystemUI/SystemUI.apk'
SYS_PARENT = '/system/system_ext/priv-app/SystemUI'
OAT_PARENT = SYS_PARENT + '/oat/arm64'
ABSENT_OAT = {OAT_PARENT+'/SystemUI.odex', OAT_PARENT+'/SystemUI.vdex'}
LAUNCHER = '/system/product/overlay/TitanPocketLauncherSpacing.apk'
PARENT = '/system/product/overlay'
FINGERPRINT = PARENT + '/TitanPocketFingerprint.apk'
PINS = {
    LAUNCHER: '29db785963ded652716704983908209f3b999545e154835af57badeb9e946d2f',
    PARENT+'/TitanPocketNotificationLight.apk': '7b642a35ec75a2af1c5e8f80a9a663adb3a2a05f19de1a9a1bbda388ac0249c9',
    '/system/build.prop': '0342d8f1a17043a9380975139620ab8d6f77b6c846783387c9125593f50707cd',
    '/system/product/media/bootanimation.zip': 'b370920629c6a751a5a67e8f7e09e37824c5e02bf818eeca480f9bb54d969714',
    FINGERPRINT: '40a0322207dc74fbd716b8d7306528b46503ddbb10f7235bfcfef552d975a7a2',
    '/system/framework/services.jar': '6806a4dcf3ef38d8368727297f62a0c7680e575365efbabb156c6bf246694e54',
    '/system/apex/com.android.bt.apex': '0d943a6d22c27440f568f8d1107b9db5cd085b7c44e7d7593a880f8d06fc05e7',
}
EPOCH = '1793242775'
FILE_EPOCH = '0x495c0780'
def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
def verify_bundle():
    pins = json.loads((P / 'source-manifest.json').read_text())
    for entry in pins['bundle_files']:
        name = entry['path']
        assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
        assert (P / name).is_file() and sha(P / name) == entry['sha256'], name
    return pins

def validate_baseline(before):
    assert all(before[p]['type']=='directory' for p in (PARENT,SYS_PARENT,OAT_PARENT))
    assert before[SYS]['inode']==4044 and before[SYS]['content_sha256']==OLD_SYS_SHA and before[SYS]['size']==OLD_SYS_SIZE
    assert not (ABSENT_OAT & before.keys()), 'Stale SystemUI OAT present'
    for path, pin in PINS.items():
        assert before[path]['type']=='regular' and before[path]['content_sha256']==pin, path
    assert before['/system/build.prop']['inode']==659
    assert before['/system/product/media/bootanimation.zip']['inode']==4406

def validate_candidate_pin():
    if not isinstance(SYS_SHA,str) or not re.fullmatch('[a-f0-9]{64}',SYS_SHA) or not isinstance(SYS_SIZE,int) or SYS_SIZE<=0:
        raise ValueError('Signed SystemUI pin is pending independent review and root signing')

def compare(before, after):
    validate_candidate_pin()
    validate_baseline(before)
    assert before.keys()==after.keys(), 'Added or removed path'
    for path, metadata in before.items():
        excluded={'size','content_sha256','allocated_512_blocks'} if path==SYS else set()
        assert {k:v for k,v in metadata.items() if k not in excluded} == {k:v for k,v in after[path].items() if k not in excluded}, 'Existing path changed: '+path
    assert after[SYS]['content_sha256']==SYS_SHA and after[SYS]['size']==SYS_SIZE

def check_inode_diff(before,after):
    assert before.keys()==after.keys()
    changed=[i for i in before if before[i]!=after[i]]
    assert set(changed)=={4044}, changed
    return changed

def listing_with_removed_oat_slots(original, parent, text):
    # debugfs may retain only these two named inode-zero directory slots.
    if parent==OAT_PARENT:
        deleted={'/0/000000/0/0/'+Path(path).name+'/0/' for path in ABSENT_OAT}
        text='\n'.join(line for line in text.splitlines() if line not in deleted)
    return original(parent,text)

def output_pin_mode(derive, expected):
    if derive == bool(expected):
        raise ValueError('Choose derivation OR exact output pin')
    if expected and not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('Invalid output pin')

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-system','systemui-apk','key','tools','avbtool','openssl','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--derive-new-output-pin', action='store_true')
    parser.add_argument('--expected-image-sha256')
    a = parser.parse_args()
    output_pin_mode(a.derive_new_output_pin, a.expected_image_sha256)
    validate_candidate_pin()
    pins = verify_bundle()
    sys.path.insert(0, str(P/'helpers'))
    import image_helpers as b
    out = a.output.resolve()
    base, key, avb, openssl = (v.resolve() for v in (a.base_system,a.key,a.avbtool,a.openssl))
    system_asset = a.systemui_apk.resolve()
    if out.exists() or a.output.is_symlink() or not out.parent.is_dir():
        raise ValueError('Invalid output')
    b.D, b.E = ((a.tools/name).resolve() for name in ('debugfs','e2fsck'))
    for name,path in [('debugfs',b.D),('e2fsck',b.E),('avbtool',avb),('openssl',openssl)]:
        assert path.is_file() and sha(path) == pins['tools'][name]['sha256'], name
    for path in (base,key,avb,openssl,b.D,b.E,system_asset):
        if not path.is_file() or path.is_relative_to(out):
            raise ValueError('Missing input or input inside output')
    b.quote(str(out)); b.quote(str(system_asset))
    b.validate_pin(base, b.SIZE, BASE)
    b.validate_pin(system_asset, SYS_SIZE, SYS_SHA)
    original_listing_parser=b.parse_directory_listing
    b.parse_directory_listing=lambda parent,text:listing_with_removed_oat_slots(original_listing_parser,parent,text)
    public = b.run([openssl,'pkey','-in',key,'-pubout'])[0]
    assert hashlib.sha256(public.encode()).hexdigest() == PUBLIC
    if shutil.disk_usage(out.parent).free < b.SIZE*2:
        raise ValueError('Insufficient working disk')
    out.mkdir(mode=0o700)
    (out/'tool-bin').mkdir()
    (out/'tool-bin/openssl').symlink_to(openssl)
    b.RUN_ENV = {**os.environ,'PATH':str(out/'tool-bin'),'E2FSPROGS_FAKE_TIME':EPOCH}
    b.RUN_ENV.pop('AVB_INVOCATION_LOGFILE', None)
    (out/'system-public.pem').write_text(public)
    tool = [sys.executable,str(avb)]
    b.run(tool+['verify_image','--image',base,'--key',out/'system-public.pem'])
    base_structure = b.check(base,'system',b.FS,b.SIZE,b.sha(base,b.FS))
    b.run([b.E,'-fn',base])
    before = b.inventory(base,out/'source-tree.json')
    raw_before = b.inode_bytes(base)
    validate_baseline(before)
    label = out/'system-file-label.bin'
    label.write_bytes(b'u:object_r:system_file:s0\0')
    image = out/'system.img'
    shutil.copyfile(base,image)
    b.run(tool+['erase_footer','--image',image])
    assert image.stat().st_size == b.FS
    commands = ['rm '+SYS,'write '+b.quote(str(system_asset))+' '+SYS]
    commands += ['set_inode_field '+SYS+' uid 0',
                 'set_inode_field '+SYS+' gid 0',
                 'set_inode_field '+SYS+' mode 0100644',
                 'ea_set -f '+b.quote(str(label))+' '+SYS+' security.selinux']
    for path in (SYS,SYS_PARENT):
        for field in ('atime','mtime','ctime','crtime'):
            commands.append('set_inode_field '+path+' '+field+' '+FILE_EPOCH)
    outputs = b.batch(image,commands,write=True)
    (out/'write-commands.json').write_text(json.dumps({'commands':commands,'outputs':outputs},indent=2)+'\n')
    b.run([b.E,'-fn',image])
    after = b.inventory(image,out/'candidate-tree-before-avb.json')
    compare(before,after)
    changed = check_inode_diff(raw_before,b.inode_bytes(image))
    fs_sha = b.sha(image)
    b.run(tool+['add_hashtree_footer','--image',image,'--partition_name','system',
                '--partition_size',b.SIZE,'--hash_algorithm','sha256','--block_size','4096',
                '--do_not_generate_fec','--algorithm','SHA256_RSA2048','--key',key,
                '--salt',fs_sha,'--rollback_index',b.SYSTEM_ROLLBACK,'--rollback_index_location','0',
                *[v for k,value in b.SYSTEM_PROPERTIES.items() for v in ['--prop',k+':'+value]]])
    assert image.stat().st_size == b.SIZE and b.sha(image,b.FS) == fs_sha
    b.run(tool+['verify_image','--image',image,'--key',out/'system-public.pem'])
    structure = b.check(image,'system',b.FS,b.SIZE,fs_sha)
    assert structure == base_structure
    b.run([b.E,'-fn',image])
    final = b.inventory(image,out/'candidate-tree-final.json')
    assert final == after and sha(base) == BASE and sha(system_asset)==SYS_SHA
    verify_bundle()
    digest = sha(image)
    if a.expected_image_sha256:
        assert digest == a.expected_image_sha256, 'Whole-image reproduction differs'
    report = {'status':'OFFLINE CANDIDATE; NOT INSTALLED OR BOOTED',
              'source_sha256':BASE,'candidate_sha256':digest,
              'added_paths':[],'modified_paths':[SYS],'removed_paths':[],
              'systemui_sha256':SYS_SHA,
              'platform_certificate_der_sha256':'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8',
              'all_other_retained_paths_content_and_metadata_unchanged':True,
              'parent_directory_metadata_unchanged':True,'changed_inode_bytes':changed,
              'retained_content_pins':PINS,'e2fsck_passed':True,'avb_verified':True,
              'avb_structure':structure,'public_key_sha256':PUBLIC,
              'fixed_reference_epoch':int(EPOCH),'file_epoch':int(FILE_EPOCH,16),
              'runtime_verified':False,'expected_image_sha256':a.expected_image_sha256,
              'exact_reference_match':bool(a.expected_image_sha256),
              'output_pin_pending_review':a.derive_new_output_pin}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__ == '__main__':
    main()
