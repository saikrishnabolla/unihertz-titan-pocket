"""Re-sign the retained diagnostic SYSTEM after one bounded configuration repair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import prepare_google_legacy_guest as base
import sign_google_dsu_pair as avb
from check_google_dsu_pair_avb import check, SYSTEM_PROPERTIES, SYSTEM_ROLLBACK
from fix_google_zygote_stdio import remove_kernel_stdio
from fix_google_ir_feature import disable_ir_feature

OLD='572c2a8513bc0e21120192e63505dc9e1fcbbe4d196e0f39870da511f457a593'
FS,SIZE=3221225472,3288334336
PATHS=('/system/etc/init/hw/init.zygote64.rc','/system/etc/init/hw/init.zygote64_32.rc')


def prepare(source_root,output,backup,key,avbtool,disable_ir=False):
    os.umask(0o077)
    old='26f5b9bb97557e6cf53d6983906502b5eec2f324392e535377f2deb82f716238' if disable_ir else OLD
    paths=('/system/etc/permissions/platform.xml',) if disable_ir else PATHS
    transform=disable_ir_feature if disable_ir else remove_kernel_stdio
    retained=json.loads(backup.read_text())
    assert retained['full_readback_verified'] is True and retained['sha256']==old and retained['bytes']==SIZE
    assert not output.exists() and not output.is_symlink()
    source=source_root/'system/system.img';base.check_source(source,(SIZE,FS,old))
    tree=json.loads((source_root/'system/after/inventory.json').read_text())
    replacements={p:transform(base.read_file(source,p)) for p in paths}
    for p in paths:assert hashlib.sha256(base.read_file(source,p)).hexdigest()==tree[p]['sha256']
    assert base.sha(avbtool)==avb.AVBTOOL_SHA and shutil.disk_usage(source).free>avb.RESERVE_BYTES
    output.mkdir(mode=0o700);work=output/'system';work.mkdir(mode=0o700)
    scope=('Temporarily mark infrared unavailable in guest SYSTEM permissions so core boot does not require the incompatible IR service. IR acceptance remains unproven; no runtime/VENDOR/security/data changes.' if disable_ir else
           'Only remove experimental stdio_to_kmsg from both Zygote services. All crash recorder, Google runtime and guest VENDOR bytes unchanged.')
    report={'scope':scope,'preimage_sha256':old,'preimage_retained_on_studio':retained,'changed_paths':list(paths)}
    (output/'preparation-intent.json').write_text(json.dumps(report,indent=2)+'\n')
    (source_root/'system-retained-on-studio.json').write_text(json.dumps(retained,indent=2)+'\n')
    candidate=work/'system.ext4'
    source.rename(candidate)
    with candidate.open('r+b') as stream:stream.truncate(FS)
    base.replace_files(candidate,tree,replacements,work)
    base.run(['/usr/sbin/e2fsck','-fn',candidate])
    expected=base.expected_inventory(tree,replacements)
    actual=base.logical_inventory(candidate,work/'after')
    assert actual==expected,'Unexpected content or metadata delta'
    for p,data in replacements.items():assert base.read_file(candidate,p)==data
    fs_sha=base.sha(candidate);public=output/'public.pem';public.write_bytes(avb.retained_public_key(key))
    base.run([sys.executable,avbtool,'add_hashtree_footer','--image',candidate,'--partition_name','system',
              *avb.settings(SIZE),'--algorithm','SHA256_RSA2048','--key',key,'--salt',fs_sha,
              '--rollback_index',SYSTEM_ROLLBACK,'--rollback_index_location','0',
              *[arg for k,v in SYSTEM_PROPERTIES.items() for arg in ('--prop',k+':'+v)]])
    base.run([sys.executable,avbtool,'verify_image','--image',candidate,'--key',public])
    report['avb_structure']=check(candidate,'system',FS,SIZE,fs_sha)
    base.run(['/usr/sbin/e2fsck','-fn',candidate]);assert base.sha(candidate,FS)==fs_sha
    final=work/'system.img';avb.publish(candidate,final)
    report.update(sha256=base.sha(final),bytes=SIZE,filesystem_sha256=fs_sha,
                  all_other_inventoried_content_metadata_unchanged=True)
    (output/'prepared.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in ('source-root','output','backup','key','avbtool'):parser.add_argument('--'+n,type=Path,required=True)
    parser.add_argument('--disable-ir',action='store_true')
    print(json.dumps(prepare(**vars(parser.parse_args())),indent=2))
