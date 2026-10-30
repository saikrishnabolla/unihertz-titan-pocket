#!/usr/bin/env python3
"""Sign only the separately reviewed early-kernel diagnostic guest pair."""
import argparse
import json
from pathlib import Path
import re

from prepare_google_early_log_guest import DEPLOYMENT, POLICY_SHA, SPECS
from sign_google_legacy_guest import sign

FILESYSTEM_SHAS = {
    'system': '92223d8f05f2c6025af68340b82808bd0008faa5fa1c51127c545c01c6d73145',
    'vendor': '3acdc77875a6a499701a10cacf068b267ae2a0f6b86577907dd1ad1331595bc8',
}


def validate(report):
    if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
           for value in FILESYSTEM_SHAS.values()):
        raise ValueError('Actual filesystem pins require independent review before signing')
    if report.get('policy_sha256') != POLICY_SHA or set(report.get('artifacts', {})) != set(SPECS):
        raise ValueError('Unexpected diagnostic policy or partition scope')
    for name, spec in SPECS.items():
        changed = [path for partition, path, *_ in DEPLOYMENT if partition == name]
        added = []
        if name == 'system':
            changed += ['/system/etc/init/hw/init.rc', '/system/etc/selinux/plat_file_contexts']
            added = ['/system/bin/titan-diag', '/system/etc/init/titan-diag.rc']
        expected = {'filesystem_sha256': FILESYSTEM_SHAS[name], 'filesystem_bytes': spec[1],
                    'partition_bytes': spec[0], 'source_sha256': spec[2],
                    'changed_paths': sorted(changed), 'added_paths': sorted(added),
                    'all_other_inventoried_contents_metadata_unchanged': True}
        if report['artifacts'][name] != expected:
            raise ValueError('Preparation differs from reviewed recorder delta: ' + name)
    entries = report.get('vendor_config_audit', {}).get('formattable_entries', [])
    if len(entries) != 1 or entries[0]['source'] != '/dev/block/by-name/userdata':
        raise ValueError('Physical storage formatting guards not established')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('prepared', 'key', 'avbtool'):
        parser.add_argument('--' + field, required=True, type=Path)
    print(json.dumps(sign(**vars(parser.parse_args()), sources=SPECS,
                          filesystem_shas=FILESYSTEM_SHAS, validate=validate,
                          require_ram=False), indent=2))
