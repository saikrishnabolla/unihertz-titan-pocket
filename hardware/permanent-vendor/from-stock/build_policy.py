#!/usr/bin/env python3
"""Compile the tested legacy VENDOR policy from original CIL inputs, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
POLICY_SHA256 = 'cb2e4b879e2de0c0acb97309c9a8380e2c25771a16ed0557733ef80bfd3b2e22'
INPUT_PINS = {
    'mapping-30.0.cil': '22a897761e5c9f5e37d61c908819a00183ce5b52c10cc89608d8226eb892bf24',
    'mapping-30.0.compat.cil': '162c01e64db8206631160c14aa132a2e5a36f4cf6a5db229df6fdf81825e4a18',
    'system_ext_sepolicy.cil': 'bcdaa16015d01771f85972ef7a2eb885708294898030d6ab78fbfa30f8090014',
    'product_sepolicy.cil': 'bcdaa16015d01771f85972ef7a2eb885708294898030d6ab78fbfa30f8090014',
    'mapping-202604.cil': '34f9db1571f43aab25ee785130fb2a080c99a49bd87a8a8a4f5c574969b5365e',
}
LOGDR_RULES = (
    '\n(allow titan_diag logdr_socket (sock_file (write)))\n'
    '(allow titan_diag logd (unix_stream_socket (connectto)))\n'
    '(allow titan_diag self (unix_stream_socket (create read write connect)))\n'
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transform(raw, entry):
    if sha(raw) != entry['source_sha256']:
        raise ValueError('Original CIL input hash differs')
    lines = raw.decode().splitlines(keepends=True)
    end = len(lines)
    for operation in reversed(entry['operations']):
        start, stop = operation['start_line_zero'], operation['end_line_zero']
        if not 0 <= start <= stop <= end:
            raise ValueError('Overlapping or invalid source delta')
        lines[start:stop] = operation['lines']
        end = start
    result = ''.join(lines).encode()
    if sha(result) != entry['intermediate_sha256']:
        raise ValueError('CIL transformation output hash differs')
    return result


def build(inputs, output, secilc, transformer):
    inputs, output = Path(inputs), Path(output)
    deltas = json.loads((HERE / 'policy-source-deltas.json').read_text())
    prepared = {name: transform((inputs / name).read_bytes(), entry)
                for name, entry in deltas.items()}
    prepared['plat_sepolicy.cil'] += LOGDR_RULES.encode()
    for name, pin in INPUT_PINS.items():
        raw = (inputs / name).read_bytes()
        if sha(raw) != pin:
            raise ValueError('Compiler input hash differs: ' + name)
        prepared[name] = raw
    output.mkdir(mode=0o700, exist_ok=False)
    for name, raw in prepared.items():
        (output / name).write_bytes(raw)
    commands = []
    def run(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=180)
        commands.append(dict(argv=list(map(str, argv)), returncode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise ValueError('Policy command failed: ' + result.stderr)
    names = ['mapping-30.0.cil', 'mapping-30.0.compat.cil',
             'system_ext_sepolicy.cil', 'product_sepolicy.cil',
             'plat_pub_versioned.cil', 'vendor_sepolicy.cil']
    run([secilc, output / 'plat_sepolicy.cil', '-m', '-M', 'true', '-G', '-N', '-c', '30',
         '-o', output / 'policy30', '-f', output / 'contexts',
         *[output / name for name in names]])
    run([transformer, output / 'policy30', output / 'precompiled_sepolicy'])
    actual = sha((output / 'precompiled_sepolicy').read_bytes())
    if actual != POLICY_SHA256:
        raise ValueError('Compiled policy differs from tested policy: ' + actual)
    platform_identifier = sha(prepared['plat_sepolicy.cil'] + prepared['mapping-202604.cil'])
    (output / 'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256').write_text(platform_identifier + '\n')
    for name in ['system_ext', 'product']:
        (output / ('precompiled_sepolicy.' + name + '_sepolicy_and_mapping.sha256')).write_text(
            'c20c78354393ef7dbb1be181810f67478db51650a7b0665937d720adc73e97cd\n')
    report = dict(policy_sha256=actual, device_actions=False,
                  source_inputs={name: sha(raw) for name, raw in prepared.items()},
                  platform_identifier=platform_identifier,
                  security_tradeoff='Legacy NLMSG permissions are coarser; this is not security-equivalent.',
                  neverallow_checks_disabled=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['inputs', 'output', 'secilc', 'transformer']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.inputs.resolve(), args.output.resolve(),
                               args.secilc.resolve(), args.transformer.resolve()), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
