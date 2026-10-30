#!/usr/bin/env python3
"""Prepare isolated hooks against one exact original A17 controller smali."""
from pathlib import Path
import argparse
import hashlib
import json
import re

SOURCE_SHA = 'f632b0c1410dcf0f5f38d2aa1c4e400ac1ea5d2d1d021a36d98a5778c4507f09'
SERVICES_SHA = 'bc5d11f4f09ec079c5804a01008e8317a0854231502550acaff89aa9f1083a86'
C = 'Lcom/android/server/input/KeyboardBacklightController;'
B = 'Lcom/android/server/input/LegacyKeyboardLightBridge;'
FIELD = 'mLegacyKeyboardLightBridge:' + B
READY = 'mLegacyKeyboardLightInventoryReady:Z'
sha = lambda b: hashlib.sha256(b).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Expected exactly one anchor: ' + old[:100])
    return text.replace(old, new, 1)


def methods(text):
    found = re.findall(r'^\.method ([^\n]+)\n.*?^\.end method\n', text, re.M | re.S)
    blocks = re.findall(r'^\.method [^\n]+\n.*?^\.end method\n', text, re.M | re.S)
    if len(found) != len(set(found)):
        raise ValueError('Duplicate method')
    return dict(zip(found, blocks))


def apply(source):
    if sha(source.encode()) != SOURCE_SHA:
        raise ValueError('Wrong or already modified original smali')
    original = methods(source)
    modified = {}

    name = 'public constructor <init>(Landroid/content/Context;Lcom/android/server/input/NativeInputManagerService;Landroid/os/Looper;Lcom/android/server/input/KeyboardBacklightController$AnimatorFactory;)V'
    anchor = f'    iput-object p2, p0, {C}->mHandler:Landroid/os/Handler;\n'
    body = anchor + f'''
    :legacy_init_start
    new-instance v0, {B}
    invoke-direct {{v0, p1, p2}}, {B}-><init>(Landroid/content/Context;Landroid/os/Handler;)V
    iput-object v0, p0, {C}->{FIELD}
    :legacy_init_end
    .catch Ljava/lang/RuntimeException; {{:legacy_init_start .. :legacy_init_end}} :legacy_init_failed
    .catch Ljava/lang/LinkageError; {{:legacy_init_start .. :legacy_init_end}} :legacy_init_failed
    goto :legacy_init_done
    :legacy_init_failed
    move-exception v0
    const/4 v0, 0x0
    iput-object v0, p0, {C}->{FIELD}
    :legacy_init_done
'''
    modified[name] = once(original[name], anchor, body)

    name = 'public final handleUserActivity()V'
    anchor = f'    iput-boolean v0, p0, {C}->mIsBacklightOn:Z\n'
    body = anchor + f'''
    :legacy_activity_start
    iget-object v0, p0, {C}->{FIELD}
    if-eqz v0, :legacy_activity_done
    iget-boolean v1, p0, {C}->{READY}
    if-eqz v1, :legacy_activity_done
    iget-boolean v1, p0, {C}->mIsInteractive:Z
    invoke-virtual {{v0, v1}}, {B}->activity(Z)V
    :legacy_activity_end
    .catch Ljava/lang/RuntimeException; {{:legacy_activity_start .. :legacy_activity_end}} :legacy_activity_failed
    .catch Ljava/lang/LinkageError; {{:legacy_activity_start .. :legacy_activity_end}} :legacy_activity_failed
    goto :legacy_activity_done
    :legacy_activity_failed
    move-exception v1
    invoke-direct {{p0}}, {C}->disableLegacyKeyboardLightAfterError()V
    :legacy_activity_done
'''
    modified[name] = once(original[name], anchor, body)

    name = 'public handleInteractiveStateChange(Z)V'
    body = once(original[name], '    .registers 2\n', '    .registers 3\n')
    anchor = f'    iput-boolean p1, p0, {C}->mIsInteractive:Z\n'
    body = once(body, anchor, anchor + f'''
    :legacy_interactive_start
    iget-boolean v0, p0, {C}->{READY}
    if-nez v0, :legacy_interactive_ready
    if-nez p1, :legacy_interactive_done
    :legacy_interactive_ready
    iget-object v0, p0, {C}->{FIELD}
    if-eqz v0, :legacy_interactive_done
    invoke-virtual {{v0, p1}}, {B}->interactive(Z)V
    :legacy_interactive_end
    .catch Ljava/lang/RuntimeException; {{:legacy_interactive_start .. :legacy_interactive_end}} :legacy_interactive_failed
    .catch Ljava/lang/LinkageError; {{:legacy_interactive_start .. :legacy_interactive_end}} :legacy_interactive_failed
    goto :legacy_interactive_done
    :legacy_interactive_failed
    move-exception v0
    invoke-direct {{p0}}, {C}->disableLegacyKeyboardLightAfterError()V
    :legacy_interactive_done
''')
    modified[name] = body

    name = 'public final handleMessage(Landroid/os/Message;)Z'
    anchor = '    :cond_47\n    return v2\n'
    modified[name] = once(original[name], anchor, f'''    :cond_47
    const/4 v1, 0x1
    iput-boolean v1, p0, {C}->{READY}
    invoke-direct {{p0}}, {C}->refreshLegacyKeyboardLightInventory()V
    return v2
''')

    name = 'public onInputDeviceChanged(I)V'
    body = original[name]
    if body.count('    return-void\n') != 3:
        raise ValueError('Unexpected changed-device return sites')
    modified[name] = body.replace('    return-void\n', f'    invoke-direct {{p0}}, {C}->refreshLegacyKeyboardLightInventory()V\n\n    return-void\n')

    name = 'public onInputDeviceRemoved(I)V'
    anchor = '    invoke-virtual {v0, p1}, Landroid/util/SparseArray;->remove(I)V\n'
    modified[name] = once(original[name], anchor, anchor + f'\n    invoke-direct {{p0}}, {C}->refreshLegacyKeyboardLightInventory()V\n')

    name = 'public dump(Ljava/io/PrintWriter;)V'
    anchor = '    .line 491\n'
    modified[name] = once(original[name], anchor, f'''    :legacy_dump_start
    iget-object v1, p0, {C}->{FIELD}
    if-eqz v1, :legacy_dump_unavailable
    invoke-virtual {{v1}}, {B}->toString()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {{v0, v1}}, Landroid/util/IndentingPrintWriter;->println(Ljava/lang/String;)V
    goto :legacy_dump_end
    :legacy_dump_unavailable
    const-string v1, "LegacyKeyboardLightBridge: unavailable"
    invoke-virtual {{v0, v1}}, Landroid/util/IndentingPrintWriter;->println(Ljava/lang/String;)V
    :legacy_dump_end
    .catch Ljava/lang/RuntimeException; {{:legacy_dump_start .. :legacy_dump_end}} :legacy_dump_failed
    .catch Ljava/lang/LinkageError; {{:legacy_dump_start .. :legacy_dump_end}} :legacy_dump_failed
    goto :legacy_dump_done
    :legacy_dump_failed
    move-exception v1
    const-string v1, "LegacyKeyboardLightBridge: diagnostics unavailable"
    invoke-virtual {{v0, v1}}, Landroid/util/IndentingPrintWriter;->println(Ljava/lang/String;)V
    :legacy_dump_done

''' + anchor)

    result = source
    for name, body in modified.items():
        result = once(result, original[name], body)
    result = once(result, '# instance fields\n', f'# instance fields\n.field private final {FIELD}\n\n.field private {READY}\n\n')
    helper = f'''
.method private disableLegacyKeyboardLightAfterError()V
    .registers 2
    :legacy_disable_start
    iget-object v0, p0, {C}->{FIELD}
    if-eqz v0, :legacy_disable_done
    invoke-virtual {{v0}}, {B}->disableAfterError()V
    :legacy_disable_end
    .catch Ljava/lang/RuntimeException; {{:legacy_disable_start .. :legacy_disable_end}} :legacy_disable_failed
    .catch Ljava/lang/LinkageError; {{:legacy_disable_start .. :legacy_disable_end}} :legacy_disable_failed
    goto :legacy_disable_done
    :legacy_disable_failed
    move-exception v0
    :legacy_disable_done
    return-void
.end method

.method private refreshLegacyKeyboardLightInventory()V
    .registers 7
    :legacy_inventory_start
    iget-object v0, p0, {C}->{FIELD}
    if-eqz v0, :legacy_inventory_done
    iget-boolean v1, p0, {C}->{READY}
    if-eqz v1, :legacy_inventory_done
    invoke-virtual {{v0}}, {B}->isTargetDevice()Z
    move-result v1
    if-eqz v1, :legacy_inventory_done
    const/4 v1, 0x0
    const/4 v5, 0x0
    iget-object v2, p0, {C}->mKeyboardBacklights:Landroid/util/SparseArray;
    :legacy_inventory_loop
    invoke-virtual {{v2}}, Landroid/util/SparseArray;->size()I
    move-result v3
    if-ge v1, v3, :legacy_inventory_publish
    invoke-virtual {{v2, v1}}, Landroid/util/SparseArray;->keyAt(I)I
    move-result v3
    invoke-virtual {{p0, v3}}, {C}->getInputDevice(I)Landroid/view/InputDevice;
    move-result-object v3
    if-eqz v3, :legacy_inventory_next
    invoke-virtual {{v3}}, Landroid/view/InputDevice;->isExternal()Z
    move-result v4
    if-nez v4, :legacy_inventory_next
    invoke-virtual {{v3}}, Landroid/view/InputDevice;->isVirtual()Z
    move-result v4
    if-nez v4, :legacy_inventory_next
    const/4 v5, 0x1
    goto :legacy_inventory_publish
    :legacy_inventory_next
    add-int/lit8 v1, v1, 0x1
    goto :legacy_inventory_loop
    :legacy_inventory_publish
    invoke-virtual {{v0, v5}}, {B}->setModernLightPresent(Z)V
    :legacy_inventory_end
    .catch Ljava/lang/RuntimeException; {{:legacy_inventory_start .. :legacy_inventory_end}} :legacy_inventory_failed
    .catch Ljava/lang/LinkageError; {{:legacy_inventory_start .. :legacy_inventory_end}} :legacy_inventory_failed
    goto :legacy_inventory_done
    :legacy_inventory_failed
    move-exception v1
    invoke-direct {{p0}}, {C}->disableLegacyKeyboardLightAfterError()V
    :legacy_inventory_done
    return-void
.end method
'''
    result = once(result, '# direct methods\n', '# direct methods\n' + helper)
    after = methods(result)
    if set(after) - set(original) != {'private disableLegacyKeyboardLightAfterError()V', 'private refreshLegacyKeyboardLightInventory()V'}:
        raise ValueError('Unexpected added methods')
    if set(original) - set(after):
        raise ValueError('Original method removed')
    if {name for name in original if after[name] != original[name]} != set(modified):
        raise ValueError('Unexpected changed methods')
    return result, {'original_smali_sha256': sha(source.encode()), 'patched_smali_sha256': sha(result.encode()), 'modified_methods': sorted(modified), 'added_methods': sorted(set(after)-set(original)), 'unchanged_methods': sorted(set(original)-set(modified)), 'bridge_implementation_included': False, 'assembled_or_merged_by_patcher': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--services', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if sha(args.services.read_bytes()) != SERVICES_SHA:
        raise ValueError('Wrong services.jar')
    text, report = apply(args.source.read_text())
    if args.output.exists():
        raise ValueError('Output already exists')
    args.output.mkdir(parents=True)
    destination = args.output / 'com/android/server/input/KeyboardBacklightController.smali'
    destination.parent.mkdir(parents=True)
    destination.write_text(text)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
