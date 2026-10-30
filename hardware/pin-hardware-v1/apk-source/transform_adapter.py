"""Patch only the hash-pinned, caller-supplied SystemUI adapter."""
import hashlib
from pathlib import Path

ORIGINAL_SHA256 = '8436b30f9bd88d424d825ebb7baf6ec8254dfc0dfba103e61c1d8f8b86426b06'
PATCHED_SHA256 = '40b5ee4cd9c2cbdafb37890e4394ca3f7caeaefedb93b53954a655396822f014'
INSERTION = '    instance-of v1, p0, Lcom/android/systemui/bouncer/ui/viewmodel/PinBouncerViewModel;\n\n    if-eqz v1, :titan_original_key\n\n    const/4 v1, 0x2\n\n    if-ne v0, v1, :titan_original_key\n\n    invoke-virtual {p1}, Landroid/view/KeyEvent;->getDevice()Landroid/view/InputDevice;\n\n    move-result-object v1\n\n    if-eqz v1, :titan_original_key\n\n    invoke-virtual {v1}, Landroid/view/InputDevice;->getName()Ljava/lang/String;\n\n    move-result-object v1\n\n    const-string v2, "aw9523-key"\n\n    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n\n    move-result v1\n\n    if-eqz v1, :titan_original_key\n\n    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I\n\n    move-result v1\n\n    const/16 v2, 0x1d\n\n    if-lt v1, v2, :titan_original_key\n\n    const/16 v2, 0x36\n\n    if-gt v1, v2, :titan_original_key\n\n    invoke-virtual {p1}, Landroid/view/KeyEvent;->getNumber()C\n\n    move-result v1\n\n    const/16 v2, 0x30\n\n    if-lt v1, v2, :titan_original_key\n\n    const/16 v2, 0x39\n\n    if-gt v1, v2, :titan_original_key\n\n    add-int/lit8 p1, v1, -0x29\n\n    goto :titan_delegate\n\n    :titan_original_key\n'

def transform(source, output):
    raw = Path(source).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Unexpected original adapter')
    text = raw.decode()
    anchor = '    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I'
    delegate = '    invoke-virtual {p0, v0, p1}, Lcom/android/systemui/bouncer/ui/viewmodel/AuthMethodBouncerViewModel;->onKeyEvent-uiMRsoQ(II)Z'
    if text.count('.registers 3') != 1 or text.count(anchor) != 1 or text.count(delegate) != 1:
        raise ValueError('Unexpected adapter structure')
    text = text.replace('.registers 3', '.registers 5', 1)
    text = text.replace(anchor, INSERTION + anchor, 1)
    text = text.replace(delegate, '    :titan_delegate\n' + delegate, 1)
    if hashlib.sha256(text.encode()).hexdigest() != PATCHED_SHA256:
        raise ValueError('Unexpected patched adapter')
    with Path(output).open('x') as destination:
        destination.write(text)
