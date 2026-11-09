"""Derive API30 maps from Google13, Google17's API31 bridge and AOSP16."""
import hashlib
import re

COMPAT_URL = 'https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r1/private/compat/30.0/30.0.compat.cil?format=TEXT'
PINS = {
    'google13_map': 'd6ddac2e83aef3bef73ca194cc82c32f88ef892710b41a59a7b34706008b7d8e',
    'google17_map31': '96964df1ab17c132dc077fe55e936169818f6b36ce0584a4115eaf41a426cab3',
    'google17_compat31': 'a48742b9a57d3950efb59952c8fdd815b68d3f8605cc533efae7015cca3d6936',
    'aosp16_compat30': '2b40198379e1bb65ca2af156b25562381273144d94c5ae223b5ed9905d7437cc',
}


def forms(raw):
    stack, result = [], []
    for token in re.findall(r'\(|\)|[^\s()]+', re.sub(r';[^\n]*', '', raw.decode())):
        if token == '(':
            item = []
            if stack:
                stack[-1].append(item)
            stack.append(item)
        elif token == ')':
            if not stack:
                raise ValueError('Unbalanced CIL')
            item = stack.pop()
            if not stack:
                result.append(item)
        else:
            if not stack:
                raise ValueError('CIL token outside form')
            stack[-1].append(token)
    if stack:
        raise ValueError('Unbalanced CIL')
    return result


def attribute_sets(parsed):
    entries = [form for form in parsed if form[0] == 'typeattributeset']
    names = [form[1] for form in entries]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate mapping attribute')
    return {form[1]: form[2] for form in entries}


def emit(form):
    return '(' + ' '.join(emit(item) if isinstance(item, list) else item for item in form) + ')'


def build(google13_map, google17_map31, google17_compat31, aosp16_compat30):
    inputs = dict(google13_map=google13_map, google17_map31=google17_map31,
                  google17_compat31=google17_compat31, aosp16_compat30=aosp16_compat30)
    for name, raw in inputs.items():
        if hashlib.sha256(raw).hexdigest() != PINS[name]:
            raise ValueError('Mapping source hash differs: ' + name)
    donor = forms(google13_map)
    if len(attribute_sets(donor)) != 1084:
        raise ValueError('Unexpected donor attribute count')
    bridge = attribute_sets(forms(google17_map31))
    generated = []
    for form in donor:
        if form[0] == 'typeattributeset':
            members = sorted({value for member in form[2] for value in bridge.get(member + '_31_0', [member])})
            form = [form[0], form[1], members]
        generated.append(emit(form))
    return ('\n'.join(generated) + '\n').encode(), aosp16_compat30 + b'\n' + google17_compat31
