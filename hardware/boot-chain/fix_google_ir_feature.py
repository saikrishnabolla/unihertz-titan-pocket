"""Temporarily withhold infrared capability from the experimental guest."""
import xml.etree.ElementTree as ET

FEATURE='android.hardware.consumerir'


def disable_ir_feature(data):
    root=ET.fromstring(data)
    if root.tag!='permissions' or data.count(b'</permissions>')!=1:
        raise ValueError('Expected one permissions document')
    if any(n.get('name')==FEATURE for n in root.iter()):
        raise ValueError('Existing infrared declaration requires reconciliation')
    result=data.replace(b'</permissions>',
        b'    <unavailable-feature name="android.hardware.consumerir" />\n</permissions>',1)
    parsed=ET.fromstring(result)
    nodes=parsed.findall('unavailable-feature')
    if sum(n.get('name')==FEATURE for n in nodes)!=1:
        raise ValueError('Missing exact infrared override')
    return result
