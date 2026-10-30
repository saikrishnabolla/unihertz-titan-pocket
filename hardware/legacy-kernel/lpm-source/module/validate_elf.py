"""Read-only checks of the offline ET_REL candidate; not a runtime test."""
from pathlib import Path
import struct,json,hashlib
P=Path(__file__).resolve().parent
b=(P/'titan_lpm.ko').read_bytes()
assert b[:6]==b'\x7fELF\x02\x01'
h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
assert h[1:4]==(1,183,1)
assert h[11]==64 and h[12]>0 and h[6]+h[11]*h[12]<=len(b)
raw=[struct.unpack_from('<IIQQQQIIQQ',b,h[6]+i*64) for i in range(h[12])]
def payload(s):
    if s[1]==8:return b''
    assert s[4]+s[5]<=len(b)
    return b[s[4]:s[4]+s[5]]
def cstr(data,at=0):
    assert at<len(data)
    end=data.index(0,at)
    return data[at:end].decode()
names=payload(raw[h[13]])
sections={cstr(names,s[0]):s for s in raw}
assert len(sections)==len(raw)
for name in ('.gnu.linkonce.this_module','__versions','.plt','.init.plt','.text','.modinfo','.symtab'):
    assert name in sections,name
assert not any('"' in name for name in sections)
for name in ('.plt','.init.plt'):
    s=sections[name];assert s[1]==8 and s[2]&6==6 and s[5]==0
sym=sections['.symtab'];assert sym[9]==24 and sym[6]<len(raw)
strings=payload(raw[sym[6]]);symbols={};undefined=[]
for at in range(sym[4],sym[4]+sym[5],24):
    n,info,other,index,value,size=struct.unpack_from('<IBBHQQ',b,at)
    name=cstr(strings,n)
    if name:symbols[name]=(info,index,value,size)
    if name and index==0:undefined.append(name)
for name in ('trie_get_next_key','trie_delete_elem'):
    info,index,value,size=symbols[name]
    assert index>0 and raw[index][2]&4 and cstr(names,raw[index][0])=='.text'
assert 'cleanup_module' not in symbols
assert symbols['__this_module'][1]==raw.index(sections['.gnu.linkonce.this_module'])
modinfo=payload(sections['.modinfo']).split(b'\0')
expected=b'vermagic=4.14.186-g40b2a1864-dirty SMP preempt mod_unload modversions aarch64'
assert expected in modinfo and b'license=GPL v2' in modinfo and b'name=titan_lpm' in modinfo
versions=json.loads((P/'versions.json').read_text());actual={}
v=payload(sections['__versions']);assert len(v)==len(versions)*64
for at in range(0,len(v),64):
    crc=struct.unpack_from('<Q',v,at)[0];name=cstr(v,at+8);assert name not in actual
    actual[name]=crc
assert actual=={name:int(value['crc'],16) for name,value in versions.items()}
assert set(undefined)|{'module_layout'}==set(actual)
relocs={}
for name,s in sections.items():
    if s[1]!=4:continue
    assert s[9]==24 and s[6]==raw.index(sym) and s[7]<len(raw)
    target=raw[s[7]]
    for at in range(s[4],s[4]+s[5],24):
        offset,info,addend=struct.unpack_from('<QQq',b,at);typ=info&0xffffffff
        assert info>>32<sym[5]//24 and offset<target[5]
        relocs[typ]=relocs.get(typ,0)+1
# Pinned source apply_relocate_add supports these; exact binary switch still unverified.
assert set(relocs)<={257,263,264,265,266,267,268,269,283},relocs
result={'status':'PASS OFFLINE ELF CHECKS; NOT LOAD TESTED','module_sha256':hashlib.sha256(b).hexdigest(),'sections':list(sections),'relocation_types':relocs,'imports':sorted(undefined),'version_entries':len(actual),'callbacks_section':'.text','module_struct_size':sections['.gnu.linkonce.this_module'][5],'no_exit':True,'relocation_support_evidence':'Pinned source only; actual kernel dispatcher not independently decoded'}
(P/'elf-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
