"""Hash-pinned offline lifecycle experiment. Never an installation candidate."""
from pathlib import Path
import argparse,shutil
import struct as S, hashlib as H, json, subprocess
SOURCE_ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description="Patch the exact CP3 libinputflinger; no device actions.")
parser.add_argument('--original',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--llvm-bin',type=Path)
args=parser.parse_args()
R=args.output.resolve();R.mkdir(parents=True,exist_ok=True)
if not args.original.is_file():parser.error('Missing private original libinputflinger.so')
SRC=args.original.resolve()
PIN='38761f904a5952bdc958b6348f00d65d467b608bff8d86a696c275f57fc72955'
LLVM=(str(args.llvm_bin.resolve())+'/' if args.llvm_bin else '')
b=SRC.read_bytes(); assert H.sha256(b).hexdigest()==PIN,'Private original libinputflinger hash differs; this patch supports only the pinned CP3 input'
h=list(S.unpack_from('<16sHHIQQQIHHHHHH',b)); assert h[2]==183
ph=[list(S.unpack_from('<IIQQQQQQ',b,h[5]+i*56)) for i in range(h[10])]
sh=[list(S.unpack_from('<IIQQQQIIQQ',b,h[6]+i*64)) for i in range(h[12])]
names=b[sh[h[13]][4]:sh[h[13]][4]+sh[h[13]][5]]
sec={names[x[0]:].split(b'\0')[0].decode():x for x in sh}
def payload(n):
 x=sec[n]; return b[x[4]:x[4]+x[5]]
def off(a,n=1):
 matches=[p[2]+a-p[3] for p in ph if p[0]==1 and p[3]<=a and a+n<=p[3]+p[5]]
 assert len(matches)==1; return matches[0]
def syms(data,st):
 return [(st[n:].split(b'\0')[0].decode(),info,idx,v,z) for n,info,o,idx,v,z in S.iter_unpack('<IBBHQQ',data)]
original_syms=syms(payload('.dynsym'),payload('.dynstr'))
byname={x[0]:x for x in original_syms}
ctor=[x for x in original_syms if x[0].startswith('_ZN7android11InputReaderC')]
dtor=[x for x in original_syms if x[0].startswith('_ZN7android11InputReaderD')]
assert len(ctor)==2 and all(x[3:]==(0x20440c,0x3e8) for x in ctor)
assert len(dtor)==3 and sorted((x[3],x[4]) for x in dtor)==[(0x204d6c,0x2ec),(0x204d6c,0x2ec),(0x2052d0,0x28)]
assert S.unpack_from('<I',b,off(0x20440c))[0]==0xd10243ff
assert S.unpack_from('<I',b,off(0x204d6c))[0]==0xd10143ff
assert byname['_ZTVN7android8EventHubE'][3:]==(0x3d5f68,0x1d8)
assert byname['_ZN7android8EventHub4wakeEv'][3]==0x1e5ab0
reltext=subprocess.check_output([LLVM+'llvm-readelf','-rW',str(SRC)],text=True)
assert '00000000003d60f0  000008e600000101 R_AARCH64_ABS64' in reltext
assert '00000000003e2ee0  0000049500000401 R_AARCH64_GLOB_DAT' in reltext
(R/'original-relocations.txt').write_text(reltext)
mapper_specs=[('constructor',0x2391b4,900,0xd103c3ff),('destructor',0x23953c,324,0xa9bd7bfd),('reset',0x23b2e4,852,0xd10283ff),('process',0x23b638,524,0xd10403ff)]
for name,a,z,w in mapper_specs:
 assert S.unpack_from('<I',b,off(a))[0]==w
 assert any(x[3:]==(a,z) for x in original_syms)
mapper_aliases={name:[x[0] for x in original_syms if x[3]==a and x[4]==z] for name,a,z,w in mapper_specs}
assert byname['_ZN7android11InputReader8loopOnceEv'][3:]==(0x205b70,0x794)
assert S.unpack_from('<I',b,off(0x205b70))[0]==0xd104c3ff
assert S.unpack_from('<I',b,off(0x2060e0))[0]==0x9406f590
cursor_specs=[(0x25b408,0xd103c3ff),(0x259970,0x2a1403e0),(0x25998c,0x2a1403e0)]
for a,w in cursor_specs: assert S.unpack_from('<I',b,off(a))[0]==w
context_specs=[(0x201a60,0xa9bd7bfd),(0x201ac0,0xd65f03c0)]
for a,w in context_specs: assert S.unpack_from('<I',b,off(a))[0]==w
final_specs=[(0x220784,0xd101c3ff),(0x239eb8,0xd10783ff),(0x205a5c,0xd10143ff),(0x27cb14,0xa9be7bfd)]
for a,w in final_specs: assert S.unpack_from('<I',b,off(a))[0]==w
# Prove all original executable B/BL edges to these functions hit their entries.
edges=[]; interior=[]
for p in ph:
 if p[0]!=1 or not p[1]&1: continue
 for a in range(p[3],p[3]+p[5]-3,4):
  w=S.unpack_from('<I',b,off(a,4))[0]
  if w&0x7c000000!=0x14000000:continue
  imm=w&0x3ffffff; imm=imm-(1<<26) if imm&(1<<25) else imm
  dest=a+imm*4
  if dest in (0x20440c,0x204d6c,0x2052d0,0x2391b4,0x23953c,0x239680,0x23b2e4,0x23b638):edges.append({'from':hex(a),'to':hex(dest),'link':bool(w&0x80000000)})
  if any(lo<dest<hi and not lo<=a<hi for lo,hi in ((0x20440c,0x2047f4),(0x204d6c,0x205058),(0x2052d0,0x2052f8),(0x2391b4,0x239538),(0x23953c,0x239680),(0x239680,0x2396a8),(0x23b2e4,0x23b638),(0x23b638,0x23b844))):interior.append((a,dest))
assert not interior
# Original first instruction is position independent; all remaining original code stays in place.
subprocess.run([LLVM+'clang','--target=aarch64-linux-android37','-c',str(SOURCE_ROOT/'hooks.S'),'-o',str(R/'hooks.o')],check=True)
obj=(R/'hooks.o').read_bytes();oh=S.unpack_from('<16sHHIQQQIHHHHHH',obj)
os=[S.unpack_from('<IIQQQQIIQQ',obj,oh[6]+i*64) for i in range(oh[12])]
on=obj[os[oh[13]][4]:os[oh[13]][4]+os[oh[13]][5]]
osd={on[x[0]:].split(b'\0')[0].decode():x for x in os}
def opay(n):x=osd[n];return obj[x[4]:x[4]+x[5]]
osym=syms(opay('.symtab'),opay('.strtab'));text=bytearray(opay('.text'))
align=lambda x,a:(x+a-1)//a*a
rxoff=align(len(b),0x4000);rxva=align(max(rxoff,max(p[3]+p[6] for p in ph if p[0]==1)),0x4000)
rooff=rxoff+0x4000;rova=rxva+0x4000
# One R segment holds relocated program headers, symbol tables and relocation tables.
count=len(ph)+3;blob=bytearray(count*56)
def put(data,a=16):
 pos=align(len(blob),a);blob.extend(b'\0'*(pos-len(blob)));blob.extend(data);return rova+pos,pos
strings=bytearray(payload('.dynstr')); imports=[]
for name in ('titan_cp3_reader_constructed_v1','titan_cp3_reader_retiring_v1','titan_cp3_mapper_constructed_v1','titan_cp3_mapper_retiring_v1','titan_cp3_mapper_reset_v1','titan_cp3_mapper_process_v1','titan_cp3_reader_drain_v1','titan_cp3_reader_notify_v1','titan_cp3_cursor_motion_v1','titan_cp3_cursor_controller_v1','titan_cp3_context_constructed_v1','titan_cp3_context_retiring_v1','titan_cp3_keyboard_process_v1','titan_cp3_mapper_reconfigured_v1','titan_cp3_reader_stop_gate_v1','titan_cp3_manager_stop_gate_v1','titan_cp3_manager_retiring_v1'):
 imports.append((name,len(strings)));strings.extend(name.encode()+b'\0')
needed=len(strings);strings.extend(b'libtitan_keyboard_surface.so\0')
strva,strpos=put(strings)
dynsyms=bytearray(payload('.dynsym'));oldcount=len(dynsyms)//24
for name,n in imports:dynsyms.extend(S.pack('<IBBHQQ',n,0x12,0,0,0,0))
symva,sympos=put(dynsyms);verva,verpos=put(payload('.gnu.version')+S.pack('<'+'H'*len(imports),*([1]*len(imports))))
# Preserve the old header's absolute search mappings, then rebase datarel fields.
oldhdr=next(p for p in ph if p[0]==0x6474e550)
header=b[oldhdr[2]:oldhdr[2]+oldhdr[5]]
assert header[:4]==bytes((1,0x1b,3,0x3b))
old_eh_va=oldhdr[3]+4+S.unpack_from('<i',header,4)[0]
old_count=S.unpack_from('<I',header,8)[0]
assert len(header)==12+old_count*8
old_entries=[(oldhdr[3]+pc,oldhdr[3]+fde) for pc,fde in S.iter_unpack('<ii',header[12:])]
assert old_entries==sorted(old_entries) and len({pc for pc,fde in old_entries})==old_count
assert old_eh_va==sec['.eh_frame'][3]
for pc,fde in old_entries:
 assert off(pc)>=0 and sec['.eh_frame'][3]<=fde<sec['.eh_frame'][3]+sec['.eh_frame'][5]
# The assembler emits one self-contained zR CIE and twelve FDEs; PC pointers are PREL32.
ehemit=bytearray(opay('.eh_frame'));ehva,ehpos=put(ehemit+b'\0'*4,8)
ehfix=[]
for pos,info,add in S.iter_unpack('<QQq',opay('.rela.eh_frame')):
 idx,typ=info>>32,info&0xffffffff
 assert typ==261 and osym[idx][2]==os.index(osd['.text'])
 target=rxva+osym[idx][3]+add;delta=target-(ehva+pos)
 assert -(1<<31)<=delta<(1<<31) and S.unpack_from('<i',ehemit,pos)[0]==0
 S.pack_into('<i',ehemit,pos,delta)
 ehfix.append({'offset':hex(pos),'type':'R_AARCH64_PREL32','target':hex(target),'place':hex(ehva+pos),'signed_value':delta})
assert len(ehfix)==len([x for x in osym if x[0].endswith('_hook') or x[0] in ('constructor_replay','mapper_constructor_replay','reader_loop_replay','guarded_wake','context_constructor_replay','mapper_reconfigure_replay')])
blob[ehpos:ehpos+len(ehemit)]=ehemit
assert ehemit[:20].hex()=='1000000000000000017a5200017c1e011b0c1f00'
new_entries=[];fde_ranges=[];at=0
while at<len(ehemit):
 length=S.unpack_from('<I',ehemit,at)[0];assert length and length!=0xffffffff
 cie=S.unpack_from('<I',ehemit,at+4)[0]
 if cie:
  assert at+4-cie==0
  pc=ehva+at+8+S.unpack_from('<i',ehemit,at+8)[0]
  extent=S.unpack_from('<I',ehemit,at+12)[0]
  new_entries.append((pc,ehva+at));fde_ranges.append((pc,pc+extent))
 at+=length+4
assert at==len(ehemit)
assert len(fde_ranges)==24 and fde_ranges[0][0]==rxva and fde_ranges[-1][1]==rxva+len(text)
all_entries=sorted(old_entries+new_entries)
hdrpos=align(len(blob),4);hdrva=rova+hdrpos
checked32=lambda n: S.pack('<i',n) if -(1<<31)<=n<(1<<31) else (_ for _ in ()).throw(ValueError(n))
# eh_frame_ptr remains the original block; the table can reference the separate new CIE/FDE block.
newhdr=bytes((1,0x1b,3,0x3b))+checked32(old_eh_va-(hdrva+4))+S.pack('<I',len(all_entries))
newhdr+=b''.join(checked32(pc-hdrva)+checked32(fde-hdrva) for pc,fde in all_entries)
assert put(newhdr,4)[1]==hdrpos
(R/'eh-frame-relocations.json').write_text(json.dumps(ehfix,indent=2)+'\n')
unwind_report={'original_header_va':hex(oldhdr[3]),'new_header_va':hex(hdrva),'header_encoding_hex':'011b033b','original_entries':old_count,'total_entries':len(all_entries),'original_eh_frame_va':hex(old_eh_va),'new_eh_frame_va':hex(ehva),'new_eh_frame_bytes':len(ehemit)+4,'new_fde_ranges':[[hex(a),hex(z)] for a,z in fde_ranges],'new_table_entries':[[hex(pc),hex(fde)] for pc,fde in new_entries],'all_original_absolute_entries_preserved':True,'runtime_backtrace_tested':False}
(R/'unwind-result.json').write_text(json.dumps(unwind_report,indent=2)+'\n')

# Allocate GOT after metadata, with no executable permission.
# Reserve PLT relocations and dynamic first to determine the next page.
relbytes=bytearray(payload('.rela.plt'));relpos=align(len(blob),16)
relva=rova+relpos
pd=next(p for p in ph if p[0]==2);dyn=[]
for t,v in S.iter_unpack('<qQ',b[pd[2]:pd[2]+pd[5]]):
 if t==0:break
 dyn.append([t,v])
dynpos=align(relpos+len(relbytes)+24*len(imports),16)
rwoff=align(rooff+dynpos+(len(dyn)+2)*16,0x4000);rwva=rova+rwoff-rooff
vals={'expected_vtable_got':0x3e2ee0,'constructed_got':rwva,'retiring_got':rwva+8,'constructor_continuation':0x204410,'destructor_continuation':0x204d70}
for i,name in enumerate(('constructed','retiring','mapper_constructed','mapper_retiring','mapper_reset','mapper_process','reader_drain','reader_notify','cursor_motion','cursor_controller','context_constructed','context_retiring','keyboard_process','mapper_reconfigured','reader_stop_gate','manager_stop_gate','manager_retiring')): vals[name+'_got']=rwva+8*i
for name,a,z,w in mapper_specs: vals['mapper_'+name+'_continuation']=a+4
vals['reader_loop_continuation']=0x205b74
vals['context_constructor_continuation']=0x201a64
vals.update(keyboard_process_continuation=0x220788,mapper_reconfigure_continuation=0x239ebc,reader_stop_continuation=0x205a60,manager_stop_continuation=0x27cb18)
vals['original_const_notify']=0x2690a8
vals['manager_destructor_continuation']=0x27c6e4
assert S.unpack_from('<I',b,off(0x27c6e0))[0]==0xa9bc7bfd
vals.update(cursor_motion_continuation=0x25b40c,original_motion_copy=0x216078,cursor_controller_1_continuation=0x259974,cursor_controller_2_continuation=0x259990,cursor_controller_skip=0x259cdc)
# Section index, not section tuple.
textidx=os.index(osd['.text'])
vals.update({name:rxva+v for name,info,idx,v,z in osym if idx==textidx and name})
fixups=[]
def patch_branch(w,delta):
 assert delta%4==0 and -(1<<27)<=delta<(1<<27);return (w&0xfc000000)|((delta>>2)&0x3ffffff)
for pos,info,add in S.iter_unpack('<QQq',opay('.rela.text')):
 idx,typ=info>>32,info&0xffffffff;name=osym[idx][0];target=vals[name]+add;pc=rxva+pos
 w=S.unpack_from('<I',text,pos)[0]
 if typ==282:
  assert w&0xfc000000==0x14000000; nw=patch_branch(w,target-pc)
 elif typ in (275,274):
  assert w&0x9f000000==(0x90000000 if typ==275 else 0x10000000)
  delta=((target>>12)-(pc>>12)) if typ==275 else target-pc
  assert -(1<<20)<=delta<(1<<20)
  nw=(w&~0x60ffffe0)|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
 elif typ==277:
  assert w&0xffc00000==0x91000000
  nw=(w&~0x003ffc00)|((target&4095)<<10)
 elif typ==286:
  assert w&0xffc00000==0xf9400000 and target%8==0
  nw=(w&~0x003ffc00)|(((target&4095)//8)<<10)
 else:raise ValueError(typ)
 S.pack_into('<I',text,pos,nw);fixups.append({'offset':hex(pos),'type':typ,'symbol':name,'target':hex(target),'before':hex(w),'after':hex(nw)})
for i in range(len(imports)):relbytes.extend(S.pack('<QQq',rwva+8*i,((oldcount+i)<<32)|1026,0))
assert put(relbytes)[1]==relpos
updates={5:strva,10:len(strings),6:symva,0x6ffffff0:verva,23:relva,2:len(relbytes)}
for d in dyn:
 if d[0] in updates:d[1]=updates[d[0]]
dyn+=[[1,needed],[0,0]]
dynbytes=b''.join(S.pack('<qQ',*d) for d in dyn)
assert put(dynbytes)[1]==dynpos
for p in ph:
 if p[0]==0x6474e550:p[:]=[0x6474e550,4,rooff+hdrpos,hdrva,hdrva,len(newhdr),len(newhdr),4]
 if p[0]==6:p[:]=[6,4,rooff,rova,rova,count*56,count*56,8]
 if p[0]==2:p[:]=[2,4,rooff+dynpos,rova+dynpos,rova+dynpos,len(dynbytes),len(dynbytes),8]
ph += [[1,5,rxoff,rxva,rxva,len(text),len(text),0x4000],[1,4,rooff,rova,rova,len(blob),len(blob),0x4000],[1,6,rwoff,rwva,rwva,8*len(imports),8*len(imports),0x4000]]
for i,p in enumerate(ph):S.pack_into('<IIQQQQQQ',blob,i*56,*p)
new=bytearray(b);new.extend(b'\0'*(rwoff+8*len(imports)-len(new)));new[rxoff:rxoff+len(text)]=text;new[rooff:rooff+len(blob)]=blob
h[5]=rooff;h[10]=count;S.pack_into('<16sHHIQQQIHHHHHH',new,0,*h)
changes=[]
for name,v,pos,size in [('.dynstr',strva,strpos,len(strings)),('.dynsym',symva,sympos,len(dynsyms)),('.gnu.version',verva,verpos,len(payload('.gnu.version'))+2*len(imports)),('.rela.plt',relva,relpos,len(relbytes)),('.dynamic',rova+dynpos,dynpos,len(dynbytes)),('.eh_frame_hdr',hdrva,hdrpos,len(newhdr))]:
 s=sec[name];idx=sh.index(s);s[3]=v;s[4]=rooff+pos;s[5]=size;S.pack_into('<IIQQQQIIQQ',new,h[6]+idx*64,*s);changes.append(idx)
entries=[(0x20440c,vals['reader_constructor_hook']),(0x204d6c,vals['reader_destructor_hook'])]+[(a,vals['mapper_'+name+'_hook']) for name,a,z,w in mapper_specs]
entries += [(0x220784,vals['keyboard_process_hook']),(0x239eb8,vals['mapper_reconfigure_hook']),(0x205a5c,vals['reader_stop_hook']),(0x27cb14,vals['manager_stop_hook'])]
entries += [(0x27c6e0,vals['manager_destructor_hook'])]
entries += [(0x201a60,vals['context_constructor_hook']),(0x201ac0,vals['context_destructor_hook'])]
entries += [(0x205b70,vals['reader_loop_hook']),(0x2060e0,vals['reader_notify_hook']),(0x25b408,vals['cursor_motion_hook']),(0x259970,vals['cursor_controller_1_hook']),(0x25998c,vals['cursor_controller_2_hook'])]
for a,dest in entries:S.pack_into('<I',new,off(a),patch_branch(0x94000000 if a==0x2060e0 else 0x14000000,dest-a))
allowed=set(range(32,40))|set(range(56,58))
for idx in changes:allowed.update(range(h[6]+idx*64,h[6]+(idx+1)*64))
for a,dest in entries:allowed.update(range(off(a),off(a)+4))
diffs=[i for i,(x,y) in enumerate(zip(b,new)) if x!=y];assert set(diffs)<=allowed
assert not any(p[0]==1 and p[1]&3==3 for p in ph)
# Preserve original notes, relocation payloads, and code outside seven entries and one callsite.
for s in sh:
 if s[1]==7:assert new[s[4]:s[4]+s[5]]==b[s[4]:s[4]+s[5]]
for p in ph:
 if p[0]==1 and p[1]&1 and p[2]<len(b):
  for i in range(p[2],p[2]+p[5]):
   if i not in allowed:assert b[i]==new[i]
out=R/'libinputflinger-final-hooks-v3-OFFLINE-ONLY.so';out.write_bytes(new)
read=subprocess.run([LLVM+'llvm-readelf','-l','-d','-rW','--dyn-syms',str(out)],text=True,capture_output=True);assert read.returncode==0 and not read.stderr,read.stderr
(R/'patched-readelf.txt').write_text(read.stdout);assert 'TEXTREL' not in read.stdout
(R/'hooks-relocations.json').write_text(json.dumps(fixups,indent=2)+'\n')
report={'status':'OFFLINE EXPERIMENT; NOT AN INSTALL CANDIDATE','source_sha256':PIN,'output_sha256':H.sha256(new).hexdigest(),'mapper_aliases':mapper_aliases,'mapper_specs':mapper_specs,'constructor_aliases':[x[0] for x in ctor],'destructor_aliases':[x[0] for x in dtor],'direct_entry_edges':edges,'patched_entrypoints':[(hex(a),hex(d)) for a,d in entries],'append_segments':ph[-3:],'sidecar_imports':[x[0] for x in imports],'all_other_original_code_bytes_preserved':True,'original_notes_preserved':True,'no_RWX_no_TEXTREL':True,'new_got_is_RW_not_RELRO':True,'runtime_loader_and_lifecycle_proof':False,'wrapper_CFI_and_header_static_proof':True,'original_byte_changes':diffs}
(R/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='original_byte_changes'},indent=2))
