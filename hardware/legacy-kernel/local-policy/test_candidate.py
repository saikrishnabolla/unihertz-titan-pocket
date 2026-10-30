import os
import pathlib,re,json,hashlib,zlib,struct
P=pathlib.Path(os.environ.get('TITAN_LOCAL_POLICY_WORK', 'work'));REL='android/net/connectivity/com/android/server/'
def methods(text):return {x.splitlines()[0].split()[-1]:x for x in re.findall(r'(?ms)^\.method [^\n]+\n.*?^\.end method',text)}
def load(root,name):return methods((P/root/(REL+name+'.smali')).read_text())
class Rejected(Exception):pass
class UnsupportedSyscall(Exception):pass
class VM:
 def __init__(self,sdk=True,release='modern',fail_lpm=False):self.sdk=sdk;self.release=release;self.fail_lpm=fail_lpm;self.fields={'sL4sSupported':True,'sLoopbackAccessMetricsEnabled':True,'sLoopbackPermissionEnabled':True};self.trace=[];self.pending=None
 def execute(self,text,args=None):
  lines=[];labels={}
  for line in text.splitlines()[1:]:
   line=line.strip()
   if line.startswith(':'):labels[line]=len(lines)
   elif line and not line.startswith(('.','#')):lines.append(line)
  r={'p0':'deps'};r.update(args or {});result=None;i=0;steps=0
  def val(x):
   if x.startswith(('v','p')):return r.get(x,0)
   return int(x,0)
  while i<len(lines):
   steps+=1;assert steps<1500,'unbounded execution';s=lines[i];i+=1;op=s.split()[0];tail=s[len(op):].strip();a=tail.split(', ')
   if op.startswith('invoke-'):
    regs,target=tail.split('}, ');regs=regs[1:];regs=[] if not regs else regs.split(', ')
    assert not any(' .. ' in x for x in regs),s
    vs=[val(x) for x in regs];name=target.split('->')[1].split('(')[0]
    if 'LegacyLocalPolicy;' in target:result=self.execute(self.helper[name],{'p0':vs[0]} if vs else {})
    elif 'SdkLevel;' in target or 'SdkUtil;' in target:result=self.sdk
    elif 'Landroid/system/Os;->uname' in target:
     if isinstance(self.release,Exception):raise self.release
     result={'release':self.release}
    elif 'Objects;->requireNonNull' in target:
     if vs[0] is None:raise ValueError('null release')
     result=vs[0]
    elif 'String;->equals' in target:result=vs[0]==vs[1]
    elif name=='<init>':
     vs[0]['value']=vs[1] if len(vs)>1 else None
    elif name=='isAccessLocalNetworkPermissionEnabled':result=True
    elif name=='isAtLeastB':result=self.sdk
    elif name in ['getCallingPid','myPid']:result=11
    elif name=='throwIfPre25Q2':result=self.execute(orig['throwIfPre25Q2(Ljava/lang/String;)V'],{'p0':vs[0],'p1':vs[1]})
    elif name.startswith('get') and 'BpfNetMaps;' in target:
     if name in ['getLocalNetAccessMap','getLocalNetUidHostAllowlistMap'] and self.fail_lpm:raise UnsupportedSyscall('get_next_key errno524')
     result={'map':name};self.trace.append(('open',name))
    elif name in ['updateEntry','clear','set','getValue']:
     mn=vs[0]['map'];self.trace.append((name,mn,vs[2] if len(vs)>2 else vs[1] if len(vs)>1 else None));result=None
    elif 'IllegalStateException;' in target or 'ServiceSpecificException;' in target:raise Rejected()
    else:raise AssertionError(('invoke',s))
   elif op.startswith('move-result'):r[tail]=result
   elif op in ['const/4','const-wide/16']:r[a[0]]=int(a[1],0)
   elif op=='const-string':r[a[0]]=tail.split(', ',1)[1].strip('"')
   elif op.startswith('sget'):
    f=a[1].split('->')[1].split(':')[0];r[a[0]]=95 if f=='EOPNOTSUPP' else self.fields.get(f,0)
   elif op.startswith('sput'):self.fields[a[1].split('->')[1].split(':')[0]]=val(a[0])
   elif op.startswith('iget'):
    f=a[2].split('->')[1].split(':')[0];r[a[0]]=val(a[1])[f]
   elif op=='new-instance':r[a[0]]={'type':a[1]}
   elif op in ['monitor-enter','monitor-exit','check-cast']:pass
   elif op in ['move-wide','move-object']:r[a[0]]=val(a[1])
   elif op=='if-ne':
    if val(a[0])!=val(a[1]):i=labels[a[2]]
   elif op=='if-eqz':
    if not val(a[0]):i=labels[a[1]]
   elif op=='if-nez':
    if val(a[0]):i=labels[a[1]]
   elif op.startswith('goto'):i=labels[tail]
   elif op=='xor-int/lit8':r[a[0]]=val(a[1])^val(a[2])
   elif op=='and-int/2addr':r[a[0]]=val(a[0])&val(a[1])
   elif op=='rem-long/2addr':r[a[0]]=val(a[0])%val(a[1])
   elif op=='add-long/2addr':r[a[0]]=val(a[0])+val(a[1])
   elif op=='cmp-long':r[a[0]]=(val(a[1])>val(a[2]))-(val(a[1])<val(a[2]))
   elif op=='return':return val(tail)
   elif op=='return-void':return None
   elif op=='throw':raise Rejected(val(tail))
   elif op=='move-exception':raise AssertionError('unexpected handler')
   else:raise AssertionError((op,s))
  raise AssertionError('missing return')
helper=load('readback','LegacyLocalPolicy');VM.helper={k.split('(')[0]:v for k,v in helper.items()}
checks=0
for sdk,rel,want in [(True,'4.14.186-g40b2a1864-dirty',False),(True,'4.14.186-other',True),(True,'6.12.0',True),(False,'6.12.0',False)]:
 vm=VM(sdk,rel);assert vm.execute(VM.helper['isSupported'])==want;checks+=1
 for enabled in [False,True]:assert vm.execute(VM.helper['gate'],{'p0':enabled})==(want and enabled);checks+=1
 try:vm.execute(VM.helper['requireSupported']);assert not sdk or want
 except Rejected:assert sdk and not want
 checks+=1
for bad in [None,RuntimeError('uname failed')]:
 try:VM(True,bad).execute(VM.helper['isSupported']);raise AssertionError('unexpected input accepted')
 except (ValueError,RuntimeError):checks+=1
orig=load('original','BpfNetMaps');new=load('readback','BpfNetMaps');key=next(k for k in orig if k.startswith('initBpfMaps('))
try:VM(True,'4.14.186-g40b2a1864-dirty',True).execute(orig[key]);raise AssertionError('original failure not reproduced')
except UnsupportedSyscall:checks+=1
modern_original=VM();modern_original.execute(orig[key]);modern_new=VM();modern_new.execute(new[key]);assert modern_new.trace==modern_original.trace;checks+=1
legacy=VM(True,'4.14.186-g40b2a1864-dirty',True);legacy.execute(new[key]);assert not any('LocalNetAccess' in str(x) or 'LocalNetUidHost' in str(x) or 'LocalNetCache' in str(x) for x in legacy.trace);checks+=1
notes=[x for x in legacy.trace if x[0]=='set' and x[1]=='getLocalNetNoteOpsEnabledBpfBoolean'];assert len(notes)==1 and notes[0][2]==False;checks+=1
for name in ['getUidPermissionChunkMap','getLoopbackPermissionEnabledBpfBoolean','getLoopbackAccessMetricsEnabledBpfBoolean','getConfigurationMap','getDataSaverEnabledMap','getIngressDiscardMap']:
 assert [x for x in legacy.trace if x[1]==name]==[x for x in modern_original.trace if x[1]==name];checks+=1
# Whole DEX round-trip diff: every unrequested method/class must remain identical.
oldfiles={x.relative_to(P/'full-original'):x for x in (P/'full-original').rglob('*.smali')};newfiles={x.relative_to(P/'full-readback'):x for x in (P/'full-readback').rglob('*.smali')};diff=[]
assert set(newfiles)-set(oldfiles)=={pathlib.Path(REL+'LegacyLocalPolicy.smali')};checks+=1
for f,path in oldfiles.items():
 before=re.sub(r"call_site_\d+", "call_site_INDEX", path.read_text());after=re.sub(r"call_site_\d+", "call_site_INDEX", newfiles[f].read_text())
 if before==after:continue
 bm=methods(before);am=methods(after);assert bm.keys()==am.keys()
 for method in bm:
  if bm[method]!=am[method]:diff.append({'class':str(f),'method':method})
assert len(diff)==22;checks+=1
# Every local-mutator invocation in entire resulting DEX is guarded or inside its guarded entry point.
cs=load('readback','ConnectivityService');calls=0
for name,m in cs.items():
 lines=[x.strip() for x in m.splitlines() if x.strip() and not x.strip().startswith(('.line','#'))]
 for i,l in enumerate(lines):
  if re.match(r'invoke-virtual(?:/range)? ',l) and re.search(r'BpfNetMaps;->(?:addLocalNet|removeLocalNet)',l):
   assert lines[i-3].endswith('LegacyLocalPolicy;->isSupported()Z');assert lines[i-2]=='move-result v0';assert lines[i-1].startswith('if-eqz v0, :');assert lines[i+1]==lines[i-1].split(', ')[1];calls+=1
assert calls==15;checks+=1
mutators=['addLocalNetAccess','removeLocalNetAccess','addLocalNetUidAccess','removeLocalNetUidAccess','addLocalNetUidHostAccess','removeLocalNetHostAllowlistForInterface']
for name,m in new.items():
 if name.split('(')[0] in mutators:
  executable=[x.strip() for x in m.splitlines()[1:] if x.strip() and not x.strip().startswith(('.','#',':'))]
  assert executable[0].endswith('LegacyLocalPolicy;->requireSupported()V');checks+=1
for file in (P/'full-readback').rglob('*.smali'):
 if file.name in ['BpfNetMaps.smali','ConnectivityService.smali']:continue
 assert not re.search(r'invoke-[^\n]+BpfNetMaps;->(?:addLocalNet|removeLocalNet)',file.read_text()),file
checks+=1
# Reporting methods execute the decoded helper gate rather than dependency flag changes.
for release,want in [('4.14.186-g40b2a1864-dirty',False),('modern',True)]:
 vm=VM(True,release);vm.fields['sBetaMetricsEnabled']=True
 for method in ['isAccessLocalNetworkPermissionEnabled()Z','isLocalNetMetricsEnabled()Z']:
  assert vm.execute(new[method],{'p0':{'mDeps':'deps'}})==want;checks+=1
allow=cs['allowLocalNetAccess(IILjava/util/List;)V']
assert allow.index('->getCallingPid()I')<allow.index('->requireSupported()V')<allow.index('->isAtLeastB()Z');checks+=1
# Mutation checks: restoring SDK-only capability must reproduce the old failing path.
real=VM.helper['isSupported'];VM.helper['isSupported']='.method public static isSupported()Z\n .registers 1\n const/4 v0, 0x1\n return v0\n.end method'
try:
 VM(True,'4.14.186-g40b2a1864-dirty',True).execute(new[key]);raise AssertionError('bad capability mutation escaped')
except UnsupportedSyscall:checks+=1
finally:VM.helper['isSupported']=real
# Removing only the scalar gate must enable note ops in the reduced mode; reject that mutation.
mutated=re.sub(r'    invoke-static \{v5\}, [^\n]+LegacyLocalPolicy;->gate\(Z\)Z\n\n    move-result v5\n\n','',new[key]);assert mutated!=new[key]
mut=VM(True,'4.14.186-g40b2a1864-dirty',True);mut.execute(mutated)
assert [x for x in mut.trace if x[0]=='set' and x[1]=='getLocalNetNoteOpsEnabledBpfBoolean'][0][2]==True;checks+=1
# Execute original and candidate pre-B guards through their unchanged exception path.
pre_b_results=[]
for name in mutators:
 method=next(k for k in orig if k.startswith(name+'('))
 for which,body in [('original',orig[method]),('candidate',new[method])]:
  try:VM(False,'old').execute(body,{'p0':{'mDeps':'deps'}});raise AssertionError('pre-B mutator unexpectedly succeeded')
  except Rejected as e:
   assert e.args[0]['type']=='Ljava/lang/UnsupportedOperationException;';pre_b_results.append([name,which,e.args[0]['type']]);checks+=1
for which,body in [('original',load('original','ConnectivityService')['allowLocalNetAccess(IILjava/util/List;)V']),('candidate',allow)]:
 try:VM(False,'old').execute(body,{'p0':{'mDeps':'deps'}});raise AssertionError('pre-B API unexpectedly succeeded')
 except Rejected as e:
  assert e.args[0]['type']=='Ljava/lang/UnsupportedOperationException;';pre_b_results.append(['allowLocalNetAccess',which,e.args[0]['type']]);checks+=1
b=(P/'classes.dex').read_bytes();assert b[:8]==b'dex\n039\0';assert struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff;assert b[12:32]==hashlib.sha1(b[32:]).digest();checks+=1
out={'checks':checks,'guarded_call_sites':calls,'semantically_preserved_original_classes':2051,'changed_methods':diff,'pre_b_exception_results':pre_b_results,'legacy_init_trace':legacy.trace,'modern_init_trace':modern_new.trace,'limits':'Mocked Android/native method calls; executes actual re-disassembled control flow, not ART runtime. No phone/image test.'}
(P/'test-results.json').write_text(json.dumps(out,indent=2)+'\n');print('PASS',checks,'checks; 15 guarded calls; original errno524 path reproduced; modern init trace unchanged; legacy scalar false and unrelated maps preserved')
