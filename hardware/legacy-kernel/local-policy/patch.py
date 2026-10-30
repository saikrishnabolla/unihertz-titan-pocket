import os
import pathlib,re,shutil,json,hashlib
P=pathlib.Path(os.environ.get('TITAN_LOCAL_POLICY_WORK', 'work'));O=P/'original';D=P/'candidate';shutil.copytree(O,D,dirs_exist_ok=True)
B='Landroid/net/connectivity/com/android/server/BpfNetMaps;';H='Landroid/net/connectivity/com/android/server/LegacyLocalPolicy;'
base='android/net/connectivity/com/android/server/'
changed=[]
def edit(file,fn):
 p=D/(base+file+'.smali');s=p.read_text()
 def each(m):
  old=m.group();new=fn(old)
  if new!=old:changed.append({'class':file,'method':old.splitlines()[0][8:],'original_sha256':hashlib.sha256(old.encode()).hexdigest(),'candidate_sha256':hashlib.sha256(new.encode()).hexdigest()})
  return new
 p.write_text(re.sub(r'(?ms)^\.method .*?^\.end method',each,s))
def once(s,old,new):
 assert s.count(old)==1,(old,s.count(old));return s.replace(old,new,1)
mutators=['addLocalNetAccess','removeLocalNetAccess','addLocalNetUidAccess','removeLocalNetUidAccess','addLocalNetUidHostAccess','removeLocalNetHostAllowlistForInterface']
def bpf(s):
 name=re.search(r'^\.method .*? ([^ ]+)\(',s)[1]
 if name=='initBpfMaps':
  old='invoke-static {}, Landroid/net/connectivity/com/android/modules/utils/build/SdkLevel;->isAtLeastB()Z'
  assert s.count(old)==2
  s=s.replace(old,'invoke-static {}, '+H+'->isSupported()Z',1)
  s=once(s,':cond_116\n    invoke-virtual {v0, v5}',':cond_116\n    invoke-static {v5}, '+H+'->gate(Z)Z\n\n    move-result v5\n\n    invoke-virtual {v0, v5}')
 elif name=='ensureInitialized':
  old='    sput-boolean v0, '+B+'->sLoopbackAccessMetricsEnabled:Z'
  s=once(s,old,'    invoke-static {v0}, '+H+'->gate(Z)Z\n\n    move-result v0\n\n'+old)
 elif name in mutators:
  s=re.sub(r'(    \.registers \d+\n)',r'\1\n    invoke-static {}, '+H+'->requireSupported()V\n',s,count=1)
 elif name in ['isLocalNetMetricsEnabled','isAccessLocalNetworkPermissionEnabled']:
  s=once(s,'    return p0','    invoke-static {p0}, '+H+'->gate(Z)Z\n\n    move-result p0\n\n    return p0')
 elif name=='dump':
  old='    .line 2225\n    sget-object p2'
  new='    invoke-static {}, '+H+'->isSupported()Z\n\n    move-result p2\n\n    if-nez p2, :legacy_dump_supported\n\n    const-string p2, "Local-network policy unavailable: legacy kernel lacks LPM iteration/deletion"\n\n    invoke-virtual {p1, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V\n\n    goto :legacy_dump_done\n\n    :legacy_dump_supported\n    .line 2225\n    sget-object p2'
  s=once(s,old,new);s=once(s,'    .line 2239\n    sget-object p2','    :legacy_dump_done\n    .line 2239\n    sget-object p2')
 return s
edit('BpfNetMaps',bpf)
callcounts={}
def cs(s):
 # Preserve the original SDK gate, adding exact legacy capability only at listener construction.
 anchor='    if-eqz v0, :cond_2b6'
 if anchor in s:
  assert '->getLocalNetEventListener(' in s
  s=once(s,anchor,anchor+'\n\n    invoke-static {}, '+H+'->isSupported()Z\n\n    move-result v0\n\n    if-eqz v0, :cond_2b6')
 calls=list(re.finditer(r'^    invoke-virtual(?:/range)? .*?'+re.escape(B)+r'->((?:addLocalNet|removeLocalNet)[^(]+)\([^\n]+\)V$',s,re.M))
 if not calls:return s
 assert all(c[1] in mutators for c in calls)
 name=s.splitlines()[0];callcounts[name]=len(calls)
 # Insert a new v0; shift all original v registers together so range calls stay contiguous.
 s=re.sub(r'\bv(\d+)\b',lambda m:'v'+str(int(m[1])+1),s)
 s=re.sub(r'\.registers (\d+)',lambda m:'.registers '+str(int(m[1])+1),s,count=1)
 count=0
 def guard(m):
  nonlocal count
  count+=1;return '    invoke-static {}, '+H+'->isSupported()Z\n\n    move-result v0\n\n    if-eqz v0, :legacy_skip_'+str(count)+'\n\n'+m[0]+'\n\n    :legacy_skip_'+str(count)
 s=re.sub(r'^    invoke-virtual(?:/range)? .*?'+re.escape(B)+r'->(?:addLocalNet|removeLocalNet)[^(]+\([^\n]+\)V$',guard,s,flags=re.M)
 if re.search(r'^\.method public allowLocalNetAccess\(',s):
  # Explicit unsupported error at the synchronous API boundary, before any handler post.
  s=once(s,'    if-ne v1, v2, :cond_53','    if-ne v1, v2, :cond_53\n\n    invoke-static {}, '+H+'->requireSupported()V')
 return s
edit('ConnectivityService',cs)
helper='''.class public final Landroid/net/connectivity/com/android/server/LegacyLocalPolicy;
.super Ljava/lang/Object;

.method public static isSupported()Z
    .registers 2
    invoke-static {}, Landroid/net/connectivity/com/android/modules/utils/build/SdkLevel;->isAtLeastB()Z
    move-result v0
    if-eqz v0, :unsupported
    invoke-static {}, Landroid/system/Os;->uname()Landroid/system/StructUtsname;
    move-result-object v0
    iget-object v0, v0, Landroid/system/StructUtsname;->release:Ljava/lang/String;
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v0
    const-string v1, "4.14.186-g40b2a1864-dirty"
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    xor-int/lit8 v0, v0, 0x1
    return v0
    :unsupported
    const/4 v0, 0x0
    return v0
.end method

.method public static gate(Z)Z
    .registers 2
    invoke-static {}, Landroid/net/connectivity/com/android/server/LegacyLocalPolicy;->isSupported()Z
    move-result v0
    and-int/2addr p0, v0
    return p0
.end method

.method public static requireSupported()V
    .registers 3
    invoke-static {}, Landroid/net/connectivity/com/android/modules/utils/build/SdkLevel;->isAtLeastB()Z
    move-result v0
    if-eqz v0, :supported
    invoke-static {}, Landroid/net/connectivity/com/android/server/LegacyLocalPolicy;->isSupported()Z
    move-result v0
    if-nez v0, :supported
    new-instance v0, Landroid/os/ServiceSpecificException;
    sget v1, Landroid/system/OsConstants;->EOPNOTSUPP:I
    const-string v2, "Local-network policy unavailable on this legacy kernel"
    invoke-direct {v0, v1, v2}, Landroid/os/ServiceSpecificException;-><init>(ILjava/lang/String;)V
    throw v0
    :supported
    return-void
.end method
'''
(D/(base+'LegacyLocalPolicy.smali')).write_text(helper)
(P/'changed-methods.json').write_text(json.dumps({'changed':changed,'added_helper_methods':['isSupported()Z','gate(Z)Z','requireSupported()V'],'connectivity_call_sites':callcounts},indent=2)+'\n')
print('changedMethods',len(changed),'guardedCalls',sum(callcounts.values()))
