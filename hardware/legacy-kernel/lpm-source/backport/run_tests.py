"""Rebuild host harnesses and retain pass/failure evidence in this folder."""
from pathlib import Path
import hashlib,json,re,subprocess,sys,time,shutil,tempfile

P=Path(__file__).resolve().parent
def run(argv,name):
    start=time.monotonic()
    p=subprocess.run(list(map(str,argv)),cwd=P,capture_output=True,timeout=120)
    (P/(name+'.log')).write_bytes(p.stdout+p.stderr)
    return dict(command=list(map(str,argv)),exit=p.returncode,seconds=round(time.monotonic()-start,3),
                log=name+'.log',output=(p.stdout+p.stderr).decode(errors='replace'))
checks=[]
checks.append(run([sys.executable,P/'prepare.py'],'prepare'))
assert checks[-1]['exit']==0
with tempfile.TemporaryDirectory(prefix='patch-apply-',dir=P) as temp:
    tree=Path(temp);(tree/'kernel/bpf').mkdir(parents=True)
    target=tree/'kernel/bpf/lpm_trie.c'
    shutil.copyfile(P/'linux-v4.14.186-lpm_trie.c',target)
    applied=subprocess.run(['/usr/bin/patch','-p1','-i',str(P/'lpm-iterate-delete-backport.patch')],cwd=tree,capture_output=True,timeout=30)
    (P/'patch-apply.log').write_bytes(applied.stdout+applied.stderr)
    assert applied.returncode==0 and target.read_bytes()==(P/'lpm_trie-backport.c').read_bytes()
for header,label in [('upstream-iterator.h','initial4.16'),('v4.19-iterator.h','stable4.19'),('corrected-iterator.h','backport')]:
    argv=['clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-g','-O1',
          '-fsanitize=address,undefined','-fno-omit-frame-pointer','-DITERATOR_HEADER="'+header+'"',
          P/'test_iterator.c','-o',P/('test-'+label)]
    checks.append(run(argv,'build-'+label));assert checks[-1]['exit']==0,checks[-1]
for label,mode,expected in [('initial4.16','right-only','FAIL'),('initial4.16','deep-stack','AddressSanitizer: heap-buffer-overflow'),
                            ('stable4.19',None,'missing test'),('backport','right-only','PASS'),
                            ('backport','deep-stack','PASS'),('backport',None,'PASS')]:
    checks.append(run([P/('test-'+label)]+([mode] if mode else []),label+'-'+(mode or 'full')))
    last=checks[-1]
    assert expected in last['output'],last
    assert (last['exit']==0)==(label=='backport'),last
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=['linux-v4.14.186-lpm_trie.c','linux-v4.16-lpm_trie.c','linux-v4.19.325-lpm_trie.c','linux-v5.10.240-lpm_trie.c',
       'lpm_trie-backport.c','lpm-iterate-delete-backport.patch','corrected-iterator.h','test_iterator.c','prepare.py','run_tests.py']
summary={
 'status':'OFFLINE SOURCE BACKPORT; HOST TESTS PASS; NOT A BUILT KERNEL',
 'changes':['Replace trie_get_next_key stub with full upstream iterator and later upstream fixes',
            'Replace trie_delete_elem stub with upstream deletion including exact-match fix'],
 'patch_applies_and_reproduces_exact_source':True,
 'source_hashes':{f:sha(P/f) for f in files},
 'upstream_sources':{
   'baseline':'https://raw.githubusercontent.com/gregkh/linux/v4.14.186/kernel/bpf/lpm_trie.c',
   'iterator_initial':'https://raw.githubusercontent.com/gregkh/linux/v4.16/kernel/bpf/lpm_trie.c',
   'iterator_final':'https://raw.githubusercontent.com/gregkh/linux/v5.10.240/kernel/bpf/lpm_trie.c',
   'delete_final':'https://raw.githubusercontent.com/gregkh/linux/v4.19.325/kernel/bpf/lpm_trie.c'},
 'upstream_commits':{
   'initial_iteration':'b471f2f1de8b816f1e799b80aa92588f3566e4bd',
   'initial_deletion':'e454cf5958538666635488030046b6a84a22d447',
   'delete_optimization':'b5d7388f9db78f19e6af7b56a469ca8d1860329d',
   'delete_exact_match':'7c0cdf0b3940f63d9777c3fcf250a2f83859ca54',
   'iterator_atomic_allocation':'2310035fa03f651dd5b03f19a26a97512aa8842c',
   'iterator_initial_null_safety':'6dd1ec6c7a2c304e9e2e2edd9e7ccb8e8791d36a',
   'iterator_right_child':'da2577fdd0932ea4eefe73903f1130ee366767d2',
   'iterator_stack_capacity':'13400ac8fb80c57c2bfb12ebd35ee121ce9b4d21',
   'iterator_exact_match':'27abc7b3fa2e09bbe41e2924d328121546865eda'},
 'test_result':checks[-1]['output'].strip(),
 'test_scope':['Actual baseline4.14 update/allocator/helper functions compiled with copied backport iterator/delete',
  'Independent compressed-prefix builder and postorder oracle compare complete enumeration',
  'Empty, missing, invalid-prefix, deleted and existing keys; intermediate nodes and right-only children',
  'Prefix0..192 actual update/enumerate/delete/clear; prefix0..2048 full-depth boundary',
  'IPv4/IPv6/Android192bit and maximum2048bit key widths',
  'Real insert -> enumerate -> delete -> clear sequences for125 seeded tries',
  'GFP_ATOMIC allocation failure remains ENOMEM, with balanced allocation/free accounting',
  'ASAN/UBSAN enabled; three historical defects reproduced in uncorrected source'],
 'locking_compatibility':[
  'Source structs and existing helper/update code unchanged in patch',
  'Iterator called under syscall RCU read lock; stack uses GFP_ATOMIC|__GFP_NOWARN',
  'Delete uses existing raw_spin_lock_irqsave and deferred kfree_rcu',
  'Host shim asserts RCU/lock use and defers frees to explicit mock grace periods'],
 'limitations':[
  'No matching OEM source tree, complete kernel compilation, device changes or boot test provided',
  'Host RCU/spinlock shim is serialized; it does not model concurrent mutation, weak memory ordering or kernel grace-period implementation',
  '2048bit full-depth boundary uses an independently built valid chain;192bit full-depth uses actual kernel insertion',
  'No changes to existing baseline update-flag semantics, permissions, SELinux, map definitions or BPF programs',
  'Native kernel ABI and runtime integration require the matching vendor tree/config/toolchain and separate verification'],
 'checks':[{k:v for k,v in c.items() if k!='output'} for c in checks]
}
(P/'backport-report.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:summary[k] for k in ('status','test_result','source_hashes')},indent=2))
