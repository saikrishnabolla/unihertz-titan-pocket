from pathlib import Path
import difflib, hashlib, json

P = Path(__file__).resolve().parent
old = (P/'linux-v4.14.186-lpm_trie.c').read_text()
upstream = (P/'linux-v4.16-lpm_trie.c').read_text()
stable = (P/'linux-v5.10.240-lpm_trie.c').read_text()
delete_source = (P/'linux-v4.19.325-lpm_trie.c').read_text()
assert hashlib.sha256(old.encode()).hexdigest() == '180e4c67b149e9aa76f8938a2396b423cf0423d8b09474bbefe0634e6a132479'
assert hashlib.sha256(stable.encode()).hexdigest() == '2d0b854140c172016b91a1d43dbdf03693f8b78976a2a24d61c6181fce717c1b'
assert hashlib.sha256(delete_source.encode()).hexdigest() == '058cae425949550ff15f9d7d4252d78e7d3acd13249a58958c6f3a823a4fcb40'

def function(text, start):
    begin = text.index(start)
    brace = text.index('{', begin)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[begin:end]

iterator = function(upstream, 'static int trie_get_next_key(')
helpers = '\n\n'.join(function(old, name) for name in ('static inline int extract_bit(', 'static size_t longest_prefix_match('))
structs = old[old.index('/* Intermediate node */'):old.index('/* This trie implements')]
(P/'upstream-iterator.h').write_text(structs + helpers + '\n\n' + iterator + '\n')
patched = old.replace(function(old, 'static int trie_get_next_key('), iterator)
(P/'lpm_trie-v4.16-exact-backport.c').write_text(patched)
(P/'v4.16-exact.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True), patched.splitlines(True), fromfile='a/kernel/bpf/lpm_trie.c', tofile='b/kernel/bpf/lpm_trie.c')))

delete = function(delete_source, 'static int trie_delete_elem(')
corrected = function(stable, 'static int trie_get_next_key(')
patched = old.replace(function(old, 'static int trie_get_next_key('), corrected)
patched = patched.replace(function(old, 'static int trie_delete_elem('), delete)
(P/'lpm_trie-backport.c').write_text(patched)
(P/'lpm-iterate-delete-backport.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True), patched.splitlines(True), fromfile='a/kernel/bpf/lpm_trie.c', tofile='b/kernel/bpf/lpm_trie.c')))
extra = '\n\n'.join(function(old, name) for name in ('static struct lpm_trie_node *lpm_trie_node_alloc(', 'static int trie_update_elem('))
(P/'corrected-iterator.h').write_text('#define HAS_MUTATIONS 1\n' + structs + helpers + '\n\n' + extra + '\n\n' + delete + '\n\n' + corrected + '\n')
(P/'v4.19-iterator.h').write_text(structs + helpers + '\n\n' + function(delete_source, 'static int trie_get_next_key(') + '\n')
