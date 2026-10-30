from pathlib import Path
import re,unittest,os
P=Path(__file__).parent
# Interpret the assembled/read-back adapter, with Android methods replaced by nonsecret test doubles.
def run(e):
 s=Path(os.environ.get('TITAN_PIN_TEST_SMALI',str(P/'readback.smali'))).read_text().splitlines();start=next(i for i,x in enumerate(s) if x.startswith('.method public final invoke('));s=[x.strip() for x in s[start+1:] if x.strip() and not x.strip().startswith(('#','.'))];labels={x:i for i,x in enumerate(s) if x.startswith(':')};r={'p0':'callable','p1':'event'};ret=None;pc=0;delegate=[]
 def val(x):return r[x] if x in r else int(x,0)
 for _ in range(150):
  x=s[pc];pc+=1
  if x.startswith(':') or x.startswith('check-cast'):continue
  if x.startswith('iget-object '):
   a,b,field=x[12:].split(', ');r[a]={'nativeKeyEvent':'event','receiver':'overlay','keyguardMediaKeyInteractor':'media'}[field.split('->')[1].split(':')[0]];continue
  if x.startswith('invoke-'):
   regs,method=re.search(r'\{(.*?)\}, (.*)',x).groups();v=[r[a] for a in regs.split(', ') if a]
   if 'processMediaKeyEvent' in method:ret=e.get('media',False)
   elif 'getAuthMethodViewModel' in method:ret=e.get('vm','pin')
   elif 'getType-' in method:ret=e.get('type',2)
   elif 'getDevice()' in method:ret=e.get('device','aw9523-key')
   elif 'getName()' in method:ret=v[0]
   elif '->equals(' in method:ret=v[0]==v[1]
   elif 'getRepeatCount()' in method:ret=e.get('repeat',0)
   elif 'getNumber()' in method:ret=e.get('number',0)
   elif 'getKeyCode()' in method:ret=e.get('key',32)
   elif 'onKeyEvent-uiMRsoQ' in method:delegate.append(tuple(v));ret=True
   elif 'Boolean;->valueOf' in method:ret=v[0]
   else:raise AssertionError(method)
   continue
  if x.startswith('move-result'):r[x.split()[-1]]=ret;continue
  if x.startswith('instance-of '):a,b,c=x[12:].split(', ');r[a]=r[b]=='pin';continue
  if x.startswith('const-string '):a,b=x[13:].split(', ',1);r[a]=b.strip('"');continue
  if x.startswith(('const/4 ','const/16 ')):a,b=x.split(' ',1)[1].split(', ');r[a]=int(b,0);continue
  if x.startswith('add-int/lit8 '):a,b,c=x[13:].split(', ');r[a]=r[b]+int(c,0);continue
  if x.startswith('goto '):pc=labels[x.split()[1]];continue
  if x.startswith('if-'):
   op,args=x.split(' ',1);args=args.split(', ');lab=args[-1];a=val(args[0]);b=val(args[1]) if len(args)==3 else None
   yes={'if-eqz':not a,'if-nez':bool(a),'if-ne':a!=b,'if-lt':a<b if b is not None else False,'if-gt':a>b if b is not None else False}[op]
   if yes:pc=labels[lab]
   continue
  if x.startswith('return-object '):return delegate
  raise AssertionError(x)
 raise AssertionError('loop')
class AdapterTests(unittest.TestCase):
 def test_all_ten_printed_digits(self):
  for n in range(10):self.assertEqual(run({'number':48+n})[-1],('pin',2,7+n))
 def test_negative_paths(self):
  for change in ({'vm':'password'},{'device':'external-usb'},{'device':None},{'type':1},{'key':28},{'key':55},{'number':47},{'number':58},{'number':0}):
   self.assertEqual(run({'number':53,**change})[-1][-1],change.get('key',32))
 def test_repeat_delegates_as_native_digit(self):self.assertEqual(run({'number':53,'repeat':3})[-1],('pin',2,12))
 def test_missing_vm(self):self.assertEqual(run({'vm':None}),[])
 def test_media_untouched(self):self.assertEqual(run({'media':True}),[])
 def test_delete_and_confirm(self):
  for key in (67,66,23):self.assertEqual(run({'key':key,'number':53})[-1][-1],key)
 def test_all_vm_types_no_translation(self):
  for vm in ('password','pattern'):self.assertEqual(run({'vm':vm,'number':53})[-1][-1],32)
 def test_original_numeric_key_untouched(self):
  for key in list(range(7,17))+list(range(144,154)):self.assertEqual(run({'key':key,'number':53})[-1][-1],key)
if __name__=='__main__':unittest.main()
