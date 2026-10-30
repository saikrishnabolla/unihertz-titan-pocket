"""Offline exact DEX patch: add 8dp to collapsed SingleShade QQS/media top padding."""
import argparse,hashlib,json,struct,zipfile,zlib
from pathlib import Path
APK_SHA='8bd6490cb42e3de628805cfdf17854f24ef150dc1e5cb193fc4e98af4901a789'
DEX_SHA='ac9ae2cc6498ad362afa74adfce374e1287c1005b7b28f39e90352cd7476f006'
CODE_SHA='9935c497d9c0f5d25fb394c84883251d38c67cfaffca09d162fb06f2cf4eac24'
CLASS='Lcom/android/systemui/shade/ui/composable/ShadeSceneKt$$ExternalSyntheticLambda20;'
PADDING='Landroidx/compose/foundation/layout/PaddingKt;'
METHOD='padding-qDBjuR0$default'
def sha(data):return hashlib.sha256(data).hexdigest()
def need(condition,message):
 if not condition:raise ValueError(message)
def patch(data):
 need(sha(data)==DEX_SHA,'Exact original DEX hash required')
 need(data[:8]==b'dex\n039\0','Wrong DEX version')
 u=lambda o:struct.unpack_from('<I',data,o)[0]
 need((u(32),u(36))==(len(data),112),'Wrong DEX header')
 need(data[12:32]==hashlib.sha1(data[32:]).digest(),'Wrong DEX signature')
 need(u(8)==zlib.adler32(data[12:])&0xffffffff,'Wrong DEX checksum')
 def leb(o):
  r=0
  for shift in range(0,35,7):
   value=data[o];o+=1;r|=(value&127)<<shift
   if not value&128:return r,o
  raise ValueError('Invalid ULEB128')
 strings=[]
 for i in range(u(56)):
  o=leb(u(u(60)+i*4))[1];strings.append(data[o:data.index(0,o)].decode('utf8',errors='replace'))
 types=[strings[u(u(68)+i*4)] for i in range(u(64))]
 def proto(index):
  _,ret,params=struct.unpack_from('<III',data,u(76)+index*12)
  args=[types[struct.unpack_from('<H',data,params+4+k*2)[0]] for k in range(u(params))] if params else []
  return types[ret],args
 methods=[struct.unpack_from('<HHI',data,u(92)+i*8) for i in range(u(88))]
 matches=[(i,c) for i,(c,p,n) in enumerate(methods) if types[c]==CLASS and strings[n]=='invoke' and proto(p)==('Ljava/lang/Object;',['Ljava/lang/Object;','Ljava/lang/Object;'])]
 need(len(matches)==1,'Target descriptor not unique')
 method_id,class_id=matches[0];need(method_id==33442,'Wrong method ID')
 offsets=[u(u(100)+i*32+24) for i in range(u(96)) if u(u(100)+i*32)==class_id]
 need(len(offsets)==1 and offsets[0]!=0,'Wrong class definition');o=offsets[0];counts=[]
 for _ in range(4):v,o=leb(o);counts.append(v)
 for _ in range(counts[0]+counts[1]):_,o=leb(o);_,o=leb(o)
 code=[]
 for count in counts[2:]:
  index=0
  for _ in range(count):
   delta,o=leb(o);index+=delta;_,o=leb(o);offset,o=leb(o)
   if index==method_id:code.append(offset)
 need(code==[4742116],'Wrong code item offset')
 offset=code[0];header=struct.unpack_from('<HHHHII',data,offset)
 need(header==(25,3,7,0,0,275),'Wrong method register/control-flow header')
 start=offset+16;instructions=data[start:start+550]
 need(sha(instructions)==CODE_SHA,'Wrong method instructions')
 # Mask,start/top/end/default-object constants and call layout are exact.
 need(instructions[376:396]==bytes.fromhex('1314070013150000131000001311000013120000'),'Wrong argument setup')
 need(instructions[396:402]==bytes.fromhex('7707f2170f00'),'Wrong padding invoke')
 c,p,n=methods[0x17f2]
 need(types[c]==PADDING and strings[n]==METHOD and proto(p)==('Landroidx/compose/ui/Modifier;',['Landroidx/compose/ui/Modifier;','F','F','F','F','I','Ljava/lang/Object;']),'Wrong padding overload')
 result=bytearray(data)
 result[start+376:start+380]=bytes.fromhex('13140500')
 result[start+388:start+392]=bytes.fromhex('15110041')
 result[12:32]=hashlib.sha1(result[32:]).digest()
 struct.pack_into('<I',result,8,zlib.adler32(result[12:])&0xffffffff)
 changed=[i for i,(a,b) in enumerate(zip(data,result)) if a!=b]
 need(len(result)==len(data),'DEX size changed')
 actual=[i for i in changed if not 8<=i<32]
 need(actual==[start+378,start+388,start+391],'Unexpected non-header changes')
 need(result[12:32]==hashlib.sha1(result[32:]).digest(),'Patched signature invalid')
 need(struct.unpack_from('<I',result,8)[0]==zlib.adler32(result[12:])&0xffffffff,'Patched checksum invalid')
 return bytes(result),{'original_dex_sha256':DEX_SHA,'patched_dex_sha256':sha(result),
   'class':CLASS,'method':'invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;',
   'code_item_offset':offset,'code_units':275,'registers':25,'tries':0,
   'instruction_changes':[{'method_byte_offset':376,'old_hex':'13140700','new_hex':'13140500','effect':'default mask7→5; only top-default bit cleared'},
                          {'method_byte_offset':388,'old_hex':'13110000','new_hex':'15110041','effect':'v17(top) 0f→8f'}],
   'changed_byte_offsets':changed,'non_header_changed_bytes':actual,
   'all_other_dex_bytes_unchanged':True,'expanded_qs_code_unchanged':True,
   'top_dp':8,'bottom_dp_unchanged':16,'expected_added_height_px_at_260dpi':13,
   'status':'OFFLINE DEX ONLY; no APK signing, packaging, SYSTEM or device operations'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 need(a.apk.is_file() and not a.apk.is_symlink() and sha(a.apk.read_bytes())==APK_SHA,'Exact original SystemUI APK required')
 need(not a.output.exists() and not a.output.is_symlink() and a.output.parent.is_dir(),'Output exists or invalid')
 with zipfile.ZipFile(a.apk) as z:
  need(z.namelist().count('classes2.dex')==1 and z.testzip() is None,'Invalid APK ZIP')
  old=z.read('classes2.dex')
 new,report=patch(old);a.output.mkdir(mode=0o700)
 (a.output/'classes2.dex').write_bytes(new);(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
