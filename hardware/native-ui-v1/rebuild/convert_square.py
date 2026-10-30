from pathlib import Path,PurePosixPath
from PIL import Image,ImageOps,ImageDraw,ImageChops
import zipfile,io,hashlib,json,argparse
parser=argparse.ArgumentParser(description='Convert the pinned original animation to the reviewed square format.')
parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
source=args.source.resolve();ROOT=args.output.resolve();assert source.is_file() and not args.output.is_symlink()
ROOT.mkdir(parents=True,exist_ok=True);dest=ROOT/'bootanimation-titan-square-v1.zip';assert source!=dest and not dest.exists()
assert hashlib.sha256(source.read_bytes()).hexdigest()=='97d77f7d8ce57b8d47102d541938e60113c0a489628fd8a1308def33a1e4b8a6'
with zipfile.ZipFile(source) as z:
 names=z.namelist();assert len(names)==len(set(names));assert z.testzip() is None
 assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names)
 desc=z.read('desc.txt').decode();assert desc=='1080 2340 60\nc 1 90 part0\nc 1 0 part1\np 240 0 part2\np 0 0 part3\n'
 converted={};samples=[];bounds=[]
 for n in names:
  if n=='desc.txt':converted[n]=desc.replace('1080 2340 60','720 720 60',1).encode();continue
  if n.endswith('/'):
   converted[n]=b'';continue
  assert n.endswith('.png') and n.split('/')[0] in ('part0','part1','part2','part3')
  im=Image.open(io.BytesIO(z.read(n)));im.load();assert im.size==(1080,2340)
  rgb=im.convert('RGB');cropped=rgb.crop((-60,570,1140,1770));diff=ImageChops.difference(cropped,Image.new('RGB',cropped.size,'black'));box=diff.getbbox()
  # A black band at every crop edge proves no visible component crosses a crop boundary.
  assert box is None or (box[0]>0 and box[1]>0 and box[2]<1200 and box[3]<1200),(n,box)
  bounds.append({'frame':n,'central_bounds':list(box) if box else None,'outside_top_bounds':ImageChops.difference(rgb.crop((0,0,1080,570)),Image.new('RGB',(1080,570),'black')).getbbox(),'outside_bottom_bounds':ImageChops.difference(rgb.crop((0,1770,1080,2340)),Image.new('RGB',(1080,570),'black')).getbbox()})
  canvas=cropped.resize((720,720),resample=Image.Resampling.LANCZOS)
  buf=io.BytesIO();canvas.save(buf,format='PNG',optimize=False,compress_level=9);converted[n]=buf.getvalue()
  if n in ('part0/frame_00000.png','part1/frame_00074.png','part1/frame_00274.png','part3/frame_00320.png'):samples.append((n,canvas.copy()))
 with zipfile.ZipFile(dest,'x',compression=zipfile.ZIP_STORED) as out:
  for n,data in converted.items():
   info=zipfile.ZipInfo(n,date_time=(2009,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED;info.external_attr=(0o40755 if n.endswith('/') else 0o100644)<<16;out.writestr(info,data)
assert hashlib.sha256(dest.read_bytes()).hexdigest()=='b370920629c6a751a5a67e8f7e09e37824c5e02bf818eeca480f9bb54d969714','Conversion differs from reviewed exact output'
with zipfile.ZipFile(dest) as z:
 assert z.testzip() is None;assert z.namelist()==names
 assert all(i.compress_type==zipfile.ZIP_STORED for i in z.infolist())
 frames=[n for n in names if n.endswith('.png')]
 for n in frames:
  im=Image.open(io.BytesIO(z.read(n)));im.load();assert im.size==(720,720)
 lines=z.read('desc.txt').decode().splitlines();parts=[line.split()[3] for line in lines[1:]];assert all(any(n.startswith(part+'/') for n in frames) for part in parts)
sheet=Image.new('RGB',(720,400),'#292929');draw=ImageDraw.Draw(sheet)
for idx,(name,im) in enumerate(samples):
 thumb=im.resize((180,180));x=(idx%4)*180;sheet.paste(thumb,(x,10));draw.text((x+3,200),name.split('/')[0],fill='white');draw.text((x+3,218),name.split('/')[-1],fill='white')
draw.text((10,260),'720x720 central square; logo enlarged without new artwork',fill='white');draw.text((10,280),'Portrait footer outside central square is omitted.',fill='white');sheet.save(ROOT/'contact-sheet.png')
report={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'candidate_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'candidate_bytes':dest.stat().st_size,'frames':len(frames),'entries':len(names),'source_dimensions':[1080,2340],'output_dimensions':[720,720],'crop_rectangle':[-60,570,1140,1770],'minimum_clear_edge_pixels':min(min(v['central_bounds'][0],v['central_bounds'][1],1200-v['central_bounds'][2],1200-v['central_bounds'][3]) for v in bounds if v['central_bounds']),'frames_with_excluded_top_content':sum(v['outside_top_bounds'] is not None for v in bounds),'frames_with_excluded_bottom_content':sum(v['outside_bottom_bounds'] is not None for v in bounds),'fps':60,'parts':lines[1:],'crc_pass':True,'all_frames_decoded':True,'stored_only':True,'no_traversal':True,'part_references_pass':True,'conversion':'centered1200x1200 crop at y570 with60pxblack horizontal padding, resized720x720 LANCZOS RGB PNG; no repainting','pillow_version':Image.__version__}
(ROOT/'frame-bounds.json').write_text(json.dumps(bounds,indent=2));(ROOT/'conversion-report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
