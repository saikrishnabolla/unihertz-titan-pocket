from PIL import Image,ImageChops,ImageDraw
import zipfile,io,json,argparse
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();p=args.output.resolve();p.mkdir(parents=True,exist_ok=True);z=zipfile.ZipFile(args.source);out=[]
for n in z.namelist():
 if not n.endswith('.png'):continue
 im=Image.open(io.BytesIO(z.read(n))).convert('RGB');diff=ImageChops.difference(im,Image.new('RGB',im.size,'black'));whole=diff.getbbox();upper=diff.crop((0,0,1080,1900)).getbbox()
 # Project visible pixels onto rows, retaining disjoint row bands for separating the footer.
 rowbands=[];start=None
 for y in range(2340):
  active=diff.crop((0,y,1080,y+1)).getbbox() is not None
  if active and start is None:start=y
  if not active and start is not None:rowbands.append([start,y]);start=None
 if start is not None:rowbands.append([start,2340])
 out.append({'frame':n,'whole':whole,'upper1900':upper,'rowbands':rowbands})
(p/'all-original-bounds.json').write_text(json.dumps(out,indent=2))
print('upper_union',min(v['upper1900'][0] for v in out if v['upper1900']),min(v['upper1900'][1] for v in out if v['upper1900']),max(v['upper1900'][2] for v in out if v['upper1900']),max(v['upper1900'][3] for v in out if v['upper1900']))
for v in out:
 if v['frame'] in ('part1/frame_00070.png','part1/frame_00100.png','part1/frame_00138.png','part1/frame_00200.png','part1/frame_00274.png'):print(v)
