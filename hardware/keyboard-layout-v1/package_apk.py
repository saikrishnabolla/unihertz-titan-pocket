from pathlib import Path
import zipfile
p=Path(__file__).parent
with zipfile.ZipFile(p/'resources.apk') as source,zipfile.ZipFile(p/'unsigned.apk','w') as target:
    for entry in source.infolist():
        target.writestr(entry,source.read(entry))
    target.writestr('classes.dex',(p/'classes.dex').read_bytes(),compress_type=zipfile.ZIP_STORED)
