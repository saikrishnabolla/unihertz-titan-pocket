import copy,hashlib,struct,zipfile

def require(condition,message):
    if not condition: raise ValueError(message)

def sha(data): return hashlib.sha256(data).hexdigest()

def payload_offset(apex, entry):
    with apex.open('rb') as stream:
        stream.seek(entry.header_offset)
        local = stream.read(30)
    require(local[:4] == b'PK\x03\x04', 'bad ZIP local header')
    name_size, extra_size = struct.unpack_from('<HH', local, 26)
    return entry.header_offset + 30 + name_size + extra_size


def verify_zip(source, output, payload, pubkey):
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output) as new:
        names = old.namelist()
        require(len(set(names)) == len(names), 'duplicate ZIP entry')
        require(new.namelist() == names, 'ZIP entry inventory or order changed')
        require(new.testzip() is None, 'ZIP CRC failure')
        inventory = []
        for name in names:
            wanted = {'apex_payload.img': payload, 'apex_pubkey': pubkey}.get(name)
            if wanted is None:
                wanted = old.read(name)
            actual = new.read(name)
            require(actual == wanted, f'ZIP entry changed: {name}')
            inventory.append(dict(name=name, size=len(actual), sha256=sha(actual)))
        entry = new.getinfo('apex_payload.img')
        offset = payload_offset(output, entry)
        require(entry.compress_type == zipfile.ZIP_STORED and offset % 4096 == 0,
                'payload must be STORED and 4096 aligned')
        return dict(payload_offset=offset, entries=inventory)


def rebuild_zip(source, output, payload, pubkey):
    require(source.resolve() != output.resolve(), 'refuse overwrite source')
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output, 'w') as new:
        new.comment = old.comment
        for entry in old.infolist():
            info = copy.copy(entry)
            data = {'apex_payload.img': payload, 'apex_pubkey': pubkey}.get(entry.filename)
            if data is None:
                data = old.read(entry)
            if entry.filename == 'apex_payload.img':
                require(info.compress_type == zipfile.ZIP_STORED, 'compressed source payload')
                base = new.fp.tell() + 30 + len(info.filename.encode())
                length = (-base) % 4096
                if 0 < length < 4:
                    length += 4096
                info.extra = struct.pack('<HH', 0xcafe, length - 4) + b'\0' * (length - 4) if length else b''
            new.writestr(info, data)
    verify_zip(source, output, payload, pubkey)

