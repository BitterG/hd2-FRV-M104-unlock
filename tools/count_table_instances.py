"""How many LDLD instances does a real settings file contain?

This matters because the addon's gate currently says "one record per table copy",
which silently assumes the file is ONE instance.  If a settings file is compiled as
several LDLD instances, that gate would refuse a perfectly good table.
"""
import gzip
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MIRROR = REPO / 'filediver' / 'datalibrary'


def load(name):
    path = MIRROR / (name + '.gz')
    if path.exists():
        return gzip.decompress(path.read_bytes())
    return (MIRROR / name).read_bytes()


def instances(data):
    """Every well-formed LDLD instance.

    The header is `LDLD <u32 version> <u32 type_hash> <u32 size> <u8 is64> <pad7>`,
    so the type hash sits at magic+8 - NOT at magic-4.  A first version of this
    script read magic-4 and produced hundreds of phantom "instances" out of payload
    bytes that merely happened to contain 'LDLD'.
    """
    out = []
    start = 0
    while True:
        at = data.find(b'LDLD', start)
        if at < 0:
            break
        start = at + 4
        if at + 24 > len(data):
            continue
        version = struct.unpack_from('<I', data, at + 4)[0]
        type_hash = struct.unpack_from('<I', data, at + 8)[0]
        size = struct.unpack_from('<I', data, at + 12)[0]
        payload = at + 24
        if version != 1 or size <= 0 or payload + size > len(data):
            continue
        if type_hash == 0:
            continue
        off = struct.unpack_from('<Q', data, payload)[0]
        count = struct.unpack_from('<Q', data, payload + 8)[0]
        # a real settings instance keeps its records inside its own payload, and
        # the descriptor offset is the small constant 16 in the file image
        if off != 16 or payload + off + count > payload + size:
            continue
        out.append({'magic': at, 'type_hash': type_hash, 'size': size,
                    'records_offset': off, 'count': count,
                    'records_at': payload + off})
    return out


def main():
    names = sorted(p.name[:-3] for p in MIRROR.glob('generated_*_settings.dl_bin.gz'))
    for name in names:
        data = load(name)
        found = instances(data)
        total = sum(item['count'] for item in found)
        strides = set()
        for item in found:
            if item['count']:
                remain = item['size'] - 16
                strides.add(remain // item['count'] if remain % item['count'] == 0
                            else 'indivisible')
        print('%-52s instances=%-3d records=%-5d strides=%s'
              % (name, len(found), total, sorted(map(str, strides))[:4]))
        if len(found) > 1:
            for item in found:
                print('      magic@%-7d type=%#010x size=%-7d count=%d'
                      % (item['magic'], item['type_hash'], item['size'],
                         item['count']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
