"""Validate the LDLD settings-table layout against REAL game data.

The addon's whole identification strategy rests on one assumption: a settings table
(`generated_*_settings.dl_bin`) is

    <u32 len> LDLD <u32 version=1> <u32 type_hash> <u32 size> <u8 is64> <u8 pad7>
    then a 16-byte DLArray descriptor  = <u64 records_offset, u64 record_count>
    then the records

and in memory that first u64 is an absolute pointer instead of a relative offset
(skill 6.13).  `generated_stratagem_settings.dl_bin` cannot be read offline, but
`generated_projectile_settings.dl_bin` is the SAME table form and the plaintext
mirror has it - so the assumption can be checked against real bytes now, instead of
being discovered in the field.

    python tools/validate_table_layout.py
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


def u32(b, at):
    return struct.unpack_from('<I', b, at)[0]


def u64(b, at):
    return struct.unpack_from('<Q', b, at)[0]


def report(name, expected_stride=None):
    data = load(name)
    print('== %s : %d bytes' % (name, len(data)))
    magic = data.find(b'LDLD')
    if magic < 0:
        print('   no LDLD marker')
        return None
    length_prefix = u32(data, 0)
    version = u32(data, magic + 4)
    type_hash = u32(data, magic + 8)
    size = u32(data, magic + 12)
    is64 = data[magic + 16]
    print('   length_prefix=%d magic@%d version=%d type_hash=%#010x size=%d is64=%d'
          % (length_prefix, magic, version, type_hash, size, is64))
    print('   payload@%d (magic+24), descriptor=%s'
          % (magic + 24, data[magic + 24:magic + 40].hex()))
    records_offset = u64(data, magic + 24)
    count = u64(data, magic + 32)
    print('   descriptor: records_offset=%d count=%d' % (records_offset, count))
    records_at = magic + 24 + records_offset
    print('   records at %d (magic+24+offset)' % records_at)
    remaining = len(data) - records_at
    print('   bytes after records start = %d' % remaining)
    if count:
        stride = remaining / count
        print('   remaining / count = %s' % ('%d' % stride if stride == int(stride)
                                             else '%.3f' % stride))
        print('   (size - 16) / count = %s'
              % ('%d' % ((size - 16) / count) if (size - 16) % count == 0
                 else 'not integral'))
        print('   file length - records_at == count * stride ? %s'
              % (remaining == count * stride))
    if expected_stride is not None:
        print('   expected stride %d -> %s'
              % (expected_stride, 'MATCH' if count and remaining == count * expected_stride
                 else 'MISMATCH'))
    return {'data': data, 'magic': magic, 'version': version,
            'type_hash': type_hash, 'size': size, 'count': count,
            'records_offset': records_offset, 'records_at': records_at}


def main():
    ok = True
    proj = report('generated_projectile_settings.dl_bin', 272)
    if proj:
        checks = [
            ('version is 1', proj['version'] == 1),
            ('the descriptor holds a RELATIVE offset in the file',
             proj['records_offset'] == 16),
            ('records follow the descriptor',
             proj['records_at'] == proj['magic'] + 24 + 16),
            ('(size - 16) divides by count',
             (proj['size'] - 16) % proj['count'] == 0),
            ('the derived stride is 272',
             (proj['size'] - 16) // proj['count'] == 272),
            ('the file is exactly header + records',
             len(proj['data']) - proj['records_at'] == proj['count'] * 272),
        ]
        for label, good in checks:
            print('   %s  %s' % ('PASS' if good else 'FAIL', label))
            ok = ok and good
    print()
    for name, stride in (('generated_damage_settings.dl_bin', 76),
                         ('generated_explosion_settings.dl_bin', None),
                         ('generated_arc_settings.dl_bin', None)):
        try:
            report(name, stride)
        except FileNotFoundError:
            print('== %s : mirror copy not available' % name)
        print()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
