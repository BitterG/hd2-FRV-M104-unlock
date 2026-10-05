"""Guard the assumptions the patcher makes about settings tables, on real data.

The patcher's whole strategy is "a settings table is a LDLD instance whose payload
starts with a 16-byte DLArray descriptor, then `count` records of a fixed stride".
That is an assumption about the game's data compiler, and this file checks it
against the plaintext mirror instead of against my memory of it.

It also pins the finding that made the first version of the gate wrong: a settings
file can compile as SEVERAL same-type LDLD instances.

    python tests/verify_table_layout.py
"""
import gzip
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MIRROR = REPO.parent / 'filediver' / 'datalibrary'
sys.path.insert(0, str(REPO.parent / 'tools'))
from dlmember import dl_hash  # noqa: E402

FAILURES = []
CHECKS_RUN = 0


def check(label, condition, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    if condition:
        print('  PASS  %s' % label)
    else:
        print('  FAIL  %s  <- %s' % (label, detail))
        FAILURES.append(label)


def load(name):
    gz = MIRROR / (name + '.gz')
    if gz.exists():
        return gzip.decompress(gz.read_bytes())
    return (MIRROR / name).read_bytes()


def instances(data):
    """Every well-formed LDLD instance: magic at +0, type hash at +8."""
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
        if version != 1 or type_hash == 0 or size <= 0 or payload + size > len(data):
            continue
        offset = struct.unpack_from('<Q', data, payload)[0]
        count = struct.unpack_from('<Q', data, payload + 8)[0]
        if offset != 16 or payload + offset + count > payload + size:
            continue
        out.append({'magic': at, 'type_hash': type_hash, 'size': size,
                    'count': count, 'records_at': payload + offset})
    return out


def describe(name, stride=None):
    data = load(name)
    found = instances(data)
    check('%s: exactly one LDLD instance' % name, len(found) == 1, len(found))
    if not found:
        return None
    item = found[0]
    check('%s: version 1 and the descriptor is the relative offset 16' % name,
          item['records_at'] - item['magic'] - 24 == 16)
    if stride:
        check('%s: size == 16 + %d * %d' % (name, item['count'], stride),
              item['size'] == 16 + item['count'] * stride, item['size'])
        check('%s: the file is exactly header + records' % name,
              len(data) - item['records_at'] == item['count'] * stride,
              len(data) - item['records_at'])
    return item


def main():
    print('== the table shape the patcher relies on (real data) ==')
    describe('generated_projectile_settings.dl_bin', 272)
    describe('generated_arc_settings.dl_bin', 104)
    describe('generated_beam_settings.dl_bin', 112)
    describe('generated_damage_settings.dl_bin', 76)

    print('\n== a build whose stride does NOT divide evenly must be refused ==')
    explosion = describe('generated_explosion_settings.dl_bin')
    if explosion:
        remain = explosion['size'] - 16
        check('explosion settings: (size-16) does not divide by count '
              '(so the patcher will not guess a stride)',
              remain % explosion['count'] != 0,
              '%d %% %d == 0' % (remain, explosion['count']))

    print('\n== a settings file can be SEVERAL same-type LDLD instances ==')
    overrides = instances(load('generated_planet_override_settings.dl_bin'))
    types = {item['type_hash'] for item in overrides}
    check('planet_override has more than one instance', len(overrides) > 1,
          len(overrides))
    check('... and they all share one type tag', len(types) == 1, types)
    check('... and the tag is the planet-override table',
          types == {dl_hash('PlanetOverrideSettings')}, types)

    customization = instances(load('generated_weapon_customization_settings.dl_bin'))
    ctypes = {item['type_hash'] for item in customization}
    check('weapon_customization is also split into several instances',
          len(customization) > 1 and len(ctypes) == 1,
          '%d instances, %d types' % (len(customization), len(ctypes)))

    print('\n== the patcher\'s own constants ==')
    check('STRATAGEM_TYPE == djb2("StratagemSettings")',
          int(__import__('re').search(
              r'STRATAGEM_TYPE = (0x[0-9a-f]+)',
              (REPO / 'Source/mods/dsh/frv_m104.lua').read_text(encoding='utf-8')
          ).group(1), 16) == dl_hash('StratagemSettings'))

    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
