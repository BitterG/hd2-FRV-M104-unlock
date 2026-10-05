"""Guard the addon's inlined constants against data drift.

The addon ships literals (resource hashes, the LDLD type tag, the entity-blob
header signature) rather than deriving them at runtime, because the runtime has no
way to hash a resource name.  That makes them a build dependency: if the game
updates and the plaintext mirror is refreshed, a stale literal would make the
addon look for something that no longer exists - and it would fail silently, in
the field, with only "nothing found" in the log.

So every literal is recomputed here from the mirror and compared with the source
text.  A refresh of `filediver/datalibrary/` therefore turns this test red before
it can turn into a support ticket.

    python tests/verify_constants.py
"""
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO.parent / 'tools'))

from dlbin import entities                        # noqa: E402
from dlmember import dl_hash                      # noqa: E402
from hd2patch import resource_hash                # noqa: E402

SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_recon.lua'

EXPECTED_IDS = {
    'frv_base': ('content/fac_helldivers/vehicles/frv/frv', 0xcc21c7ffd3ebefb9),
    'frv_supply': ('content/fac_helldivers/vehicles/frv_supply/frv_supply',
                   0x9b2140378640432e),
    'frv_heavy': ('content/fac_helldivers/vehicles/frv_heavy/frv_flamer',
                  0x2d85bfe3d8717fe5),
    'delivery': (None, 0x75be82ed8592a6b3),
}

FAILED = []


def check(label, ok, detail=''):
    print('%s  %s%s' % ('PASS' if ok else 'FAIL', label,
                        '' if ok else '  <- ' + str(detail)))
    if not ok:
        FAILED.append(label)


def little_endian_hex(value):
    return struct.pack('<Q', value).hex()


def main():
    text = SOURCE.read_text(encoding='utf-8')

    print('== typed in the source vs recomputed from the mirror ==')
    for label, (path, value) in EXPECTED_IDS.items():
        if path:
            recomputed = resource_hash(path)
            check('MurmurHash64A(%s) == %#018x' % (path, value),
                  recomputed == value, '%#018x' % recomputed)
        expected_hex = little_endian_hex(value)
        pattern = re.compile(r"label = '%s',\s*hex = '([0-9a-f]{16})'" % label)
        found = pattern.search(text)
        check("addon's %s literal is %s" % (label, expected_hex),
              found is not None and found.group(1) == expected_hex,
              found.group(1) if found else 'not found in source')

    tag = dl_hash('StratagemSettings')
    found = re.search(r'Recon\.STRATAGEM_TYPE = (0x[0-9a-f]+)', text)
    check('djb2(StratagemSettings) == %#010x' % tag,
          found is not None and int(found.group(1), 16) == tag,
          found.group(1) if found else 'not found')

    blob = entities()
    signature = bytes(blob[:20]).hex()
    found = re.search(r"Recon\.BLOB_SIGNATURE = '([0-9a-f]+)'", text)
    check('entity blob signature is %s' % signature,
          found is not None and found.group(1) == signature,
          found.group(1) if found else 'not found')
    check('the signature is unique inside the blob',
          blob.count(bytes(blob[:20])) == 1)

    print('\n== the heavy FRV really is a distinct unit in the mirror ==')
    heavy = resource_hash('content/fac_helldivers/vehicles/frv_heavy/frv_flamer')
    hits = 0
    start = 0
    needle = struct.pack('<Q', heavy)
    while True:
        at = blob.find(needle, start)
        if at < 0:
            break
        hits += 1
        start = at + 1
    check('frv_heavy appears in the entity blob', hits > 0, '%d hits' % hits)
    check('frv_supply and frv_heavy are different units', heavy != EXPECTED_IDS['frv_supply'][1])

    print('\n%d failure(s)' % len(FAILED))
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
