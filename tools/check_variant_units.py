"""Does the shipped entity data actually contain the M-103 / M-104 units?

The community name lists cannot answer this - they are a hash dictionary, not a
manifest, and they simply predate the FRV variants.  The entity blob can: it is the
game's own entity definition data, and `verify_identity.py` already finds the BASE
FRV (`content/fac_helldivers/vehicles/frv/frv`) as a component-index key inside it.
So the same search is run for the other two unit names.  If the base is there and
the variants are not, the variants' content is not in this build and no payload swap
can ever spawn them - which would settle the question far more cheaply than another
in-game crash.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dlbin import entities          # noqa: E402
from hd2patch import resource_hash  # noqa: E402

NAMES = {
    'base (M-102)': 'content/fac_helldivers/vehicles/frv/frv',
    'supply (M-103)': 'content/fac_helldivers/vehicles/frv_supply/frv_supply',
    'heavy (M-104)': 'content/fac_helldivers/vehicles/frv_heavy/frv_flamer',
    'combat_walker (control)': 'content/fac_helldivers/vehicles/combat_walker/combat_walker',
    'lav (control)': 'content/fac_helldivers/vehicles/lav/lav',
}


def main() -> int:
    blob = bytes(entities())
    print('entity blob: %d bytes' % len(blob))
    for label, name in NAMES.items():
        h = resource_hash(name)
        pat = struct.pack('<Q', h)
        raw = blob.count(pat)
        print('  %-24s %#018x  %-8s raw_u64_occurrences=%d'
              % (label, h, name.rsplit('/', 1)[-1], raw))

    # the component index is a u64 key -> value map; report whether the key is a
    # key (i.e. appears at the start of a 16-byte slot) rather than merely present
    print('\nas a component-index KEY (16-byte aligned slot start):')
    for label, name in NAMES.items():
        h = resource_hash(name)
        pat = struct.pack('<Q', h)
        keys = 0
        start = 0
        while True:
            at = blob.find(pat, start)
            if at < 0:
                break
            if at % 16 == 0:
                keys += 1
            start = at + 1
        print('  %-24s %-8s aligned_key_slots=%d' % (label, name.rsplit('/', 1)[-1], keys))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
