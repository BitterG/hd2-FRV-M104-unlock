"""Sanity-check the payload convention against the one vehicle stratagem we can
read offline.

Community snapshot (2024-09-17) gives the Exosuit stratagems:
    StratagemType_DropoffCombatWalker             payload[0] = 0x79e4b3d2da5e45e3
    StratagemType_DropoffCombatWalker_Autocannon  payload[0] = 0xc2d449ecf7facab1
    both                                          payload[1] = 0x75be82ed8592a6b3

If those payload[0] values are unit resources living in the entity blob's
component index tables, then `payload[0]` really is "the unit to spawn" and the
M-102 record's payload[0] will be the base FRV hash - which is what the runtime
patcher will look for.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dlbin import entities                       # noqa: E402
from hd2patch import resource_hash               # noqa: E402

CANDIDATES = {
    'walker': 0x79e4b3d2da5e45e3,
    'walker_obsidian': 0xc2d449ecf7facab1,
    'delivery': 0x75be82ed8592a6b3,
    'frv_base': 0xcc21c7ffd3ebefb9,
    'frv_heavy': 0x2d85bfe3d8717fe5,
}


def name_db():
    table = {}
    for line in (REPO / 'work/files.txt').read_text(encoding='utf-8', errors='replace').splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith('//'):
            continue
        table.setdefault(resource_hash(line), line)
    return table


def main():
    db = name_db()
    blob = bytes(entities())

    entries = {}   # key -> list of (type_hash, blob_offset, record_index)
    start = 0
    while True:
        at = blob.find(b'LDLD', start)
        if at < 0:
            break
        start = at + 4
        if at < 4:
            continue
        type_hash = struct.unpack_from('<I', blob, at - 4)[0]
        size = struct.unpack_from('<I', blob, at + 12)[0]
        payload = at + 24
        if size <= 0 or payload + size > len(blob):
            continue
        for slot in range(0, min(size, 8192) - 16 + 1, 16):
            key = struct.unpack_from('<Q', blob, payload + slot)[0]
            if key in CANDIDATES.values():
                entries.setdefault(key, []).append((type_hash, payload + slot,
                                                    struct.unpack_from('<I', blob, payload + slot + 8)[0]))

    for label, key in CANDIDATES.items():
        rows = entries.get(key, [])
        print('%-16s %#018x  name=%-58s  component tables=%d'
              % (label, key, (db.get(key) or '(unknown)')[:58], len(rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
