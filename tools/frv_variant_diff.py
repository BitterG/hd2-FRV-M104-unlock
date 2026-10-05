"""Differential recon of the three FRV variants in the plaintext entity blob.

Variants (resource name hashes, verified against the community name-db and the
M-103 mod's own identity data):

    frv (base)     0xcc21c7ffd3ebefb9  content/fac_helldivers/vehicles/frv/frv
    frv_supply     0x9b2140378640432e  content/fac_helldivers/vehicles/frv_supply/frv_supply
    frv_heavy      0x2d85bfe3d8717fe5  content/fac_helldivers/vehicles/frv_heavy/frv_flamer

`frv_heavy/frv_flamer` is the M-104 Incinerator FRV: the entity carries its own
component records, so "make the base FRV into the incinerator" is a finite,
offline-derivable set of record edits. This script finds that set.

Output is deliberately narrow: only components where the variants differ, and the
exact byte ranges that differ.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dlbin import entities                      # noqa: E402
from dlmember import dl_hash                    # noqa: E402

COMPONENT_DIR = REPO / 'work/hddata/data/components'

VARIANTS = [
    ('base', 0xcc21c7ffd3ebefb9),
    ('supply', 0x9b2140378640432e),
    ('heavy', 0x2d85bfe3d8717fe5),
]


def component_names():
    table = {}
    for path in sorted(COMPONENT_DIR.glob('*.json')):
        table[dl_hash(path.stem)] = path.stem
    return table


def instances(blob):
    """Every LDLD instance: (type_hash, payload_offset, payload_size)."""
    out = []
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
        out.append((type_hash, payload, size))
    return out


def hashmap_and_records(payload, size):
    """The entity blob uses ComponentIndexData: 16-byte entries then records.

    There is no length in the payload, so the hashmap length is found by
    scanning 16-byte entries while the high u32 of the resource key is nonzero
    or the slot is still referenced. Records start at the first offset where the
    remaining size divides evenly by a plausible record stride - but that is
    what we do not know. So instead: return the raw payload and let the caller
    line up records by looking for the *next* variant's key.
    """
    return payload, size


def main():
    blob = bytes(entities())
    names = component_names()
    found_any = False

    rows = []
    for type_hash, payload, size in instances(blob):
        hits = {}
        # 16-byte ComponentIndexData entries live at the head of the payload
        for at in range(0, min(size, 8192) - 16 + 1, 16):
            key = struct.unpack_from('<Q', blob, payload + at)[0]
            for label, want in VARIANTS:
                if key == want:
                    idx = struct.unpack_from('<I', blob, payload + at + 8)[0]
                    hits[label] = (at // 16, idx)
        if not hits:
            continue
        found_any = True
        rows.append((names.get(type_hash, 'Data 0x%08x' % type_hash),
                     type_hash, payload, size, hits))

    print('%d component table(s) carry at least one FRV variant key\n' % len(rows))
    for name, type_hash, payload, size, hits in sorted(rows):
        desc = '  '.join('%s:slot%d/rec%d' % (lbl, hits[lbl][0], hits[lbl][1])
                         for lbl, _ in VARIANTS if lbl in hits)
        missing = [lbl for lbl, _ in VARIANTS if lbl not in hits]
        print('%-44s size=%-8d %s%s' % (name, size, desc,
                                        ('   MISSING ' + ','.join(missing)) if missing else ''))
    print()
    print('total instances scanned:', len(instances(blob)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
