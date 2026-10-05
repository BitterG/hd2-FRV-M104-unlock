"""Verify the FRV identity constants and derive the runtime anchors.

Everything the runtime patcher needs to recognise things is computed here, from
the plaintext mirror, so the addon ships literals rather than guesses:

  * the three FRV unit resource hashes (recomputed by MurmurHash64A),
  * what the shared vehicle "delivery" payload entry (0x75be82ed8592a6b3) is,
  * the entity-blob header signature (first 20 bytes) used to anchor into memory,
  * the blob-relative offset of every component-table hashmap entry for the base
    FRV, for the fallback lever (remap the base FRV onto the heavy records).
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dlbin import entities                       # noqa: E402
from dlmember import dl_hash                     # noqa: E402
from hd2patch import resource_hash               # noqa: E402

NAMES = {
    'base': 'content/fac_helldivers/vehicles/frv/frv',
    'supply': 'content/fac_helldivers/vehicles/frv_supply/frv_supply',
    'heavy': 'content/fac_helldivers/vehicles/frv_heavy/frv_flamer',
}
DELIVERY = 0x75be82ed8592a6b3


def name_db():
    """resource-name hash -> name, from the workspace name list."""
    table = {}
    path = REPO / 'work/files.txt'
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith('//'):
            continue
        table.setdefault(resource_hash(line), line)
    return table


def main():
    print('== FRV resource hashes ==')
    for label, name in NAMES.items():
        h = resource_hash(name)
        print('  %-7s %#018x  lo32=%#010x  %s' % (label, h, h & 0xFFFFFFFF, name))

    db = name_db()
    print('\n== what is the shared vehicle payload entry? ==')
    print('  %#018x -> %s' % (DELIVERY, db.get(DELIVERY, '(no name in files.txt)')))
    print('  (%d names in work/files.txt)' % len(db))

    blob = bytes(entities())
    print('\n== entity blob ==')
    print('  size      = %d' % len(blob))
    print('  signature = %s' % blob[:20].hex())
    print('  sig count = %d' % blob.count(blob[:20]))

    print('\n== component index entries for the base FRV (fallback lever targets) ==')
    start = 0
    rows = []
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
            if key == resource_hash(NAMES['base']):
                idx = struct.unpack_from('<I', blob, payload + slot + 8)[0]
                rows.append((type_hash, payload + slot, idx))
    for type_hash, off, idx in rows:
        print('  type %#010x  entry_blob_offset=%#010x  record_index=%d'
              % (type_hash, off, idx))
    print('  %d entries' % len(rows))

    out = HERE.parent / 'work'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'blob_signature.hex').write_text(blob[:20].hex())
    print('\nwrote', out / 'blob_signature.hex')
    return 0


if __name__ == '__main__':
    sys.exit(main())
