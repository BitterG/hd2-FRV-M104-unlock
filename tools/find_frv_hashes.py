"""Where do the FRV resource hashes appear across every offline table?

If the M-102 (base FRV) -> vehicle binding is stored as a resource hash anywhere
we can read offline, this finds it. The tables FileDiver's mirror covers are
searched in full; the ones only the game ships are reported as missing so the
runtime recon knows what to look for.
"""
import gzip
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
MIRROR = REPO / 'filediver' / 'datalibrary'
GAME = Path(r'E:\SteamLibrary\steamapps\common\Helldivers 2\data\game')

VARIANTS = {
    'frv_base': 0xcc21c7ffd3ebefb9,
    'frv_supply': 0x9b2140378640432e,
    'frv_heavy': 0x2d85bfe3d8717fe5,
}
# the second payload entry shared by the Exosuit stratagems (delivery entity)
DELIVERY = 0x75be82ed8592a6b3
MASK = (1 << 64) - 1


def load(path):
    raw = path.read_bytes()
    if raw[:2] == b'\x1f\x8b':
        return gzip.decompress(raw)
    return raw


def find_all(hay, needle):
    out = []
    start = 0
    while True:
        at = hay.find(needle, start)
        if at < 0:
            return out
        out.append(at)
        start = at + 1


def main():
    names = sorted({p.name for p in MIRROR.glob('*.dl_bin')} |
                   {p.name for p in GAME.glob('*.dl_bin')})
    gz_names = sorted({p.name[:-3] for p in MIRROR.glob('*.dl_bin.gz')})

    print('searching %d table names (%d available offline)\n' % (len(names), len(gz_names)))
    print('%-52s %10s  hits' % ('table', 'size'))
    for name in names:
        mp = MIRROR / name
        gp = MIRROR / (name + '.gz')
        if mp.exists():
            src, data = 'mirror', load(mp)
        elif gp.exists():
            src, data = 'mirror-gz', load(gp)
        else:
            print('%-52s %10s  (offline copy not available)' % (name, '-'))
            continue
        hits = []
        for label, value in list(VARIANTS.items()) + [('delivery', DELIVERY)]:
            for off in find_all(data, struct.pack('<Q', value)):
                hits.append('%s@%#x' % (label, off))
            # also the low 32 bits on their own (thin hash references)
            for off in find_all(data, struct.pack('<I', value & 0xFFFFFFFF)):
                hits.append('%s.lo32@%#x' % (label, off))
        print('%-52s %10d  %s' % (name, len(data), ' '.join(hits) if hits else '-'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
