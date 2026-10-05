"""Print game vs mirror sizes for generated_*.dl_bin (no fancy formatting)."""
import collections
import math
import sys
from pathlib import Path

GAME = Path(r'E:\SteamLibrary\steamapps\common\Helldivers 2\data\game')
MIRROR = Path(__file__).resolve().parent.parent / 'filediver' / 'datalibrary'


def entropy(b):
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    rows = []
    for gp in sorted(GAME.glob('generated_*.dl_bin')):
        gb = gp.read_bytes()
        mp = MIRROR / gp.name
        gsize = len(gb)
        ldld = gb.count(b'LDLD')
        ent = entropy(gb[:1 << 20])
        if mp.exists():
            msize = mp.stat().st_size
            diff = gsize - msize
        else:
            msize = None
            diff = None
        rows.append((gp.name, gsize, msize, diff, ldld, ent))

    print('%-52s %10s %10s %8s %6s %8s' % ('file', 'game', 'mirror', 'diff', 'LDLD', 'entropy'))
    for name, gsize, msize, diff, ldld, ent in rows:
        print('%-52s %10d %10s %8s %6d %8.4f'
              % (name, gsize, msize if msize else '--',
                 diff if diff is not None else '--', ldld, ent))
    return 0


if __name__ == '__main__':
    sys.exit(main())
