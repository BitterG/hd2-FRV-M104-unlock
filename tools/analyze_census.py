"""Read a live census and answer: is the stratagem table in memory, and under what tag?

The in-game run so far reports `stratagem_tables=0` with 872 LDLD blocks found, so
either the table is not resident yet (the scan was two thirds through its first
sweep) or the current build tags it with a different type hash than the mirror's
`StratagemSettings` (0x30eb6399).

The table's *size* is a second, tag-independent handle: the file on disk is 80328
bytes and a settings table's LDLD `size` field is file_size - 76, so ~80252.  A
block near that size with a big record count is the table whatever it is called.

    python tools/analyze_census.py [log-dir]
"""
import re
import sys
from collections import Counter
from pathlib import Path

LINE = re.compile(r'^ldld address=0x([0-9A-Fa-f]+) type=0x([0-9A-Fa-f]+) '
                  r'name=(\S+)\s+size=(\d+)')
STRATAGEM_TAG = 0x30eb6399
# the mirror typelib's known table tags, for orientation
KNOWN = {
    0x30eb6399: 'StratagemSettings',
    0x7bd60854: 'StratagemInfo',
    0xbd4042c2: 'ProjectileSettings',
    0xe0a72cf0: 'DamageSettings',
    0xeb1433da: 'ProjectileInfo?',
    0xafdf0267: 'ArcSettings',
    0x2aea2592: 'ExplosionSettings',
}


def main():
    log_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path.home() / 'AppData/Local/CowboyBingus/Helldivers2/Logs')
    path = log_dir / 'frv_m104_census.txt'
    if not path.exists():
        print('no census at %s' % path)
        return 1
    text = path.read_text(encoding='utf-8', errors='replace')

    blocks = []
    for line in text.splitlines():
        match = LINE.match(line)
        if match:
            blocks.append({'address': int(match.group(1), 16),
                           'type': int(match.group(2), 16),
                           'name': match.group(3),
                           'size': int(match.group(4))})
    print('%d LDLD blocks in the census' % len(blocks))
    if not blocks:
        return 1

    print('\n== is the stratagem table tag present? ==')
    hits = [b for b in blocks if b['type'] == STRATAGEM_TAG]
    print('  blocks tagged StratagemSettings (0x%08X): %d' % (STRATAGEM_TAG, len(hits)))
    for b in hits[:8]:
        print('    0x%X size=%d' % (b['address'], b['size']))

    print('\n== the most common tags ==')
    counter = Counter(b['type'] for b in blocks)
    for tag, count in counter.most_common(10):
        name = KNOWN.get(tag, '')
        print('  0x%08X  x%-4d %s' % (tag, count, name))

    print('\n== blocks whose SIZE looks like the stratagem table ==')
    # 80252 on disk for the shipped file; allow for the build having grown
    for b in sorted(blocks, key=lambda x: abs(x['size'] - 80252)):
        if 60000 <= b['size'] <= 120000:
            print('  0x%-12X size=%-8d type=0x%08X %s'
                  % (b['address'], b['size'], b['type'], KNOWN.get(b['type'], '')))
        if b['size'] > 200000:
            break

    print('\n== any block with that size, ignoring the tag ==')
    near = [b for b in blocks if 79000 <= b['size'] <= 82000]
    if not near:
        print('  none: no resident block is within 3 KB of the expected 80252 bytes')
    for b in near:
        print('  0x%X size=%d type=0x%08X' % (b['address'], b['size'], b['type']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
