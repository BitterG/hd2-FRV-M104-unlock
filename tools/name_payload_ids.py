"""Try to put NAMES on the stratagem payload ids.

Everything in this mod rests on one convention: a stratagem's `payload` array holds
the resource hashes of the units it spawns.  That was verified structurally - both
Exosuit payload[0] values are units that exist in the entity blob's component index
- but never with a *name*.  If the community hash list can name one of them, the
convention stops being an inference.

    python tools/name_payload_ids.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

IDS = {
    'exosuit_payload0': 0x79e4b3d2da5e45e3,
    'exosuit_obsidian_payload0': 0xc2d449ecf7facab1,
    'shared_payload1': 0x75be82ed8592a6b3,
    'frv_base': 0xcc21c7ffd3ebefb9,
    'frv_supply': 0x9b2140378640432e,
    'frv_heavy': 0x2d85bfe3d8717fe5,
}

LISTS = [
    ('filediver/hashes/hashes.txt', REPO / 'filediver/hashes/hashes.txt'),
    ('work/files.txt', REPO / 'work/files.txt'),
    ('work/game_refs.json', REPO / 'work/game_refs.json'),
    ('work/_name_gh.txt', REPO / 'work/_name_gh.txt'),
    ('work/cracked.txt', REPO / 'work/cracked.txt'),
]


def main():
    for label, path in LISTS:
        print('=== %s' % label)
        if not path.exists():
            print('    (missing)')
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        for name, value in IDS.items():
            forms = {
                '%016x' % value,
                '%X' % value,
                str(value),
                '%#x' % value,
                '%#018x' % value,
            }
            hit = None
            for form in forms:
                at = text.find(form)
                if at >= 0:
                    start = max(0, text.rfind('\n', 0, at) + 1)
                    end = text.find('\n', at)
                    hit = text[start:end if end > 0 else len(text)][:160]
                    break
            print('    %-24s %s' % (name, hit if hit else '(not in this list)'))
        print()


if __name__ == '__main__':
    sys.exit(main())
