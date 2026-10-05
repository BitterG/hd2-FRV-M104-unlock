"""Is the game's own dl_library.dl_typelib readable, and what does it say?

The installed build ships a 1062706-byte typelib; the FileDiver mirror is
905554 bytes. If the installed one parses, it is the authoritative layout for the
running game - which is what the runtime patcher must agree with.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dltypelib import Typelib                      # noqa: E402
from dlmember import dl_hash                       # noqa: E402

GAME_TL = Path(r'E:\SteamLibrary\steamapps\common\Helldivers 2\data\game\dl_library.dl_typelib')
MIRROR_TL = REPO / 'filediver/datalibrary/dl_library.dl_typelib'


def main():
    raw = GAME_TL.read_bytes()
    print('game typelib: %d bytes, head=%r, LTLD count=%d'
          % (len(raw), raw[:16], raw.count(b'LTLD')))
    if raw[:4] != b'LTLD':
        print('-> not a plaintext typelib; cannot parse offline')
        return 1

    for label, path in (('game', GAME_TL), ('mirror', MIRROR_TL)):
        tl = Typelib(path)
        print('\n%s: version=%d types=%d enums=%d members=%d default_data=%d strings=%d exact=%s'
              % (label, tl.version, tl.type_count, tl.enum_count, tl.member_count,
                 len(tl.default_data), tl.strings_size, tl.exact))
        for name in ('StratagemInfo', 'StratagemSettings'):
            h = dl_hash(name)
            idx = tl.type_index(h)
            if idx is None:
                print('   %-18s %#010x ABSENT' % (name, h))
                continue
            t = tl.types[idx]
            print('   %-18s %#010x size=%d members=%d' % (name, h, t['size'],
                                                          t['member_count']))
            for md in tl.members[t['member_start']:t['member_start'] + t['member_count']]:
                print('        +%-5d size=%-3d align=%-3d type_id=%#010x'
                      % (md['offset'], md['size'], md['align'], md['type_id']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
