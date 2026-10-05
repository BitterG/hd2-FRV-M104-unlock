"""Layout of the StratagemSettings table, straight from the game's own typelib.

`filediver/datalibrary/*.go` has no stratagem file, but `dl_library.dl_typelib`
is the game's complete type library: it carries the offset and size of every
member of every type, including the stratagem ones. Member *names* were stripped
by the game (typeinfo_strings_size == 0), so names come from the community
component schema (`work/hddata/data/components/StratagemInfo.json`), which lists
the fields in declaration order.

The two agree on order; the typelib supplies the widths. That combination is the
offline layout, and it is what the runtime patcher's self-check compares against.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / 'tools'))
from dlmember import dl_hash                      # noqa: E402
from dltypelib import Typelib                     # noqa: E402


def field_order():
    """Field names, in declaration order, from the community schema."""
    import json
    doc = json.loads((REPO / 'work/hddata/data/components/StratagemInfo.json')
                     .read_text(encoding='utf-8'))
    return list(doc['StratagemInfo'].items())


SIZES = {1: 'byte', 2: 'u16', 3: 'u32?', 4: 'u32', 8: 'u64'}


def main():
    tl = Typelib(REPO / 'filediver/datalibrary/dl_library.dl_typelib')
    print('typelib: types=%d enums=%d members=%d strings=%d'
          % (tl.type_count, tl.enum_count, tl.member_count, tl.strings_size))

    for name in ('StratagemInfo', 'StratagemSettings', 'StratagemSettingsData',
                 'ProjectileSettings', 'DamageSettings'):
        h = dl_hash(name)
        idx = tl.type_index(h)
        print('\n== %-22s dlsum=%#010x %s' % (name, h,
              ('FOUND size=%d members=%d' % (tl.types[idx]['size'],
                                             tl.types[idx]['member_count']))
              if idx is not None else 'not in typelib'))
        if idx is None:
            continue
        t = tl.types[idx]
        members = tl.members[t['member_start']:t['member_start'] + t['member_count']]
        names = field_order() if name == 'StratagemInfo' else []
        for i, md in enumerate(members):
            label = names[i][0] if i < len(names) else '?'
            kind = names[i][1].get('type') if i < len(names) else ''
            print('   [%2d] +%-5d size=%-3d align=%-3d type_id=%#010x  %-34s %s'
                  % (i, md['offset'], md['size'], md['align'], md['type_id'],
                     label, kind))
        # consistency: does each (offset,size) line up with the schema order?
        print('   sum of sizes = %d, struct size = %d, trailing = %d'
              % (sum(m['size'] for m in members), t['size'],
                 t['size'] - (members[-1]['offset'] + members[-1]['size'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
