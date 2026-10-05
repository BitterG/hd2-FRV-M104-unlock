"""Quick manual driver for the v2 patcher: run one fixture and print the verdict.

    python tests/smoke_patch.py [fixture]
        fixture: ok (default) | copies | noref | wrongfield | tworecords | readonly
                 lying | recononly | disabled
"""
import sys
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'

FIXTURES = {
    'ok': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6}, {}),
    'copies': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
                'extra_copies': 2}, {}),
    'noref': ({'layout': 'abs', 'count': 8, 'id_at': 5}, {}),
    'wrongfield': ({'count': 8, 'placements': [
        {'record': 5, 'field': 112, 'id': 'frv_base'},
        {'record': 6, 'field': 120, 'id': 'frv_supply'}]}, {}),
    'tworecords': ({'count': 8, 'placements': [
        {'record': 5, 'field': 112, 'id': 'frv_base'},
        {'record': 6, 'field': 112, 'id': 'frv_base'},
        {'record': 7, 'field': 112, 'id': 'frv_supply'}]}, {}),
    'readonly': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
                  'read_only': True}, {}),
    'lying': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
               'lying_writer': True}, {}),
    'recononly': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6},
                  {'config': {'enabled': True, 'apply': False,
                              'restore_on_shutdown': True, 'source': 'smoke'}}),
    'disabled': ({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6},
                 {'config': {'enabled': False, 'apply': True,
                             'restore_on_shutdown': True, 'source': 'smoke'}}),
}


def to_lua(lua, spec):
    table = lua.table()
    for key, value in spec.items():
        if isinstance(value, (list, tuple)):
            inner = lua.table()
            for index, item in enumerate(value, 1):
                sub = lua.table()
                for k, v in item.items():
                    sub[k] = v
                inner[index] = sub
            table[key] = inner
        else:
            table[key] = value
    return table


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'ok'
    kind, opts = FIXTURES[name]
    lua = LuaRuntime(unpack_returned_tuples=True)
    g = lua.globals()
    g.HARNESS_SOURCE = (HERE / 'harness.lua').read_text(encoding='utf-8')
    g.ADDON_SOURCE = SOURCE.read_text(encoding='utf-8')
    g.DshFrvM104Test = True
    lua.execute("local c = assert(load(HARNESS_SOURCE, '@harness')); M = c();"
                "local a = assert(load(ADDON_SOURCE, '@addon')); R = a();")
    run_opts = lua.table()
    if opts.get('config'):
        cfg = lua.table()
        for k, v in opts['config'].items():
            cfg[k] = v
        run_opts['config'] = cfg
    out = lua.eval('function(k, o) return M.run(R, k, o) end')(
        to_lua(lua, kind), run_opts)
    for key in ('patch_state', 'patch_field', 'patch_reason', 'patched_count',
                'refused_count', 'record_hits', 'strat_count', 'write_ok',
                'write_failed', 'restore', 'after_restore'):
        print('%-16s %s' % (key, out[key]))
    print('--- status ---')
    print(out['status'][:900])
    print('--- patch report (evidence) ---')
    print(out['patch_report'][:1600])
    return 0


if __name__ == '__main__':
    sys.exit(main())
