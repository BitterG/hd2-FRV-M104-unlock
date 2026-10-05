"""Check that the dump analyzer re-derives the layout independently.

The analyzer reads what a run leaves behind (`frv_m104_stratagem_dump.txt`).  Its
whole point is that it must agree with the addon while sharing no code with it, so
the test feeds it dumps produced by the harness for fixtures whose layout is known
and asserts on the numbers it derives.

    python tests/run_tests_analyzer.py
"""
import subprocess
import sys
import tempfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ANALYZER = REPO / 'tools' / 'analyze_dump.py'

FAILURES = []
CHECKS_RUN = 0


def check(label, ok, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    print('%s  %s%s' % ('PASS' if ok else 'FAIL', label,
                        '' if ok else '  <- ' + str(detail)))
    if not ok:
        FAILURES.append(label)


def to_lua(lua, spec):
    if isinstance(spec, dict):
        table = lua.table()
        for key, value in spec.items():
            table[key] = to_lua(lua, value)
        return table
    if isinstance(spec, (list, tuple)):
        table = lua.table()
        for index, value in enumerate(spec, 1):
            table[index] = to_lua(lua, value)
        return table
    return spec


def make_dump(kind, directory):
    lua = LuaRuntime(unpack_returned_tuples=True)
    g = lua.globals()
    g.HARNESS_SOURCE = (HERE / 'harness.lua').read_text(encoding='utf-8')
    g.ADDON_SOURCE = (REPO / 'Source/mods/dsh/frv_m104.lua').read_text(
        encoding='utf-8')
    g.DshFrvM104Test = True
    lua.execute("local c = assert(load(HARNESS_SOURCE, '@harness')); M = c();"
                "local a = assert(load(ADDON_SOURCE, '@addon')); R = a();")
    out = lua.eval('function(k) return M.run(R, k) end')(to_lua(lua, kind))
    (directory / 'frv_m104_stratagem_dump.txt').write_text(
        out['strat_dumps'], encoding='utf-8', newline='\n')
    (directory / 'frv_m104_stratagem.txt').write_text(
        out['strat_lines'], encoding='utf-8', newline='\n')
    return out


def run_analyzer(directory):
    result = subprocess.run([sys.executable, str(ANALYZER), str(directory)],
                            capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def main():
    cases = [
        ('absolute pointer, inline ids, 8 records',
         {'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6}, 312, 112, 5, 6),
        ('130 records, ids inside nested arrays',
         {'count': 130,
          'nested': [{'record': 100, 'id': 'frv_base', 'pointer_field': 112},
                     {'record': 110, 'id': 'frv_supply', 'pointer_field': 112}]},
         312, 0, 100, 110),
        # the case the analyzer is really for: the addon could not attribute the id
        # (its `type` column filter scores zero), so it fell back to a flat scan.
        # The analyzer tries the typelib stride regardless and can still attribute.
        ('type column unusable - the addon fell back, the analyzer should not',
         {'count': 8, 'garbage_types': True,
          'placements': [{'record': 5, 'field': 112, 'id': 'frv_base'},
                         {'record': 6, 'field': 112, 'id': 'frv_supply'}]},
         312, 112, 5, 6),
    ]
    for label, kind, stride, field, base_record, ref_record in cases:
        print('\n== %s ==' % label)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            out = make_dump(kind, directory)
            expected = kind.get('garbage_types') and 'field_unverified' \
                or 'confirmed_by_reference'
            print('   (addon: %s / %s)' % (out['patch_state'],
                                           out['patch_confidence']))
            code, text = run_analyzer(directory)
            check('the analyzer exits cleanly', code == 0, text[-400:])
            check('it parsed the instance image(s)',
                  'parsed 1 instance image(s)' in text, text[:300])
            check('it re-derives stride %d' % stride,
                  ('%d(' % stride) in text, text)
            check('it attributes frv_base to record %d field +%d'
                  % (base_record, field),
                  'frv_base    record=%d' % base_record in text,
                  text[-900:])
            check('it attributes frv_supply to record %d' % ref_record,
                  'frv_supply  record=%d' % ref_record in text, text[-900:])
            if expected == 'field_unverified':
                check('the addon needed the fallback, the analyzer did not',
                      out['patch_confidence'] == 'field_unverified', 
                      out['patch_confidence'])

    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
