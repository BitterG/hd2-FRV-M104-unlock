"""Offline test suite for mods/dsh/frv_m104_recon.lua.

Runs the addon under the *game's* Lua (LuaJIT via lupa.luajit21 - 6.20: a plain
lupa.LuaRuntime is Lua 5.5 and happily accepts syntax the game rejects) against
the fake address space in tests/harness.lua, then mutates the addon and requires
each mutation to be caught.  A mutation that nothing notices means the test is
not testing anything.

    python tests/run_tests.py
"""
import sys
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_recon.lua'
HARNESS = HERE / 'harness.lua'

FAILURES = []
CHECKS_RUN = 0


def check(label, condition, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    if condition:
        print('  PASS  %s' % label)
    else:
        print('  FAIL  %s %s' % (label, detail))
        FAILURES.append(label)


class Session:
    """One LuaJIT runtime with the harness and (optionally mutated) addon loaded."""

    def __init__(self, addon_source):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.HARNESS_SOURCE = HARNESS.read_text(encoding='utf-8')
        g.ADDON_SOURCE = addon_source
        g.DshFrvM104ReconTest = True       # suppress the addon's own auto-start
        self.lua.execute(
            "local chunk = assert(load(HARNESS_SOURCE, '@harness'));"
            "M = chunk();"
            "local addon = assert(load(ADDON_SOURCE, '@addon'));"
            "Recon = addon();"
        )
        self.M = g.M
        self.Recon = g.Recon

    def run(self, kind):
        # lupa raises KeyError when Lua indexes a missing key of a Python dict,
        # so hand the fixture kind over as a real Lua table instead
        return self.M.run(self.Recon, self.to_lua(kind))

    def to_lua(self, spec):
        table = self.lua.table()
        for key, value in spec.items():
            if value is None:
                continue
            if isinstance(value, (list, tuple)):
                inner = self.lua.table()
                for index, item in enumerate(value, 1):
                    inner[index] = item
                table[key] = inner
            else:
                table[key] = value
        return table


SELF_TEXT = None


def self_texts(M):
    return [M.SIGNATURE_HEX, 'b9efebd3ffc721cc', '2e4340863740219b',
            'e57f71d8e3bf852d', 'b3a69285ed82be75']


def syntax_gate():
    print('\n== syntax gate (LuaJIT compiles the exact shipped bytes) ==')
    text = SOURCE.read_text(encoding='utf-8')
    check('source has no UTF-8 BOM (6.53)', not text.startswith('\ufeff'))
    check('source is LF-only (6.55)', '\r' not in text)
    marker = '-- HD2-Addon: mods/dsh/frv_m104_recon\n'
    check('source declares the addon on line 1', text.startswith(marker))
    check('declaration appears exactly once', text.count('-- HD2-Addon:') == 1)
    for token in ('goto ', '//', '<<', '>>', 'math.type', 'string.pack',
                  'table.move'):
        check('no Lua-5.3-only construct %r (6.20)' % token, token not in text)
    for token in ('WriteProcessMemory(', 'VirtualProtect('):
        check('read-only: no %s' % token, token not in text)
    for token in ('os.execute', 'io.popen'):
        check('read-only: no %s (6.51)' % token, token not in text)
    # the addon must not declare a VirtualQuery prototype bound to a generic
    # struct name; other mods in this install use FRV_MBI (6.52)
    check('MBI struct name is private to this addon',
          'FRV_MBI' not in text and 'FRVM104_MBI_9c41' in text)


def functional():
    print('\n== functional: absolute-pointer layout (the expected game shape) ==')
    s = Session(SOURCE.read_text(encoding='utf-8'))
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5})
    lines = r['strat_lines']
    check('finds exactly one StratagemSettings table',
          r['strat_count'] == 1, 'got %s' % r['strat_count'])
    check('derives stride 312', 'derived stride=312' in lines)
    check('descriptor decodes to an absolute pointer',
          'raw_u64_0=0x200001028' in lines, lines[:400])
    check('record count decodes to 8', 'count=8' in lines)
    check('finds frv_base in record 5 at field +112',
          'RECORD_HIT' in lines and 'frv_base' in lines
          and 'record=5' in lines and 'field=+112' in lines, lines[-800:])
    check('finds the delivery id at field +120', 'delivery' in lines
          and 'field=+120' in lines)
    # With the realistic layout both the absolute-pointer and the
    # inline-after-descriptor candidate resolve to the same block, so the check is
    # that they agree on the record and field rather than that one of them misses.
    check('both candidates resolve to the same real record array',
          'array absolute_pointer' in lines
          and 'array inline_after_descriptor' in lines
          and 'record=5' in lines and 'field=+112' in lines, lines[-800:])
    check('record_hits counted', r['record_hits'] >= 2, 'got %s' % r['record_hits'])
    check('finishes with the decisive reason',
          r['phase'] == 'done' and 'stratagem record found' in r['reason'],
          '%s / %s' % (r['phase'], r['reason']))
    check('status first line is OK', r['status'].splitlines()[0].startswith('OK -'))
    check('entity blob image found',
          'blob_signature' in r['hit_lines'])
    check('census names the stratagem table',
          'name=StratagemSettings' in r['census_lines'])
    check('full hex dump of the table was kept',
          'full StratagemSettings instance' in r['strat_dumps'])

    print('\n== functional: relative-offset layout (the file shape, 6.13) ==')
    r = s.run({'layout': 'rel', 'count': 8, 'id_at': 3})
    lines = r['strat_lines']
    check('relative-offset candidate produces the record hits',
          'where=relative_offset' in lines and 'record=3' in lines
          and 'field=+112' in lines, lines[-800:])
    check('inline candidate also lands on the array',
          'where=inline_after_descriptor' in lines)
    check('record_hits non-zero', r['record_hits'] >= 2)
    # the whole point of the audit trail: the reported absolute address must be
    # the record's real address, not merely somewhere overlapping the array
    want = r['fixture']['strat']['array_addr'] + 3 * 312 + 112
    check('reports the exact address of the frv id',
          ('0x%016X' % want) in lines, 'want 0x%016X' % want)

    print('\n== functional: undecidable stride must not be guessed ==')
    r = s.run({'layout': 'abs', 'count': 7, 'id_at': 3, 'size_bias': 5})
    check('stride reported as undecidable',
          'derived stride=undecidable' in r['strat_lines'], r['strat_lines'][:300])
    check('no record hits are invented', r['record_hits'] == 0)
    check('table still dumped for offline analysis',
          'full StratagemSettings instance' in r['strat_dumps'])

    print('\n== functional: table present but no FRV id inside ==')
    r = s.run({'layout': 'abs', 'count': 8, 'no_ids': True})
    check('no record hits', r['record_hits'] == 0)
    check('says so instead of claiming success',
          'no FRV unit id' in r['reason'], r['reason'])
    check('status first line is OK, not FAILED',
          r['status'].splitlines()[0].startswith('OK -'))

    print('\n== functional: no stratagem table at all ==')
    r = s.run({'no_strat': True})
    check('no table found', r['strat_count'] == 0)
    check('reports which table was missing',
          'no StratagemSettings table found' in r['reason'], r['reason'])

    print('\n== functional: self-detection (6.2) ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5,
               'self_addr': 0x100100000, 'self_texts': self_texts(s.M)})
    check('self hits were skipped', r['self_hits'] >= 1, 'got %s' % r['self_hits'])
    check('the self address is not reported as a finding',
          '100100000' not in r['hit_lines'])
    check('the real record hit still found', r['record_hits'] >= 2)

    print('\n== census ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5})
    check('census sees both LDLD blocks', r['census'] == 2, 'got %s' % r['census'])
    check('sweeps terminated (they do not run forever, 6.41)',
          1 <= r['sweeps'] <= 5, 'got %s' % r['sweeps'])

    print('\n== functional: a mission load brings the table in (6.8) ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5, 'strat_in_phase2': True})
    check('still finds the table after the reload',
          r['record_hits'] >= 2 and 'stratagem record found' in r['reason'],
          '%s / %s' % (r['record_hits'], r['reason']))
    check('the reload is noticed and refunds a sweep',
          r['level_loads'] >= 1, 'level_loads=%s' % r['level_loads'])
    check('phase 1 alone did not find a table',
          r['sweeps'] >= 1, 'sweeps=%s' % r['sweeps'])


MUTATIONS = [
    ('record index arithmetic removed',
     'local within = field - index * stride',
     'local within = field',
     {'layout': 'abs', 'count': 8, 'id_at': 5},
     lambda r: 'field=+112' not in r['strat_lines']),
    ('descriptor read from the wrong offset',
     'local descriptor = body:sub(29, 44)',
     'local descriptor = body:sub(25, 40)',
     {'layout': 'abs', 'count': 8, 'id_at': 5},
     lambda r: r['record_hits'] == 0),
    ('payload offset used for the relative candidate',
     'local payload_abs = address + Recon.PAYLOAD_OFFSET',
     'local payload_abs = address',
     # only the relative-offset fixture can catch this: with an absolute pointer
     # descriptor the pointer candidate still lands on the array, so the abs
     # fixture is blind to it - the "fixture shape is too narrow" trap (skill 8).
     # And the catch has to be on record/field identity, not on hit count: the
     # wrong start still overlaps the real array and still reports hits.
     {'layout': 'rel', 'count': 8, 'id_at': 3},
     lambda r: ('record=3' not in r['strat_lines']
                or 'field=+112' not in r['strat_lines'])),
    ('self-detection disabled (6.2)',
     '    if self:is_self(address) then\n'
     '        self.self_hits = self.self_hits + 1\n'
     '        return\n'
     '    end',
     '    if false then\n'
     '        self.self_hits = self.self_hits + 1\n'
     '        return\n'
     '    end',
     {'layout': 'abs', 'count': 8, 'id_at': 5,
      'self_addr': 0x100100000, 'self_texts': '__SELF__'},
     # self_hits alone is not a usable signal: the LDLD census path bumps it too.
     # What matters is that the scanner's own bytes stop being filtered out of the
     # findings, so assert on the reported address.
     lambda r: '100100000' in r['hit_lines']),
    ('record array never scanned',
     '                    self:scan_record_array(instance, candidate.how, candidate.at,\n'
     '                        stride, count, array, lines)',
     '                    lines[#lines + 1] = "      array skipped"',
     {'layout': 'abs', 'count': 8, 'id_at': 5},
     lambda r: r['record_hits'] == 0),
    ('record hit counter never incremented',
     '                self.record_hits = self.record_hits + 1',
     '                self.record_hits = self.record_hits + 0',
     {'layout': 'abs', 'count': 8, 'id_at': 5},
     lambda r: r['record_hits'] == 0),
]


def mutations():
    print('\n== mutation testing: every mutation must be caught ==')
    original = SOURCE.read_text(encoding='utf-8')
    for label, old, new, kind, caught_if in MUTATIONS:
        if old not in original:
            check('mutation is applicable: %s' % label, False,
                  'anchor text not found - update the mutation')
            continue
        mutated = original.replace(old, new, 1)
        if mutated == original:
            check('mutation changed the source: %s' % label, False)
            continue
        s = Session(mutated)
        spec = dict(kind)
        if spec.get('self_texts') == '__SELF__':
            spec['self_texts'] = self_texts(s.M)
        try:
            r = s.run(spec)
            caught = caught_if(r)
            check('caught: %s' % label, caught,
                  'record_hits=%s self_hits=%s' % (r['record_hits'], r['self_hits']))
        except Exception as exc:            # a mutation that crashes is caught too
            check('caught (raised): %s' % label, True)
            print('        raised: %s' % exc)


def main():
    syntax_gate()
    functional()
    mutations()
    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
