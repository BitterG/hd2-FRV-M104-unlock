"""Offline test suite for the patcher addon (mods/dsh/frv_m104.lua).

Runs the addon under the *game's* Lua (LuaJIT via lupa.luajit21 - 6.20: a plain
lupa.LuaRuntime is Lua 5.5 and happily accepts syntax the game rejects) against
the fake address space in tests/harness.lua, then mutates the addon and requires
every mutation to be caught.  A mutation nothing notices means the test is not
testing anything.

    python tests/run_tests_patch.py
"""
import sys
import tempfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'
HARNESS = HERE / 'harness.lua'

BASE_ID = 'b9efebd3ffc721cc'
HEAVY_ID = 'e57f71d8e3bf852d'
PATCHED_FIELD = 112

FAILURES = []
CHECKS_RUN = 0


def check(label, condition, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    if condition:
        print('  PASS  %s' % label)
    else:
        print('  FAIL  %s  <- %s' % (label, detail))
        FAILURES.append(label)


class Session:
    """One LuaJIT runtime with the harness and (optionally mutated) addon loaded."""

    def __init__(self, addon_source):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.HARNESS_SOURCE = HARNESS.read_text(encoding='utf-8')
        g.ADDON_SOURCE = addon_source
        g.DshFrvM104Test = True       # suppress the addon's own auto-start
        self.lua.execute(
            "local chunk = assert(load(HARNESS_SOURCE, '@harness')); M = chunk();"
            "local addon = assert(load(ADDON_SOURCE, '@addon')); R = addon();"
        )
        self.M = g.M
        self.R = g.R
        self.g = g

    def bytes(self, hex_value):
        return self.M.hex_to_bytes(hex_value)

    def lua_function(self, body):
        return self.lua.eval('function(instance, api) %s end' % body)

    def to_lua(self, spec):
        return self._convert(spec)

    def _convert(self, value):
        if isinstance(value, dict):
            table = self.lua.table()
            for key, item in value.items():
                table[key] = self._convert(item)
            return table
        if isinstance(value, (list, tuple)):
            table = self.lua.table()
            for index, item in enumerate(value, 1):
                table[index] = self._convert(item)
            return table
        return value

    def run(self, kind, config=None, on_frame=None, frames=3000):
        opts = self.lua.table()
        if config is not None:
            cfg = self.lua.table()
            for key, value in config.items():
                cfg[key] = value
            opts['config'] = cfg
        if on_frame is not None:
            opts['on_frame'] = on_frame
        opts['frames'] = frames
        return self.M.run(self.R, self.to_lua(kind), opts)


def placements(*triples):
    return {'count': 8, 'placements': [
        {'record': record, 'field': field, 'id': ident}
        for record, field, ident in triples]}


OK_FIXTURE = {'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6}
# The package field, live-measured at record +168 - see the harness for the proof
# from the community plaintext dump.  The two values are what the fixture gives the
# M-102 record and the M-104 record it must copy from.
PACKAGE_FIELD = 168
PKG_BASE = '1111111111111111'
PKG_TARGET = '2222222222222222'
PKG_TARGET_BYTES = bytes.fromhex(PKG_TARGET)
HEAVY_BYTES = bytes.fromhex('e57f71d8e3bf852d')
# copies of the table that only appear after a "level load" (a second regions() call)
LATE_TABLE = {'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
              'late_copies': 1}
IDENTITY_CONFIG = {'enabled': True, 'apply': True, 'restore_on_shutdown': True,
                   'source': 'test'}

# The REAL stratagem-table shape: the ids are not in the records at all, they live
# in a nested array appended AFTER the records, reached through a pointer stored in
# the record.  This is what makes `(size - 16) / count` the wrong stride - measured
# on the real table, size-16 is 80236 whose only divisors are 1,2,4,13,26,52,1543
# and 3086, so no plausible stride/count pair exists and nested data must be there.
NESTED_TABLE = {
    'count': 9,
    'nested': [{'record': 5, 'id': 'frv_base', 'pointer_field': 112},
               {'record': 6, 'id': 'frv_supply', 'pointer_field': 112}],
}
NESTED_TABLE_FILE_FORM = dict(NESTED_TABLE, nested_relative=True)
# the layout may be a bare u64 offset with no element count next to it; the patcher
# then falls back to its small default window rather than guessing a large one
NESTED_TABLE_NO_COUNT = dict(NESTED_TABLE, no_nested_count=True)
# the runtime may place the array in its own allocation; the record then holds a
# plain absolute pointer that is NOT inside the instance payload
NESTED_TABLE_DETACHED = dict(NESTED_TABLE, nested_detached=True)

# A realistic-size table.  The live build has on the order of a hundred and thirty
# stratagems, so the stride scorer has to pick 312 out of 76 candidates at real
# scale - and NOT the 624 alias, which samples every other record and scores the
# same on both columns (the tie-break towards the typelib value is what settles it).
BIG_TABLE = {
    'count': 130,
    'nested': [{'record': 100, 'id': 'frv_base', 'pointer_field': 112},
               {'record': 110, 'id': 'frv_supply', 'pointer_field': 112}],
}

# Two records grant the base FRV AND no stride scores (garbage type column), so the
# only identification available is the flat payload scan - which sees two
# occurrences at two different offsets.  That is precisely why the
# field-consistency requirement cannot apply on the fallback path.
GARBAGE_MULTI = dict(placements((5, 112, 'frv_base'), (6, 200, 'frv_base')),
                     garbage_types=True)

# The layout the LIVE GAME actually reported (2026-09-25, game.dll PE timestamp
# 0x6AB3B43F, 11 StratagemSettings instances resident):
#
#   M-102: 1 record(s) across 1 table instance(s), field(s) +0@152
#   M-103 reference: 1 distinct record(s) at field(s) +0@152
#   CONFIRMED: a different FRV stratagem uses the same payload field 0@152
#
# and inside that instance, three CONSECUTIVE records whose payload arrays are
# [frv_base, delivery], [frv_supply, delivery] and [frv_heavy, delivery]:
#
#   record 0  frv_base   +0   delivery +8
#   record 1  frv_supply +0   delivery +8
#   record 2  frv_heavy  +0   delivery +8
#
# So `payload` really is [unit, delivery] exactly as the Exosuit records implied,
# the M-104 stratagem already exists in the table, and the vehicle sits at offset 0
# of the array reached through the record's +152 pointer.  This fixture reproduces
# that shape, so a future build that moves the slot turns the suite red.
LIVE_LAYOUT = {
    'count': 40,
    'nested': [{'record': 0, 'id': 'frv_base', 'pointer_field': 152, 'elements': 2},
               {'record': 1, 'id': 'frv_supply', 'pointer_field': 152,
                'elements': 2},
               {'record': 2, 'id': 'frv_heavy', 'pointer_field': 152,
                'elements': 2}],
}

# The stratagem table can compile as SEVERAL same-type LDLD instances.  Measured on
# the offline mirror: generated_planet_override_settings.dl_bin is 12 instances and
# generated_weapon_customization_settings.dl_bin is 9, and the community dump of the
# stratagem table is likewise 12 groups.  Only one of the instances carries the
# M-102 record - so a gate that demands "one record per instance in memory" would
# refuse a perfectly good table.  The first version of the gate did exactly that.
SPLIT_TABLE = {
    'count': 8, 'extra_copies': 2,
    'copy_placements': [
        [{'record': 5, 'field': 112, 'id': 'frv_base'},
         {'record': 6, 'field': 112, 'id': 'frv_supply'}],
        [{'record': 1, 'field': 40, 'id': 'delivery'}],
        [{'record': 2, 'field': 64, 'id': 'delivery'}],
    ],
}

# Two copies of the table whose M-102 id sits at a different field offset in each.
# A single-copy fixture cannot express this: with one copy, two records holding the
# id trips the uniqueness check first, and the field-consistency check is never
# reached.  This is the "fixture shape is too narrow" trap (skill 8).
MOVING_FIELD = {
    'count': 8, 'extra_copies': 1,
    'copy_placements': [
        [{'record': 5, 'field': 112, 'id': 'frv_base'},
         {'record': 6, 'field': 112, 'id': 'frv_supply'}],
        [{'record': 5, 'field': 120, 'id': 'frv_base'},
         {'record': 6, 'field': 112, 'id': 'frv_supply'}],
    ],
}


def poke_hook(session, state, hex_value):
    """An on_frame hook that pokes `hex_value` in once the state is reached.

    The poke has to happen entirely inside Lua: lupa decodes Lua strings as UTF-8,
    so a byte string full of 0xE5 never survives a round trip through Python.
    """
    return session.lua.eval(
        "function(want_state, want_hex)\n"
        "  local once = false\n"
        "  return function(instance, api)\n"
        "    if once then return end\n"
        "    if instance.patch_state ~= want_state then return end\n"
        "    if not instance.patch_targets then return end\n"
        "    api.poke(instance.patch_targets[1].address, M.hex_to_bytes(want_hex))\n"
        "    once = true\n"
        "  end\n"
        "end")(state, hex_value)


# ---------------------------------------------------------------------------
# syntax + safety gate
# ---------------------------------------------------------------------------
def syntax_gate():
    print('\n== syntax and safety gate (the exact bytes that ship) ==')
    text = SOURCE.read_text(encoding='utf-8')
    check('source has no UTF-8 BOM (6.53)', not text.startswith('\ufeff'))
    check('source is LF-only (6.55)', '\r' not in text)
    marker = '-- HD2-Addon: mods/dsh/frv_m104\n'
    check('source declares the addon on line 1', text.startswith(marker))
    check('declaration appears exactly once', text.count('-- HD2-Addon:') == 1)
    for token in ('goto ', '//', '<<', '>>', 'math.type', 'string.pack',
                  'table.move'):
        check('no Lua-5.3-only construct %r (6.20)' % token, token not in text)
    check('never *calls* VirtualProtect (6.50: measured GameGuard kill)',
          'VirtualProtect(' not in text)
    for token in ('os.execute', 'io.popen'):
        check('never spawns a process: %s (6.51)' % token, token not in text)
    check('there is exactly one WriteProcessMemory call site',
          text.count('kernel.WriteProcessMemory(') == 1,
          text.count('kernel.WriteProcessMemory('))
    check('MBI struct name is private to this addon',
          'FRV_MBI' not in text and 'FRVM104_MBI_9c41' in text)

    lua = LuaRuntime()
    lua.globals().SRC = text
    result = lua.execute('local f, e = load(SRC, "@addon")\n'
                         'if f then return "ok" else return e end')
    check('the source compiles under LuaJIT', result == 'ok', result)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
def config_tests():
    print('\n== config parsing ==')
    s = Session(SOURCE.read_text(encoding='utf-8'))
    parse = s.R.parse_config
    defaults = s.R.DEFAULT_CONFIG

    text = ('# a comment\n'
            '; another comment\n'
            '\n'
            'enabled = true\n'
            'APPLY = False\n'
            'restore_on_shutdown = yes\n'
            'future_option = 3\n')
    cfg = parse(text, defaults)
    check('comment lines are ignored', cfg['enabled'] is True, cfg['enabled'])
    check('keys are case-insensitive and values too', cfg['apply'] is False,
          cfg['apply'])
    check('yes counts as true', cfg['restore_on_shutdown'] is True)
    check('unknown keys are reported, not silently dropped',
          len(cfg['unknown']) == 1, list(cfg['unknown']))

    cfg = parse(None, defaults)
    check('missing text yields the defaults',
          cfg['enabled'] is True and cfg['apply'] is True)
    cfg = parse('apply = 0\nenabled = off\n', defaults)
    check('0 / off are false', cfg['apply'] is False and cfg['enabled'] is False)

    cfg = parse('require_reference = true\nmulti_record = refuse\n', defaults)
    check('require_reference parses', cfg['require_reference'] is True)
    check('multi_record parses', cfg['multi_record'] == 'refuse',
          cfg['multi_record'])
    cfg = parse('multi_record = nonsense\n', defaults)
    check('an invalid multi_record value is reported, not silently accepted',
          cfg['multi_record'] == 'all' and len(cfg['unknown']) == 1,
          '%s / %s' % (cfg['multi_record'], list(cfg['unknown'])))
    cfg = parse(None, defaults)
    check('the default is to patch every stratagem that grants the base FRV',
          cfg['multi_record'] == 'all', cfg['multi_record'])
    check('the default does not demand the M-103 reference',
          cfg['require_reference'] is False, cfg['require_reference'])

    print('\n== config file handling (6.58) ==')
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'frv_m104.cfg'
        first = s.R.load_config(str(path))
        check('first run writes a template', path.exists(), 'no file was written')
        check('the template reports itself', 'template written' in first['source'],
              first['source'])
        body_before = path.read_text(encoding='utf-8')
        check('the template carries commented keys', '# apply' in body_before)
        path.write_text('apply = false\n', encoding='utf-8', newline='\n')
        second = s.R.load_config(str(path))
        check('an existing file is read, not overwritten',
              path.read_text(encoding='utf-8') == 'apply = false\n')
        check('its values take effect', second['apply'] is False)


# ---------------------------------------------------------------------------
# behaviour
# ---------------------------------------------------------------------------
def functional():
    print('\n== happy path: identified, patched, verified, restorable ==')
    s = Session(SOURCE.read_text(encoding='utf-8'))
    r = s.run(OK_FIXTURE)
    check('state is applied', r['patch_state'] == 'applied', r['patch_reason'])
    check('the accepted record stride is the typelib value 312',
          r['stride'] == 312, r['stride'])
    check('the field offset is +%d' % PATCHED_FIELD,
          r['patch_field'] == PATCHED_FIELD, r['patch_field'])
    check('exactly one copy was patched', r['patched_count'] == 1,
          r['patched_count'])
    check('two writes reached memory: the vehicle AND its asset package',
          r['write_ok'] == 2, r['write_ok'])
    check('the package was swapped exactly once', r['package_swapped'] == 1,
          r['package_swapped'])
    check('the package went to the record that holds the payload',
          r['package_targets'][1]['address']
          == r['fixture']['strat']['array_addr'] + 5 * 312 + PACKAGE_FIELD,
          hex(r['package_targets'][1]['address']))
    check('the package the M-104 record carries is the one written',
          PKG_BASE in r['originals'] and PKG_TARGET in r['originals'],
          r['originals'])
    check('no write was refused', r['write_failed'] == 0)
    check('the addon restored the original on retire', r['restore'] == 1,
          'restore=%s' % r['restore'])
    check('the bytes after restore are the M-102 id',
          r['after_restore'] == BASE_ID, r['after_restore'])
    check('and the package went back to the M-102 package with it',
          r['packages_after'] == PKG_BASE, r['packages_after'])
    check('status first line reports the patch',
          r['status'].splitlines()[0].startswith('OK - patch applied'))
    check('the evidence names the confirming reference',
          'CONFIRMED' in r['patch_report'], r['patch_report'][-400:])
    check('the originals file has the before and after bytes',
          BASE_ID in r['originals'] and HEAVY_ID in r['originals'],
          r['originals'])

    print('\n== the patch really lands in memory while the mod is live ==')
    s2 = Session(SOURCE.read_text(encoding='utf-8'))
    s2.g.SEEN_HEX = None
    # lupa decodes Lua strings as UTF-8, so binary must cross the boundary as hex
    s2.run(OK_FIXTURE, on_frame=s2.lua_function(
        "if instance.patch_state == 'applied' and instance.patch_targets then "
        "  SEEN_HEX = M.hex(api.read(instance.patch_targets[1].address, 8)) end"))
    check('while applied, memory holds the M-104 id',
          s2.g.SEEN_HEX == HEAVY_ID, s2.g.SEEN_HEX)

    print('\n== every copy of the table is patched (6.17) ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
               'extra_copies': 2})
    check('three copies were patched', r['patched_count'] == 3, r['patched_count'])
    check('all three were restored', r['restore'] == 3, r['restore'])
    check('three distinct addresses were touched', r['after_restore'].count(',') == 2,
          r['after_restore'])

    print('\n== idempotence: our own earlier write is recognised ==')
    s3 = Session(SOURCE.read_text(encoding='utf-8'))
    r = s3.run(OK_FIXTURE, on_frame=poke_hook(s3, 'decided', HEAVY_ID))
    check('an already-patched field counts as ours, not as a foreign write',
          r['patch_state'] == 'applied' and r['patched_count'] == 1,
          'state=%s writes=%s patched=%s' % (r['patch_state'], r['write_ok'],
                                             r['patched_count']))
    check('and the only write left to do was the package',
          r['write_ok'] == 1 and r['package_swapped'] == 1,
          'writes=%s packages=%s' % (r['write_ok'], r['package_swapped']))

    print('\n== maintain: a reverted copy is written again ==')
    s4 = Session(SOURCE.read_text(encoding='utf-8'))
    r = s4.run(OK_FIXTURE, on_frame=poke_hook(s4, 'applied', BASE_ID))
    check('the revert was noticed and re-applied', r['reapplied_count'] >= 1,
          'reapplied=%s' % r['reapplied_count'])

    print('\n== read-only kernel refusal is reported, not claimed ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
               'read_only': True})
    check('the run fails loudly', r['patch_state'] == 'failed'
          and r['status'].splitlines()[0].startswith('FAILED'),
          '%s / %s' % (r['patch_state'], r['status'].splitlines()[0]))
    check('no memory changed', r['patched_count'] == 0)

    print('\n== a lying writer is caught by the read-back (6.29) ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
               'lying_writer': True})
    check('the run does not claim success',
          r['patch_state'] == 'failed' and r['patched_count'] == 0,
          '%s / patched=%s' % (r['patch_state'], r['patched_count']))
    check('the failure is visible in the status first line',
          r['status'].splitlines()[0].startswith('FAILED'))

    print('\n== the M-103 reference is corroboration, not a requirement ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5})
    check('with no reference at all the patch still applies',
          r['patch_state'] == 'applied' and r['patched_count'] == 1,
          '%s / %s' % (r['patch_state'], r['patch_reason']))
    check('and the status says the confidence honestly',
          r['patch_confidence'] == 'reference_absent'
          and 'confidence=reference_absent' in r['status'],
          '%s' % r['patch_confidence'])
    check('the evidence explains why that is acceptable',
          'confidence=reference_absent' in r['patch_report'],
          r['patch_report'][-500:])
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5}, config=dict(
        IDENTITY_CONFIG, require_reference=True))
    check('require_reference = true refuses the very same table',
          r['patch_state'] == 'refused' and r['write_ok'] == 0,
          '%s / writes=%s' % (r['patch_state'], r['write_ok']))

    print('\n== several records of one instance carrying the M-102 id ==')
    r = s.run(TWO_BASE_RECORDS)
    check('multi_record = all patches every one of them',
          r['patch_state'] == 'applied' and r['patched_count'] == 2,
          '%s / patched=%s / %s' % (r['patch_state'], r['patched_count'],
                                    r['patch_reason']))
    r = s.run(TWO_BASE_RECORDS, config=dict(IDENTITY_CONFIG,
                                            multi_record='refuse'))
    check('multi_record = refuse writes nothing',
          r['patch_state'] == 'refused' and r['write_ok'] == 0,
          '%s / writes=%s' % (r['patch_state'], r['write_ok']))

    print('\n== refusals that survive the softening ==')
    cases = [
        ('the reference sits at a different field',
         placements((5, 112, 'frv_base'), (6, 120, 'frv_supply')),
         'they disagree'),
        ('the M-102 id moves between fields',
         MOVING_FIELD,
         'different field offsets'),
    ]
    for label, kind, expected in cases:
        r = s.run(kind)
        check('refused: %s' % label,
              r['patch_state'] == 'refused' and expected in (r['patch_reason'] or ''),
              '%s / %s' % (r['patch_state'], r['patch_reason']))
        check('nothing written: %s' % label,
              r['write_ok'] == 0 and r['patched_count'] == 0,
              'writes=%s patched=%s' % (r['write_ok'], r['patched_count']))

    print('\n== a foreign value in the slot is left alone ==')
    s5 = Session(SOURCE.read_text(encoding='utf-8'))
    r = s5.run(OK_FIXTURE, on_frame=poke_hook(s5, 'decided', 'deadbeefdeadbeef'))
    check('the run refuses rather than overwriting another owner',
          r['patch_state'] == 'failed' and r['patched_count'] == 0,
          '%s / patched=%s' % (r['patch_state'], r['patched_count']))

    print('\n== a table split into several instances is still handled ==')
    r = s.run(SPLIT_TABLE)
    check('all three instances were found', r['strat_count'] == 3,
          'instances=%s' % r['strat_count'])
    check('the patch still applies', r['patch_state'] == 'applied'
          and r['patched_count'] == 1,
          '%s / patched=%s / %s' % (r['patch_state'], r['patched_count'],
                                    r['patch_reason']))
    check('only the one instance holding the id was touched', r['restore'] == 1,
          r['restore'])
    check('the evidence reports instances, not just records',
          'table instance(s)' in r['patch_report'], r['patch_report'][:600])

    print('\n== the table only arriving with a mission load (6.8) ==')
    r = s.run({'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
               'strat_in_phase2': True})
    check('the reload was noticed', r['level_loads'] >= 1, r['level_loads'])
    check('the patch applies after the reload',
          r['patch_state'] == 'applied' and r['patched_count'] == 1,
          '%s / %s' % (r['patch_state'], r['patch_reason']))

    print('\n== the real shape: ids inside a nested array appended after the ==')
    print('== records, reached through a record pointer                       ==')
    for label, kind in (('memory form (absolute address)', NESTED_TABLE),
                        ('file form (relative offset)', NESTED_TABLE_FILE_FORM),
                        ('no element count next to the pointer',
                         NESTED_TABLE_NO_COUNT),
                        ('array in its own allocation (detached pointer)',
                         NESTED_TABLE_DETACHED)):
        r = s.run(kind)
        fixture = r['fixture']['strat']
        if kind.get('nested_detached'):
            # with the array in its own allocation nothing is appended, so the size
            # DOES divide - this fixture exists to reach the external-pointer branch,
            # not the non-divisible-stride trap
            check('%s: the instance holds only records (array detached)' % label,
                  fixture['size'] == 16 + fixture['count'] * 312, fixture['size'])
        else:
            check('%s: the fixture models the trap - (size-16) does not divide by '
                  'count' % label,
                  (fixture['size'] - 16) % fixture['count'] != 0,
                  '%d %% %d' % (fixture['size'] - 16, fixture['count']))
        lines = r['strat_lines']
        check('%s: the accepted hypothesis is the 312-byte record' % label,
              r['stride'] == 312, r['stride'])
        check('%s: the id was found through the nested pointer' % label,
              '/nested' in lines and 'frv_base' in lines and 'record=5' in lines
              and 'ptr=+112' in lines, lines[-700:])
        check('%s: the M-103 reference came from its own nested array' % label,
              'frv_supply' in lines and 'record=6' in lines, lines[-700:])
        check('%s: the gate confirmed and the patch applied' % label,
              r['patch_state'] == 'applied' and r['patched_count'] == 1,
              '%s / %s' % (r['patch_state'], r['patch_reason']))
        check('%s: the write went to the nested array' % label,
              r['write_ok'] == 2 and r['restore'] == 1,
              'writes=%s restore=%s' % (r['write_ok'], r['restore']))
        check('%s: and the package went to the record, not the array' % label,
              r['package_targets'][1]['address']
              == fixture['array_addr'] + 5 * 312 + PACKAGE_FIELD
              and r['packages_after'] == PKG_BASE,
              '%s / %s' % (hex(r['package_targets'][1]['address']),
                           r['packages_after']))

    print('\n== the whole-payload fallback (id present but unattributable) ==')
    garbage = dict(OK_FIXTURE, garbage_types=True)
    r = s.run(garbage)
    check('no stride hypothesis scores, so nothing is attributed to a record',
          'ptr=' not in r['strat_lines'] and '/inline' not in r['strat_lines'],
          r['strat_lines'][-600:])
    check('the id is still found by the flat payload scan',
          'whole-payload id occurrences: frv_base=1' in r['strat_lines'],
          r['strat_lines'][-400:])
    # Without record attribution the package field (+168) cannot be located either,
    # and a vehicle whose assets belong to a package this record never loads is
    # what crashed the live game.  So the default now refuses - loudly - and only
    # the documented escape hatch writes the vehicle alone.
    check('and the default refuses, because the package cannot be located',
          r['patch_state'] == 'refused' and r['write_ok'] == 0
          and 'asset package' in (r['patch_reason'] or ''),
          '%s / %s' % (r['patch_state'], r['patch_reason']))
    check('the refusal names the escape hatch',
          'require_package = false' in (r['patch_reason'] or ''),
          r['patch_reason'])

    r = s.run(garbage, config=dict(IDENTITY_CONFIG, require_package=False))
    check('require_package = false patches the vehicle without a package',
          r['patch_state'] == 'applied' and r['patched_count'] == 1,
          '%s / %s' % (r['patch_state'], r['patch_reason']))
    check('the confidence says the attribution was not verified',
          r['patch_confidence'] == 'field_unverified', r['patch_confidence'])
    check('the status carries that confidence',
          'confidence=field_unverified' in r['status'])
    check('and it wrote the right bytes', r['write_ok'] == 1 and r['restore'] == 1,
          'writes=%s restore=%s' % (r['write_ok'], r['restore']))
    check('with no package to swap, only the vehicle was written',
          r['package_swapped'] == 0, r['package_swapped'])

    r = s.run(garbage, config=dict(IDENTITY_CONFIG,
                                   allow_unverified_field=False))
    check('allow_unverified_field = false refuses the same table',
          r['patch_state'] != 'applied' and r['write_ok'] == 0,
          '%s / writes=%s' % (r['patch_state'], r['write_ok']))

    print('\n== the fallback still honours multi_record ==')
    # the flat-scan path can only ever run with require_package = false: with no
    # record attribution there is no +168 to read the package from (see above)
    r = s.run(GARBAGE_MULTI, config=dict(IDENTITY_CONFIG, require_package=False))
    check('the flat scan reports both occurrences with their offsets',
          'whole-payload id occurrences: frv_base=2' in r['strat_lines']
          and r['strat_lines'].count('+0x') >= 2, r['strat_lines'][-400:])
    check('multi_record = all patches both',
          r['patch_state'] == 'applied' and r['patched_count'] == 2,
          '%s / patched=%s / %s' % (r['patch_state'], r['patched_count'],
                                    r['patch_reason']))
    check('and the two writes landed', r['write_ok'] == 2, r['write_ok'])
    r = s.run(GARBAGE_MULTI, config=dict(IDENTITY_CONFIG, require_package=False,
                                         multi_record='refuse'))
    check('multi_record = refuse refuses the same table',
          r['patch_state'] != 'applied' and r['write_ok'] == 0,
          '%s / writes=%s' % (r['patch_state'], r['write_ok']))

    print('\n== a realistic-size table (130 records, nested payload arrays) ==')
    r = s.run(BIG_TABLE)
    fixture = r['fixture']['strat']
    check('it is about the size of the real stratagem table',
          fixture['size'] == 16 + 130 * 312 + 96, fixture['size'])
    check('and its size does not divide into a stride',
          (fixture['size'] - 16) % 130 != 0)
    check('the scorer picked 312, not the 624 alias', r['stride'] == 312,
          r['stride'])
    check('the M-102 id was found in real-scale record 100',
          'record=100' in r['strat_lines'] and 'frv_base' in r['strat_lines'],
          r['strat_lines'][-600:])
    check('the M-103 reference was found in record 110',
          'record=110' in r['strat_lines'] and 'frv_supply' in r['strat_lines'],
          r['strat_lines'][-600:])
    check('the patch applies at real scale',
          r['patch_state'] == 'applied' and r['patched_count'] == 1,
          '%s / %s' % (r['patch_state'], r['patch_reason']))
    check('and nothing spurious was touched', r['restore'] == 1, r['restore'])

    print('\n== a mission load brings its own table copies (live 2026-09-25) ==')
    # The live failure this models: the patch was applied and confirmed on the SHIP
    # copy, every copy still read back as ours for the whole session (reapplied=0
    # foreign=0 dead=0) - and the mission still delivered the M-102, because a level
    # load brings its own copies of the table.  A freed heap keeps its bytes, so
    # "has every patched copy disappeared" can never fire; the only signal is that
    # the address space grew.
    r = s.run(LATE_TABLE)
    check('the level load was noticed and followed', r['follows'] >= 1,
          'follows=%s' % r['follows'])
    check('both the ship copy and the mission copy were patched',
          r['patched_count'] == 2 and r['package_swapped'] == 2,
          'patched=%s packages=%s / %s' % (r['patched_count'],
                                           r['package_swapped'],
                                           r['patch_reason']))
    late = r['fixture']['late'][1]
    record = late['array_addr'] + 5 * 312          # the inline fixture puts the id at +112
    seen = set()
    for w in r['writes'].values():
        if w['ok']:
            seen.add(w['address'])
    check('the later copy really was written to, in its own memory',
          record + 112 in seen, sorted(hex(a) for a in seen))
    check('and the package of the later copy went with it',
          record + PACKAGE_FIELD in seen, sorted(hex(a) for a in seen))
    check('the observer says both copies hold our bytes',
          r['observed'] is not None
          and r['observed']['vehicle']['ours'] == 2
          and r['observed']['package']['ours'] == 2,
          r['observed'] and '%s / %s' % (dict(r['observed']['vehicle']),
                                         dict(r['observed']['package'])))

    # While that re-scan is in flight the patch is NOT undone, and the status line
    # has to say so - reporting "WORKING - scanning" there once made a live test look
    # like a failure when the mod was in fact still applied.
    s6 = Session(SOURCE.read_text(encoding='utf-8'))
    s6.g.FOLLOW_STATUS = None
    s6.run(LATE_TABLE, on_frame=s6.lua_function(
        "if FOLLOW_STATUS == nil and instance.follows > 0 "
        "  and instance.patched_count > 0 then "
        "  FOLLOW_STATUS = instance:status_text() end"))
    mid = s6.g.FOLLOW_STATUS or ''
    check('mid-rescan the first line still says the patch is applied',
          mid.splitlines() and mid.splitlines()[0].startswith(
              'OK - patch is STILL applied'),
          mid.splitlines()[0] if mid else '(never captured)')
    check('and it quotes the frame the slot was last seen ours at',
          'last seen in place at frame' in mid, mid.splitlines()[0] if mid else '')

    # ...but ordinary memory churn must NOT trigger a re-scan.  The first, looser
    # gate did exactly that on the live game: 14 re-scans in 8 minutes, one of them
    # while the address space had shrunk, each re-reading hundreds of MB for nothing.
    r = s.run(dict(LATE_TABLE, churn_waves=2))
    check('only the real level load triggered a re-scan, not the later churn',
          r['follows'] == 1, 'follows=%s' % r['follows'])
    check('and both table copies are still patched',
          r['patched_count'] == 2 and r['package_swapped'] == 2,
          'patched=%s packages=%s' % (r['patched_count'], r['package_swapped']))

    print('\n== the layout the live game reported (field 0@152) ==')
    r = s.run(LIVE_LAYOUT)
    check('the slot the live game used is the one identified',
          r['patch_field_key'] == '0@152', r['patch_field_key'])
    check('the M-102 record is the one that gets patched',
          'frv_base' in r['strat_lines'] and 'frv_supply' in r['strat_lines']
          and 'frv_heavy' in r['strat_lines'], r['strat_lines'][-700:])
    check('it confirms against the M-103 record',
          r['patch_confidence'] == 'confirmed_by_reference', r['patch_confidence'])
    check('and patches exactly the M-102 record', r['patch_state'] == 'applied'
          and r['patched_count'] == 1,
          '%s / %s / %s' % (r['patch_state'], r['patched_count'],
                            r['patch_reason']))
    check('the original bytes are the M-102 unit id',
          'b9efebd3ffc721cc' in r['originals'], r['originals'])
    check('and the written bytes are the M-104 unit id',
          'e57f71d8e3bf852d' in r['originals'], r['originals'])

    print('\n== config switches ==')
    r = s.run(OK_FIXTURE, config={'enabled': True, 'apply': False,
                                  'restore_on_shutdown': True, 'source': 'test'})
    check('apply = false writes nothing', r['write_ok'] == 0)
    check('apply = false still runs the full identification',
          r['patch_state'] == 'recon_only' and r['record_hits'] >= 3,
          '%s / hits=%s' % (r['patch_state'], r['record_hits']))
    check('the status says recon only',
          r['status'].splitlines()[0].startswith('OK - recon only'),
          r['status'].splitlines()[0])

    r = s.run(OK_FIXTURE, config={'enabled': False, 'apply': True,
                                  'restore_on_shutdown': True, 'source': 'test'})
    check('enabled = false scans nothing and writes nothing',
          r['write_ok'] == 0 and r['census'] == 0, r['census'])
    check('the status says disabled',
          r['status'].splitlines()[0].startswith('DISABLED'))

    print('\n== restore_on_shutdown = false leaves the change in place ==')
    s6 = Session(SOURCE.read_text(encoding='utf-8'))
    r = s6.run(OK_FIXTURE, config={'enabled': True, 'apply': True,
                                   'restore_on_shutdown': False,
                                   'source': 'test'})
    check('nothing was restored', r['restore'] == 0, r['restore'])
    check('the patched bytes are still the M-104 id',
          r['after_restore'] == HEAVY_ID, r['after_restore'])


# ---------------------------------------------------------------------------
# mutations
# ---------------------------------------------------------------------------
TWO_BASE_RECORDS = placements((5, 112, 'frv_base'), (6, 112, 'frv_base'),
                              (7, 112, 'frv_supply'))
WRONG_REF_FIELD = placements((5, 112, 'frv_base'), (6, 120, 'frv_supply'))
LYING_WRITER = {'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
                'lying_writer': True}


def mutation_cases():
    return [
        # the greedy window can only bite when the record does NOT carry an element
        # count: with a count present the window is sized from it, so this mutation
        # is invisible on the counted fixture (the "fixture shape is too narrow"
        # trap again)
        # only a fixture whose array lives OUTSIDE the instance can reach the
        # external-pointer branch; with the array inside, the earlier branch returns
        # first and this mutation is invisible.  The condition spans two lines, so
        # the mutation neutralises the first clause rather than deleting the `if`.
        ('the external (own-allocation) pointer branch removed',
         '    if value % 8 == 0 and value >= M104.POINTER_MIN',
         '    if false and value >= M104.POINTER_MIN',
         NESTED_TABLE_DETACHED, None,
         lambda r: r['patch_state'] != 'applied'),
        ('the nested read window made greedy (it swallows the next array)',
         'M104.NESTED_READ = 16',
         'M104.NESTED_READ = 256',
         NESTED_TABLE_NO_COUNT, None,
         lambda r: r['patch_state'] != 'applied'),
        # These two no longer change the OUTCOME (the whole-payload fallback still
        # patches the unique id); what they change is the quality of the
        # identification, so that is what the test asserts.  A mutation that only
        # degrades confidence is still observable - and the dedicated fallback test
        # below covers the fallback itself.
        ('the nested-pointer resolution disabled',
         '            local nested = value and M104.resolve_nested(self, instance, value)',
         '            local nested = nil',
         NESTED_TABLE, None,
         lambda r: r['patch_confidence'] != 'confirmed_by_reference'),
        ('the fallback registers only the first occurrence',
         '                for index = 1, #source.list do',
         '                for index = 1, 1 do',
         GARBAGE_MULTI, None,
         lambda r: r['patched_count'] != 2),
        ('the whole-payload fallback disabled',
         '        if not decided and self.allow_unverified_field then',
         '        if false then',
         dict(OK_FIXTURE, garbage_types=True), None,
         lambda r: r['patch_state'] != 'applied'),
        ('the record scan removed',
         '    for index = 0, records - 1 do',
         '    for index = 0, -1 do',
         NESTED_TABLE, None,
         lambda r: r['patch_confidence'] != 'confirmed_by_reference'),
        ('the multi_record policy ignored (refuse behaves like all)',
         "    if worst_instance > 1 and self.multi_record ~= 'all' then",
         '    if false then',
         TWO_BASE_RECORDS, None,
         lambda r: r['patch_state'] == 'applied'),
        ('the per-instance record count never computed',
         '        worst_instance = math.max(worst_instance, base_by[key].count)',
         '        worst_instance = 0',
         TWO_BASE_RECORDS, 'refuse_policy',
         lambda r: r['patch_state'] == 'applied'),
        ('the field-consistency check removed',
         '    if #base_fields ~= 1 then',
         '    if false then',
         MOVING_FIELD, None,
         lambda r: r['patch_state'] == 'applied'),
        ('the reference-field comparison removed',
         '    if #ref_fields ~= 1 or ref_fields[1] ~= field then',
         '    if false then',
         WRONG_REF_FIELD, None,
         lambda r: r['patch_state'] == 'applied'),
        ('the vehicle read-back verification removed (6.29)',
         '            if ok and after == target_bytes then',
         '            if ok then',
         dict(LYING_WRITER, lying_writer='vehicle'), None,
         lambda r: r['patch_state'] == 'applied'),
        ('the package read-back verification removed (6.29)',
         '            if ok and after == entry.bytes then',
         '            if ok then',
         dict(LYING_WRITER, lying_writer='package'), None,
         lambda r: r['patch_state'] == 'applied'),
        ('the package left swapped when the vehicle write failed',
         '    local rolled = self:undo_orphan_packages()',
         '    local rolled = 0',
         OK_FIXTURE, 'foreign', lambda r: r['package_swapped'] > 0),
        ('the level-load follower disabled (the mission keeps the original car)',
         '    if previous == nil or not (grew and spaced and #fresh > 0) then',
         '    if true then',
         LATE_TABLE, None, lambda r: r['patched_count'] != 2),
        # NOTE: "the follower fires on ordinary churn" is deliberately NOT a mutation
        # here.  Loosening the growth gate alone is masked by the 60 s rate limit, so
        # the mutation would be invisible and would rot into a false green.  The
        # property is pinned by the direct assertion in functional() instead ("only
        # the real level load triggered a re-scan, not the later churn"), which did
        # catch the loose gate the first time it was written.
        ('the pre-write content check removed',
         '        elseif before ~= source_bytes then',
         '        elseif false then',
         OK_FIXTURE, 'foreign',
         lambda r: r['patch_state'] == 'applied'),
        ('the once-per-sweep decision gate removed (spins instead of scanning)',
         '    if self.patch_state == \'idle\' and self.sweeps_done > self.last_decision_sweep then',
         '    if self.patch_state == \'idle\' and self.sweeps >= 0 then',
         {'layout': 'abs', 'count': 8, 'id_at': 5, 'ref_at': 6,
          'strat_in_phase2': True}, None,
         lambda r: r['patch_state'] != 'applied'),
        ('the maintain re-apply disabled',
         '            local ok = self.api.write(target.address, target_bytes)',
         '            local ok = true',
         OK_FIXTURE, 'revert',
         lambda r: r['reapplied_count'] == 0),
        ('the restore on retire removed',
         '        if target.original then',
         '        if false then',
         OK_FIXTURE, None,
         lambda r: r['restore'] == 0),
    ]


def run_mutations():
    print('\n== mutation testing: every mutation must be caught ==')
    original = SOURCE.read_text(encoding='utf-8')
    for label, old, new, kind, hook_kind, broke in mutation_cases():
        if old not in original:
            check('mutation anchor exists: %s' % label, False,
                  'anchor text not found - update the mutation')
            continue
        mutated = original.replace(old, new, 1)
        if mutated == original:
            check('mutation changed the source: %s' % label, False)
            continue
        try:
            # loading is inside the try too: a mutation that breaks the syntax means
            # the addon would not even load, which is a catch in its own right
            session = Session(mutated)
            hook = None
            config = None
            if hook_kind == 'foreign':
                hook = poke_hook(session, 'decided', 'deadbeefdeadbeef')
            elif hook_kind == 'revert':
                hook = poke_hook(session, 'applied', BASE_ID)
            elif hook_kind == 'refuse_policy':
                # this mutation can only be seen under multi_record = refuse
                config = dict(IDENTITY_CONFIG, multi_record='refuse')
            result = session.run(kind, config=config, on_frame=hook)
            check('caught: %s' % label, broke(result),
                  'state=%s patched=%s reapplied=%s restore=%s'
                  % (result['patch_state'], result['patched_count'],
                     result['reapplied_count'], result['restore']))
        except Exception as exc:            # a mutation that crashes is caught too
            check('caught (raised): %s' % label, True)
            print('        raised: %s' % exc)


def main():
    syntax_gate()
    config_tests()
    functional()
    run_mutations()
    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
