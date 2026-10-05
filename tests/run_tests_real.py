"""Run the whole identification + patch against REAL game table bytes.

Every other fixture is synthetic, which means they all share my assumptions about
what a settings table looks like.  This one does not: it starts from
`generated_projectile_settings.dl_bin` - a real, FileDiver-decoded settings table
(93340 bytes, DLArray descriptor <16, 343>, 343 records of 272 bytes) - and only
changes the two things the test needs:

  * the LDLD type tag, so the addon treats it as a stratagem table;
  * two of the 343 real records, to carry the M-102 and M-103 unit ids.

Everything else - the header, the descriptor, the stride, the record contents - is
the game's own bytes.  If the addon's model of a settings table were wrong in any
way, this test would fail while every synthetic fixture still passed.

    python tests/run_tests_real.py
"""
import gzip
import struct
import sys
import tempfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'
HARNESS = HERE / 'harness.lua'
MIRROR = REPO.parent / 'filediver' / 'datalibrary'

STRATAGEM_TYPE = 0x30eb6399
PROJECTILE_STRIDE = 272
FIELD = 112
BASE_ID = 0xcc21c7ffd3ebefb9
SUPPLY_ID = 0x9b2140378640432e
HEAVY_ID = 0x2d85bfe3d8717fe5
RECORD_BASE = 200
RECORD_SUPPLY = 250
RECORD_HEAVY = 300
# the package field, live-measured at record +168 (see the harness for the proof)
PACKAGE_FIELD = 168
PACKAGE_BASE = 0x1111111111111111
PACKAGE_TARGET = 0x2222222222222222

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


def real_table():
    path = MIRROR / 'generated_projectile_settings.dl_bin.gz'
    if path.exists():
        data = gzip.decompress(path.read_bytes())
    else:
        data = (MIRROR / 'generated_projectile_settings.dl_bin').read_bytes()
    return bytearray(data)


def shape(data):
    magic = data.find(b'LDLD')
    return {
        'magic': magic,
        'version': struct.unpack_from('<I', data, magic + 4)[0],
        'type_hash': struct.unpack_from('<I', data, magic + 8)[0],
        'size': struct.unpack_from('<I', data, magic + 12)[0],
        'records_offset': struct.unpack_from('<Q', data, magic + 24)[0],
        'count': struct.unpack_from('<Q', data, magic + 32)[0],
        'records_at': magic + 24 + struct.unpack_from('<Q', data, magic + 24)[0],
    }


def build_image(*, absolute_pointer):
    data = real_table()
    info = shape(data)
    assert info['version'] == 1
    assert info['records_offset'] == 16
    assert info['count'] == 343
    assert len(data) - info['records_at'] == info['count'] * PROJECTILE_STRIDE

    # the two edits the test needs, and nothing else
    struct.pack_into('<I', data, info['magic'] + 8, STRATAGEM_TYPE)
    records_at = info['records_at']
    struct.pack_into('<Q', data, records_at + RECORD_BASE * PROJECTILE_STRIDE + FIELD,
                     BASE_ID)
    struct.pack_into('<Q', data, records_at + RECORD_SUPPLY * PROJECTILE_STRIDE + FIELD,
                     SUPPLY_ID)
    # The live table carries the M-104 record beside the M-102 one, and the package
    # hash the game loads the stratagem's assets from sits at record +168 (measured:
    # 70 of 100 live records match the community dump's `package` at exactly +168).
    # Without the donor record there is no package to copy and the patcher refuses -
    # swapping the vehicle alone is what crashed the live game on call-in.
    struct.pack_into('<Q', data, records_at + RECORD_HEAVY * PROJECTILE_STRIDE + FIELD,
                     HEAVY_ID)
    struct.pack_into('<Q',
                     data, records_at + RECORD_BASE * PROJECTILE_STRIDE + PACKAGE_FIELD,
                     PACKAGE_BASE)
    struct.pack_into('<Q',
                     data, records_at + RECORD_HEAVY * PROJECTILE_STRIDE + PACKAGE_FIELD,
                     PACKAGE_TARGET)
    if absolute_pointer:
        # in memory the descriptor's first u64 is an absolute address, not the file's
        # relative 16 (skill 6.13) - model both, because the addon has to handle both
        struct.pack_into('<Q', data, info['magic'] + 24, 0)
    return data, info


class Session:
    def __init__(self, addon_source):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.HARNESS_SOURCE = HARNESS.read_text(encoding='utf-8')
        g.ADDON_SOURCE = addon_source
        g.DshFrvM104Test = True
        self.lua.execute(
            "local chunk = assert(load(HARNESS_SOURCE, '@harness')); M = chunk();"
            "local addon = assert(load(ADDON_SOURCE, '@addon')); R = addon();"
        )
        self.M, self.R, self.g = g.M, g.R, g

    def run(self, path, base, require_reference=False):
        kind = self.lua.table()
        kind['no_strat'] = True
        raw = self.lua.table()
        entry = self.lua.table()
        entry['base'] = base
        entry['path'] = str(path)
        raw[1] = entry
        kind['raw_regions'] = raw
        opts = self.lua.table()
        cfg = self.lua.table()
        cfg['enabled'] = True
        cfg['apply'] = True
        cfg['restore_on_shutdown'] = True
        cfg['require_reference'] = require_reference
        cfg['multi_record'] = 'all'
        cfg['source'] = 'real-data test'
        opts['config'] = cfg
        return self.M.run(self.R, kind, opts)


def with_temp_image(absolute_pointer):
    data, info = build_image(absolute_pointer=absolute_pointer)
    # the fixture path must be ASCII: Lua's fopen cannot open a non-ASCII path
    handle = tempfile.NamedTemporaryFile(suffix='.dl_bin', delete=False)
    handle.write(bytes(data))
    handle.close()
    return Path(handle.name), info, data


def main():
    data, info = build_image(absolute_pointer=False)
    print('== the fixture really is the game\'s own table ==')
    check('it is a version-1 LDLD instance', info['version'] == 1)
    check('size == 16 + 343 * 272 (the real shape)',
          info['size'] == 16 + 343 * PROJECTILE_STRIDE, info['size'])
    check('the descriptor holds the relative offset 16',
          info['records_offset'] == 16)
    check('the record count is the real 343', info['count'] == 343)
    check('the file is exactly header + records',
          len(data) - info['records_at'] == info['count'] * PROJECTILE_STRIDE)

    session = Session(SOURCE.read_text(encoding='utf-8'))

    for label, absolute in (('file image (relative offset)', False),
                            ('memory image (absolute pointer)', True)):
        print('\n== end-to-end against %s ==' % label)
        path, info, _ = with_temp_image(absolute)
        try:
            base = 0x500000000
            if absolute:
                # point the descriptor at the real records address in fake memory:
                # region base + (magic + 24 + 16) - the addon's magic address is
                # base + info['magic']
                records_va = base + info['records_at']
                patched = bytearray(path.read_bytes())
                struct.pack_into('<Q', patched, info['magic'] + 24, records_va)
                path.write_bytes(bytes(patched))
            r = session.run(path, base)

            hits = r['strat_lines']
            check('the table was found and parsed', r['strat_count'] == 1,
                  'instances=%s' % r['strat_count'])
            check('the real stride 272 was the accepted hypothesis',
                  'hypothesis stride=272' in hits, hits[:400])
            check('the real record count 343 was read', 'count=343' in hits)
            check('the M-102 id was found in real record %d' % RECORD_BASE,
                  'frv_base' in hits and 'record=%d' % RECORD_BASE in hits,
                  hits[-600:])
            check('the M-103 reference was found in real record %d' % RECORD_SUPPLY,
                  'frv_supply' in hits and 'record=%d' % RECORD_SUPPLY in hits,
                  hits[-600:])
            check('the field offset is +%d' % FIELD, r['patch_field'] == FIELD,
                  r['patch_field'])
            check('the gate confirmed and the patch applied',
                  r['patch_state'] == 'applied' and r['patched_count'] == 1,
                  '%s / %s' % (r['patch_state'], r['patch_reason']))
            check('exactly one real vehicle write plus its package reached memory',
                  r['write_ok'] == 2 and r['package_swapped'] == 1,
                  'writes=%s packages=%s' % (r['write_ok'], r['package_swapped']))
            check('the original bytes were restored on retire',
                  r['restore'] == 1 and r['after_restore'] == 'b9efebd3ffc721cc',
                  '%s / %s' % (r['restore'], r['after_restore']))
            check('no ANALYSIS_ERROR anywhere',
                  'ANALYSIS_ERROR' not in hits, hits[:400])
        finally:
            path.unlink(missing_ok=True)

    print('\n== with the M-103 reference blanked out ==')
    data, info = build_image(absolute_pointer=False)
    struct.pack_into('<Q', data, info['records_at']
                     + RECORD_SUPPLY * PROJECTILE_STRIDE + FIELD, 0)
    handle = tempfile.NamedTemporaryFile(suffix='.dl_bin', delete=False)
    handle.write(bytes(data))
    handle.close()
    path = Path(handle.name)
    try:
        r = session.run(path, 0x500000000)
        check('a unique M-102 unit id is enough: the patch still applies',
              r['patch_state'] == 'applied' and r['patched_count'] == 1,
              '%s / %s' % (r['patch_state'], r['patch_reason']))
        check('and the confidence is reported honestly',
              r['patch_confidence'] == 'reference_absent', r['patch_confidence'])
    finally:
        path.unlink(missing_ok=True)

    print('\n== and require_reference = true refuses that same table ==')
    data, info = build_image(absolute_pointer=False)
    struct.pack_into('<Q', data, info['records_at']
                     + RECORD_SUPPLY * PROJECTILE_STRIDE + FIELD, 0)
    handle = tempfile.NamedTemporaryFile(suffix='.dl_bin', delete=False)
    handle.write(bytes(data))
    handle.close()
    path = Path(handle.name)
    try:
        r = session.run(path, 0x500000000, require_reference=True)
        check('refused, and nothing was written',
              r['patch_state'] == 'refused' and r['write_ok'] == 0,
              '%s / writes=%s' % (r['patch_state'], r['write_ok']))
    finally:
        path.unlink(missing_ok=True)

    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
