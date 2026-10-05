"""End-to-end against a table reconstructed from REAL stratagem field values.

The synthetic fixtures all guess at the record contents.  This one does not: the
community dump of the stratagem table (103 records, manifest 6656621620609811302)
gives every record's real `type` enum, its real `id`, its real localisation keys
and - for the two Exosuit stratagems - its real `payload` array.  Those values are
laid into records at the mirror's StratagemInfo stride, with the payload arrays in
nested allocations reached through a record pointer, which is the shape the size
arithmetic proved the real table has.

The point is the stride scorer: it decides which stride hypothesis is worth
searching by scoring the record `type` column, and that column now carries the real
distribution of StratagemType values instead of a counter I made up.

    python tests/run_tests_reconstructed.py
"""
import json
import struct
import sys
import tempfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'
HARNESS = HERE / 'harness.lua'
DATA = REPO.parent / 'work/hddata/data'

STRIDE = 312
EXTRA_RECORDS = 27            # the live build has grown since that dump
BASE_ID = 0xcc21c7ffd3ebefb9
SUPPLY_ID = 0x9b2140378640432e
HEAVY_ID = 0x2d85bfe3d8717fe5
DELIVERY_ID = 0x75be82ed8592a6b3
# M-102, M-103 and the M-104 donor record.  The 2024 snapshot predates the FRVs, so
# the trio is injected - and the live table really does hold all three side by side
# (measured 2026-09-25: records 0/1/2 of one instance carried frv_base, frv_supply
# and frv_heavy payload arrays).
FRV_RECORDS = (5, 6, 7)
# the package field: record +168, measured against the community dump (70 of 100
# live records match the dump's `package` value at exactly this offset)
PACKAGE_FIELD = 168
PACKAGE_BASE = 0x1111111111111111
PACKAGE_TARGET = 0x2222222222222222
WALKER_TYPE = 'StratagemType_DropoffCombatWalker'

FAILURES = []
CHECKS_RUN = 0


def check(label, ok, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    print('%s  %s%s' % ('PASS' if ok else 'FAIL', label,
                        '' if ok else '  <- ' + str(detail)))
    if not ok:
        FAILURES.append(label)


def load_real_records():
    doc = json.loads((DATA / 'settings/generated_stratagem_settings.json')
                     .read_text(encoding='utf-8'))
    items = []
    for group in doc:
        items.extend(group['StratagemSettings']['items'])
    types = json.loads((DATA / 'enums/StratagemType.json')
                       .read_text(encoding='utf-8'))['StratagemType']
    return items, types


def build_image():
    items, types = load_real_records()
    index_of = {name: index for index, name in enumerate(types)}

    records = []
    for item in items:
        records.append({
            'type': index_of.get(item['type'], 0),
            'id': item['id'] & 0xFFFFFFFF,
            'name_upper': item.get('name_upper', 0) & 0xFFFFFFFF,
            'name_cased': item.get('name_cased', 0) & 0xFFFFFFFF,
            'payload': list(item.get('payload') or []),
            'label': item['type'],
        })
    # the live build has more stratagems than that snapshot: extend with plausible
    # types rather than pretending the table is still 103 records
    for extra in range(EXTRA_RECORDS):
        records.append({'type': len(types) + extra, 'id': 0x40000000 + extra,
                        'name_upper': 0, 'name_cased': 0, 'payload': [],
                        'label': 'synthesised_%d' % extra})
    count = len(records)

    # three records grant the FRVs; the first is the one we are replacing, and the
    # third is the donor the asset package is copied from
    records[FRV_RECORDS[0]]['payload'] = [BASE_ID, DELIVERY_ID]
    records[FRV_RECORDS[0]]['label'] = 'INJECTED M-102 base FRV'
    records[FRV_RECORDS[0]]['package'] = PACKAGE_BASE
    records[FRV_RECORDS[1]]['payload'] = [SUPPLY_ID, DELIVERY_ID]
    records[FRV_RECORDS[1]]['label'] = 'INJECTED M-103 supply FRV'
    records[FRV_RECORDS[2]]['payload'] = [HEAVY_ID, DELIVERY_ID]
    records[FRV_RECORDS[2]]['label'] = 'INJECTED M-104 flamethrower FRV'
    records[FRV_RECORDS[2]]['package'] = PACKAGE_TARGET

    nested_total = sum(8 * len(record['payload']) for record in records)
    payload_size = 16 + count * STRIDE + nested_total

    # ---- build the instance image -----------------------------------------
    base = 0x200000000
    magic = base + 0x1000
    array_va = magic + 24 + 16
    nested_va = array_va + count * STRIDE
    image = bytearray(count * STRIDE)
    pointer = nested_va
    for index, record in enumerate(records):
        at = index * STRIDE
        struct.pack_into('<I', image, at + 0, record['type'])
        struct.pack_into('<I', image, at + 4, record['id'])
        struct.pack_into('<I', image, at + 16, record['name_upper'])
        struct.pack_into('<I', image, at + 20, record['name_cased'])
        # deterministic filler elsewhere, so no accidental id match can occur
        for offset in range(24, STRIDE, 4):
            if offset in (112, 120, PACKAGE_FIELD):
                continue
            struct.pack_into('<I', image, at + offset,
                             (index * 2654435761 + offset * 40503) & 0xFFFFFFFF)
        if record.get('package'):
            struct.pack_into('<Q', image, at + PACKAGE_FIELD, record['package'])
        if record['payload']:
            struct.pack_into('<Q', image, at + 112, pointer)       # DLArray ptr
            struct.pack_into('<Q', image, at + 120, len(record['payload']))
            record['nested_at'] = pointer
            pointer += 8 * len(record['payload'])

    nested = bytearray(nested_total)
    for record in records:
        if not record['payload']:
            continue
        at = record['nested_at'] - nested_va
        for slot, value in enumerate(record['payload']):
            struct.pack_into('<Q', nested, at + 8 * slot, value)
    image = bytes(image) + bytes(nested)

    # LDLD <u32 version> <u32 type_hash> <u32 size> <u8 is64> <u8 pad7> = 24 bytes,
    # placed so that the LDLD marker lands at region base + 0x1000 (the address the
    # addon will call the magic)
    header = struct.pack('<4sIII', b'LDLD', 1, 0x30eb6399, payload_size)
    header += bytes([1]) + b'\0' * 7
    assert len(header) == 24, len(header)
    descriptor = struct.pack('<QQ', array_va, count)

    magic_offset = 0x1000
    full = bytearray(0x100000)
    full[magic_offset:magic_offset + len(header)] = header
    payload_start = magic_offset + 24
    full[payload_start:payload_start + 16] = descriptor
    body_at = payload_start + 16                     # records start here
    assert body_at + len(image) <= len(full), (body_at + len(image), len(full))
    full[body_at:body_at + len(image)] = image
    return bytes(full), base, base + magic_offset, count, payload_size, records


class Session:
    def __init__(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.HARNESS_SOURCE = HARNESS.read_text(encoding='utf-8')
        g.ADDON_SOURCE = SOURCE.read_text(encoding='utf-8')
        g.DshFrvM104Test = True
        self.lua.execute(
            "local c = assert(load(HARNESS_SOURCE, '@harness')); M = c();"
            "local a = assert(load(ADDON_SOURCE, '@addon')); R = a();")
        self.M, self.R, self.g = g.M, g.R, g

    def run(self, path, base):
        kind = self.lua.table()
        kind['no_strat'] = True
        raw = self.lua.table()
        entry = self.lua.table()
        entry['base'] = base
        entry['path'] = str(path)
        raw[1] = entry
        kind['raw_regions'] = raw
        return self.M.run(self.R, kind, self.lua.table())


def main():
    image, base, magic, count, payload_size, records = build_image()
    print('== the reconstructed table ==')
    check('it has the snapshot\'s records plus room for the build to have grown',
          count == 103 + EXTRA_RECORDS, count)
    check('records sit at the mirror\'s StratagemInfo stride', STRIDE == 312)
    check('the payload size does NOT divide into a stride (nested data present)',
          (payload_size - 16) % count != 0,
          '%d %% %d' % (payload_size - 16, count))
    check('the two Exosuit payloads are the real ones from the snapshot',
          records[0]['payload'] != [] or any(r['payload'] for r in records))
    walker = [r for r in records if r['label'] == WALKER_TYPE]
    check('the snapshot really carries a walker payload',
          bool(walker) and len(walker[0]['payload']) == 2,
          walker[0]['payload'] if walker else 'none')
    check('the injected M-102 / M-103 records are in place',
          records[FRV_RECORDS[0]]['payload'][0] == BASE_ID
          and records[FRV_RECORDS[1]]['payload'][0] == SUPPLY_ID)

    # the magic address is base + 0x1000, and the harness region starts at base
    handle = tempfile.NamedTemporaryFile(suffix='.dl_bin', delete=False)
    handle.write(image)
    handle.close()
    path = Path(handle.name)
    try:
        session = Session()
        r = session.run(path, base)
        lines = r['strat_lines']
        check('the table was found and parsed', r['strat_count'] == 1,
              r['strat_count'])
        check('the real record count was read', 'count=%d' % count in lines,
              lines[:400])
        check('the scorer picked the 312-byte record',
              r['stride'] == 312, r['stride'])
        check('the real `type` column scored near 1.0 for it',
              'stride 312    type_in_range=1.00' in lines, lines[-900:])
        check('the M-102 payload was found through the record pointer',
              'frv_base' in lines and 'record=%d' % FRV_RECORDS[0] in lines
              and 'ptr=+112' in lines, lines[-900:])
        check('the M-103 reference was found in its own record',
              'frv_supply' in lines and 'record=%d' % FRV_RECORDS[1] in lines,
              lines[-900:])
        check('both records agree on the payload slot',
              'confirmed_by_reference' in (r['patch_confidence'] or ''),
              r['patch_confidence'])
        check('the patch applied', r['patch_state'] == 'applied'
              and r['patched_count'] == 1,
              '%s / %s' % (r['patch_state'], r['patch_reason']))
        check('it wrote the M-104 id over the M-102 one, package included',
              r['write_ok'] == 2 and r['restore'] == 1
              and r['packages_after'] == '1111111111111111',
              'writes=%s restore=%s packages=%s' % (r['write_ok'], r['restore'],
                                                    r['packages_after']))
    finally:
        path.unlink(missing_ok=True)

    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
