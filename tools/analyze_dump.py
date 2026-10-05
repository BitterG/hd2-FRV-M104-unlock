"""Re-derive the stratagem table layout from a run's raw hex dump.

When the addon refuses, the useful artefact is
`frv_m104_stratagem_dump.txt`: the full bytes of every resident StratagemSettings
instance.  This reads that file and works out the layout *independently* of the
addon's own conclusions - same inputs, separate arithmetic - so a disagreement
between the two is itself a finding.

It answers, from the bytes alone:

  * how many instances there are, their size, and their DLArray descriptor,
  * which record stride the `type` column supports (scored over every 8-byte
    candidate in a plausible range, exactly as the addon does, but from the dump),
  * where each FRV id sits: inline in a record, or inside a nested array the record
    points at, and the resulting (record, field) pair,
  * the constants to bake into the addon if it needs fixing.

    python tools/analyze_dump.py [log-dir]
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

IDS = {
    'frv_base': 0xcc21c7ffd3ebefb9,
    'frv_supply': 0x9b2140378640432e,
    'frv_heavy': 0x2d85bfe3d8717fe5,
    'delivery': 0x75be82ed8592a6b3,
}
STRIDE_MIN, STRIDE_MAX = 200, 800
STRIDE_HINT = 312

HEADER = re.compile(
    r'^#\s*full StratagemSettings instance at 0x(?P<addr>[0-9A-Fa-f]+)\s+'
    r'size=(?P<size>\d+)\s+\(read (?P<read>\d+) bytes from 0x(?P<base>[0-9A-Fa-f]+)\)')
HEXLINE = re.compile(r'^0x(?P<addr>[0-9A-Fa-f]+)\s+(?P<hex>[0-9a-fA-F]+)\s*$')


def parse_dump(text):
    """-> list of {base, size, data} built from the hex block."""
    out = []
    current = None
    for line in text.splitlines():
        match = HEADER.match(line)
        if match:
            current = {'base': int(match.group('base'), 16),
                       'size': int(match.group('size')),
                       'chunks': {}}
            out.append(current)
            continue
        if current is None:
            continue
        match = HEXLINE.match(line)
        if match:
            at = int(match.group('addr'), 16)
            current['chunks'][at] = bytes.fromhex(match.group('hex'))
    for item in out:
        if not item['chunks']:
            continue
        start = min(item['chunks'])
        end = max(item['chunks']) + len(item['chunks'][max(item['chunks'])])
        data = bytearray(end - start)
        for at, chunk in item['chunks'].items():
            data[at - start:at - start + len(chunk)] = chunk
        item['origin'] = start
        item['data'] = bytes(data)
    return [item for item in out if item.get('data')]


def u32(data, at):
    return int.from_bytes(data[at:at + 4], 'little')


def u64(data, at):
    return int.from_bytes(data[at:at + 8], 'little')


def score_stride(payload, count, stride):
    total = in_range = 0
    seen = set()
    for index in range(count):
        at = index * stride
        if at + 4 > len(payload):
            break
        value = u32(payload, at)
        total += 1
        if 1 <= value <= 4096:
            in_range += 1
        seen.add(value)
    if total == 0:
        return 0.0, 0.0, 0
    return in_range / total, len(seen) / total, total


def occurrences(payload, value):
    needle = value.to_bytes(8, 'little')
    out, pos = [], 0
    while True:
        at = payload.find(needle, pos)
        if at < 0:
            return out
        if at % 8 == 0:
            out.append(at)
        pos = at + 1


def attribute(instance, stride):
    """(record, field, how) for each id, following nested pointers one level."""
    payload = instance['payload']
    count = instance['count']
    found = {}
    for label, value in IDS.items():
        found[label] = []
    nested = {}
    for record in range(count):
        base = record * stride
        if base + stride > len(payload):
            break
        chunk = payload[base:base + stride]
        for label, value in IDS.items():
            for at in occurrences(chunk, value):
                found[label].append((record, at, 'inline'))
        for offset in range(0, stride - 8, 8):
            pointer = int.from_bytes(chunk[offset:offset + 8], 'little')
            if pointer == 0:
                continue
            target = None
            if instance['payload_start'] <= pointer < instance['payload_end']:
                target = pointer
            elif 16 <= pointer < len(payload):
                target = instance['payload_start'] + pointer
            if target is None:
                continue
            target -= instance['payload_start']
            if not (0 <= target < len(payload)):
                continue
            if target in nested:
                continue
            nested[target] = (record, offset)
            window = payload[target:target + 256]
            for label, value in IDS.items():
                for at in occurrences(window, value):
                    found[label].append((record, at, 'nested@+%d' % offset))
    return found


def main():
    log_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path.home() / 'AppData/Local/CowboyBingus/Helldivers2/Logs')
    dump_path = log_dir / 'frv_m104_stratagem_dump.txt'
    text_path = log_dir / 'frv_m104_stratagem.txt'
    if not dump_path.exists():
        print('no %s' % dump_path)
        print('(the addon writes it on every run, including refused ones)')
        return 1

    instances = parse_dump(dump_path.read_text(encoding='utf-8', errors='replace'))
    print('parsed %d instance image(s) from %s' % (len(instances), dump_path.name))
    if text_path.exists():
        hits = [line.strip() for line in
                text_path.read_text(encoding='utf-8', errors='replace').splitlines()
                if 'RECORD_HIT' in line or 'whole-payload' in line]
        print('the addon itself reported %d hit/scan line(s)' % len(hits))
        for line in hits[:12]:
            print('    ' + line)
    print()

    for index, instance in enumerate(instances, 1):
        data = instance['data']
        origin = instance['origin']
        magic = origin + 4                     # the dump starts at magic-4
        if data[4:8] != b'LDLD':
            print('== instance %d at %#x: no LDLD marker where expected'
                  % (index, magic))
            continue
        size = u32(data, 16)
        payload_start = magic + 24
        descriptor_ptr = u64(data, 28)
        count = u64(data, 36)
        print('== instance %d: magic=0x%X declared_size=%d count=%d '
              'descriptor_u64_0=0x%X' % (index, magic, size, count,
                                         descriptor_ptr))
        array_start = None
        if payload_start <= descriptor_ptr < payload_start + size:
            array_start = descriptor_ptr
        else:
            array_start = payload_start + 16
        payload = data[array_start - origin:]
        if not payload:
            print('   (no payload bytes in the dump)')
            continue
        instance['payload'] = payload
        instance['payload_start'] = payload_start
        instance['payload_end'] = payload_start + size
        instance['count'] = count

        flat = {label: occurrences(payload, value) for label, value in IDS.items()}
        print('   flat payload scan: ' + '  '.join(
            '%s=%d[%s]' % (label, len(at), ' '.join('+%#x' % a for a in at[:4]))
            for label, at in flat.items()))

        scored = []
        for stride in range(STRIDE_MIN, STRIDE_MAX + 1, 8):
            in_range, distinct, total = score_stride(payload, count, stride)
            scored.append((in_range, distinct, stride, total))
        scored.sort(key=lambda item: (-item[0], -item[1],
                                      abs(item[2] - STRIDE_HINT)))
        print('   best strides: ' + ', '.join(
            '%d(%.2f/%.2f)' % (s[2], s[0], s[1]) for s in scored[:5]))

        for in_range, distinct, stride, total in scored[:3]:
            if in_range < 0.5 and stride != STRIDE_HINT:
                continue
            result = attribute(instance, stride)
            if any(result[label] for label in IDS):
                print('   with stride %d:' % stride)
                for label in IDS:
                    for record, field, how in result[label][:6]:
                        print('      %-11s record=%-4d field=+%-5d %s'
                              % (label, record, field, how))
        print()

    print('if the ids are inline at a consistent field, bake that number in;')
    print('if every stride fails, the record start is wrong - look at')
    print('descriptor_u64_0 above and compare it with magic+24+16.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
