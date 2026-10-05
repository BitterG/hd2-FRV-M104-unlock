"""Name every live record offset from the community plaintext schema.

For each live StratagemSettings record that can be matched to the community dump
by `id` (record +4), every scalar field of the community record is searched for
inside the 400-byte body as a little-endian u32 and u64.  Aggregating over ~100
matched records turns "field order in the JSON" into a measured offset table, so
a field like `package` is proven rather than assumed.
"""

from __future__ import annotations

import io
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import diff_frv_records as D  # noqa: E402

JSON_PATH = Path(r"C:\Users\kugua\Desktop\hd2-mod\work\hddata\data\settings\generated_stratagem_settings.json")
STRIDE = 400
SCALARS = (4, 8)


def load_community() -> dict[int, dict]:
    data = json.load(io.open(JSON_PATH, encoding="utf-8"))
    out = {}
    for inst in data:
        for it in inst["StratagemSettings"]["items"]:
            out[int(it["id"])] = it
    return out


def find_int(body: bytes, value: int, width: int) -> list[int]:
    if value <= 0 or value >= (1 << (width * 8)):
        return []
    pat = value.to_bytes(width, "little")
    hits, start = [], 0
    while True:
        i = body.find(pat, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def main() -> int:
    dump = Path(sys.argv[1])
    mem = D.parse_dump(dump)
    community = load_community()
    instances = [int(m.group(1), 16)
                 for m in (D.HDR_RE.match(l)
                           for l in dump.read_text(encoding="utf-8", errors="replace").splitlines())
                 if m]

    # key -> {(width, offset): [count, example]}
    table: dict[str, dict[tuple[int, int], list]] = defaultdict(lambda: defaultdict(list))
    matched = 0
    for magic in instances:
        _payload, records_start, count = D.find_instance(mem, magic)
        if count > 40:
            continue
        for i in range(count):
            base = records_start + i * STRIDE
            body = D.read(mem, base, STRIDE)
            if body is None:
                continue
            rid = struct.unpack_from("<I", body, 4)[0]
            it = community.get(rid)
            if it is None:
                continue
            matched += 1
            for key, value in it.items():
                if not isinstance(value, int):
                    continue
                for width in SCALARS:
                    for off in find_int(body, value, width):
                        table[key][(width, off)].append(rid)

    print(f"matched records: {matched}\n")
    print("field -> measured offset (u32/u64), by number of records confirming it")
    for key in sorted(table):
        entries = sorted(table[key].items(), key=lambda kv: -len(kv[1]))
        parts = []
        for (width, off), rids in entries[:4]:
            parts.append(f"u{width * 8}@{off}({len(rids)}x)")
        print(f"  {key:<34} {'  '.join(parts)}")

    print("\n--- fields that landed at exactly one offset in >=20 records ---")
    for key in sorted(table):
        for (width, off), rids in sorted(table[key].items(), key=lambda kv: -len(kv[1])):
            if len(rids) >= 20 and len(table[key]) <= 4:
                print(f"  {key:<34} u{width * 8} @ +{off:<4} ({len(rids)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
