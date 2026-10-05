"""Prove the live record field map against the community plaintext schema.

The community dump `generated_stratagem_settings.json` names every field and
gives its exact value. Records in the live game memory can be matched by `id`
(record +4), and then the JSON's 64-bit fields (package / icon / payload) are
located inside the live 400-byte record body by value. That both proves the
field order (payload -> package -> icon) and pins the exact offset of `package`,
which the patcher must also swap when the payload unit is swapped.
"""

from __future__ import annotations

import io
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import diff_frv_records as D  # noqa: E402

JSON_PATH = Path(r"C:\Users\kugua\Desktop\hd2-mod\work\hddata\data\settings\generated_stratagem_settings.json")
STRIDE = 400


def load_community() -> dict[int, dict]:
    data = json.load(io.open(JSON_PATH, encoding="utf-8"))
    out = {}
    for inst in data:
        for it in inst["StratagemSettings"]["items"]:
            out[int(it["id"])] = it
    return out


def find_u64(body: bytes, value: int) -> list[int]:
    if value == 0:
        return []
    pat = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    hits, start = [], 0
    while True:
        i = body.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    return hits


def main() -> int:
    dump = Path(sys.argv[1])
    mem = D.parse_dump(dump)
    community = load_community()
    print(f"community records: {len(community)}")

    # every instance in the dump, in file order
    instances = []
    for raw in dump.read_text(encoding="utf-8", errors="replace").splitlines():
        m = D.HDR_RE.match(raw)
        if m:
            instances.append(int(m.group(1), 16))
    print(f"live instances in dump: {len(instances)}")

    offset_hits: dict[str, list[str]] = {}
    matched = 0
    for magic in instances:
        payload_start, records_start, count = D.find_instance(mem, magic)
        if count > 40:
            continue
        for i in range(count):
            base = records_start + i * STRIDE
            body = D.read(mem, base, STRIDE)
            if body is None:
                continue
            rid = struct.unpack_from("<I", body, 4)[0]
            if rid not in community:
                continue
            it = community[rid]
            matched += 1
            pkg = int(it.get("package") or 0)
            icon = int(it.get("icon") or 0)
            for name, val in (("package", pkg), ("icon", icon)):
                for off in find_u64(body, val):
                    offset_hits.setdefault(f"{name}@{off}", []).append(
                        f"id={rid} type={it.get('type')} @{base + off:#x}")
            for k, v in enumerate(it.get("payload") or []):
                v = int(v)
                for off in find_u64(body, v):
                    offset_hits.setdefault(f"payload[{k}]@{off}", []).append(
                        f"id={rid} @{base + off:#x}")

    print(f"\nrecords matched against the community schema: {matched}")
    print("\noffset histogram (community field value found at live body offset):")
    for key in sorted(offset_hits, key=lambda k: (int(k.split("@")[1]), k)):
        names = offset_hits[key]
        print(f"  {key:<18} {len(names):>3}x   e.g. {names[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
