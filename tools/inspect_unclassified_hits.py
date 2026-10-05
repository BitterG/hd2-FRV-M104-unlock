"""What are the ~81 'unclassified' frv_base hits really?

Either the game genuinely holds dozens of copies of the FRV unit id outside any
LDLD table (per-player loadout entries, vehicle manager slots, ...), or the sweep is
finding the ADDON'S OWN pattern strings on the Lua heap - the addon builds every id
as a raw 8-byte Lua string, so its own heap is full of them and `self_hits_skipped=0`
says the self-detection never fired.  The bytes around a hit tell the two apart: a
Lua heap hit sits next to other raw id strings and Lua object headers, while a real
structure looks like a record.

    python tools/inspect_unclassified_hits.py <log dir> [address ...]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HDR = re.compile(r"^hit label=(\S+)\s+address=(0x[0-9A-Fa-f]+)\s+kind=(\S+)\s+where=(\S+)")
DUMP_HDR = re.compile(
    r"^#\s+(\S+)\s+address=(0x[0-9A-Fa-f]+)\s+base=(0x[0-9A-Fa-f]+)\s+"
    r"bytes=(\d+)\s+frame=(\d+)\s+where=(\S+)")
CHUNK = re.compile(r"^(0x[0-9A-Fa-f]+)\s+([0-9A-Fa-f ]+)$")


def load_hits(text: str):
    hits, cur = [], None
    for line in text.splitlines():
        m = HDR.match(line) or DUMP_HDR.match(line)
        if m:
            cur = {"label": m.group(1), "address": int(m.group(2), 16),
                   "lines": []}
            hits.append(cur)
            continue
        if cur is not None:
            c = CHUNK.match(line.strip())
            if c:
                cur["lines"].append((int(c.group(1), 16),
                                     bytes.fromhex(c.group(2).replace(" ", ""))))
    return hits


def ascii_of(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def main() -> int:
    logdir = Path(sys.argv[1])
    wanted = [int(a, 16) for a in sys.argv[2:]]
    dumps = load_hits((logdir / "frv_m104_dump.txt").read_text(
        encoding="utf-8", errors="replace"))
    base = load_hits((logdir / "frv_m104_hits.txt").read_text(
        encoding="utf-8", errors="replace"))
    print(f"dump windows: {len(dumps)}, hit records: {len(base)}")
    unclassified = [h for h in base
                    if "unclassified" in str(h.get("where", "")) or True]
    unclassified = [h for h in base if h["label"] == "frv_base"]
    print(f"frv_base hits: {len(unclassified)}")

    flat = {}
    for d in dumps:
        for at, data in d["lines"]:
            flat[at] = data

    def window(address: int, before: int = 32, after: int = 96):
        out = bytearray()
        start = address - before
        size = before + after
        for at in range(start, start + size, 16):
            chunk = flat.get(at)
            if chunk is None:
                return None
            out += chunk
        return bytes(out)

    picks = wanted or [h["address"] for h in unclassified[:6]]
    for address in picks:
        print(f"\n=== {address:#x} ===")
        w = window(address)
        if w is None:
            print("  (this hit was not among the ones dumped)")
            continue
        for i in range(0, len(w), 16):
            at = address - 32 + i
            mark = "  <-- hit" if at <= address < at + 16 else ""
            print(f"  {at:#018x}  {w[i:i + 16].hex()}  {ascii_of(w[i:i + 16])}{mark}")

    print("\n=== how many raw id strings sit within one 1 KB dumped window ===")
    ids = {"frv_base": "b9efebd3ffc721cc", "frv_heavy": "e57f71d8e3bf852d",
           "frv_supply": "2e4340863740219b", "delivery": "b3a69285ed82be75"}
    for h in unclassified[:24]:
        address = h["address"]
        near = {}
        for at, data in flat.items():
            if address - 1024 <= at <= address + 1024:
                for label, hexid in ids.items():
                    c = data.count(bytes.fromhex(hexid))
                    if c:
                        near[label] = near.get(label, 0) + c
        print(f"  {address:#018x}  {near if near else 'no ids nearby'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
