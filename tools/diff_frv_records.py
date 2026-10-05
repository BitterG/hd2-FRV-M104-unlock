#!/usr/bin/env python3
"""Offline whole-record diff of the M-102 vs M-104 StratagemSettings records.

Reads the read-only recon dump `frv_m104_stratagem_dump.txt` (full hex of every
StratagemSettings instance the live game exposed) and reconstructs the record
bodies around the payload pointers the patcher reported, so the two records can
be compared field by field without touching the game again.

Usage:
    python tools/diff_frv_records.py <dump.txt> [--instance 0x...] [--stride 400]
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

LINE_RE = re.compile(r"^(0x[0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s*$")
HDR_RE = re.compile(r"^# full .*?instance at (0x[0-9A-Fa-f]+) size=(\d+)")

PAYLOAD_FIELD = 152  # field offset of the payload pointer inside a stratagem record
IDS = {
    0xCC21C7FFD3EBEFB9: "frv_base (M-102 Gunner)",
    0x9B2140378640432E: "frv_supply (M-103)",
    0x2D85BFE3D8717FE5: "frv_heavy (M-104 Incinerator)",
    0x75BE82ED8592A6B3: "delivery",
    0x99D98C71A5C37AD8: "?",
}


def parse_dump(path: Path) -> dict[int, int]:
    """Return {address: byte} for every byte in the dump.

    Dump lines are 16 bytes wide but are not necessarily 16-byte aligned, so a
    requested address can sit inside a line keyed by a lower address. Storing
    one entry per byte keeps `read` trivial and correct.
    """
    mem: dict[int, int] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(raw.strip())
        if not m:
            continue
        addr = int(m.group(1), 16)
        data = bytes.fromhex(m.group(2))
        for i, b in enumerate(data):
            mem[addr + i] = b
    return mem


def read(mem: dict[int, int], addr: int, n: int) -> bytes | None:
    try:
        return bytes(mem[addr + i] for i in range(n))
    except KeyError:
        return None


def u32(b: bytes) -> int:
    return struct.unpack_from("<I", b)[0]


def u64(b: bytes) -> int:
    return struct.unpack_from("<Q", b)[0]


def lookswise_id(v: int) -> str:
    if v in IDS:
        return IDS[v]
    return ""


def find_instance(mem: dict[int, int], magic: int) -> tuple[int, int, int]:
    """Return (payload_start, records_start, count)."""
    head = read(mem, magic, 64)
    assert head is not None, f"instance at {magic:#x} not in dump"
    assert head[:4] == b"LDLD", f"no LDLD magic at {magic:#x}: {head[:8].hex()}"
    payload_start = magic + 24
    desc = read(mem, payload_start, 16)
    assert desc is not None
    records_start = u64(desc[:8])
    count = u64(desc[8:16])
    return payload_start, records_start, count


def find_pointer_fields(mem: dict[int, int], needle: int, window: tuple[int, int]) -> list[int]:
    """Addresses inside [lo,hi) holding the little-endian u64 `needle`."""
    pat = struct.pack("<Q", needle)
    hits = []
    lo, hi = window
    flat = bytearray()
    base = lo
    for addr in range(lo, hi):
        flat.append(mem.get(addr, 0))
    start = 0
    while True:
        i = flat.find(pat, start)
        if i < 0:
            break
        hits.append(base + i)
        start = i + 1
    return sorted(hits)


def dump_record(mem: dict[int, int], base: int, stride: int, label: str) -> None:
    body = read(mem, base, stride)
    if body is None:
        print(f"    {label}: body unreadable at {base:#x}")
        return
    print(f"    {label} base={base:#x}")
    for off in range(0, stride, 8):
        v = u64(body[off:off + 8])
        w = u32(body[off:off + 4])
        note = []
        name = lookswise_id(v)
        if name:
            note.append(f"ID -> {name}")
        if 0x10000 < v < 0x800000000000 and v % 4 == 0:
            note.append(f"ptr -> {v:#x}")
        if not note and v == 0:
            continue
        f32 = struct.unpack_from("<f", body[off:off + 4])[0]
        f32s = ""
        if v and abs(f32) > 1e-6 and abs(f32) < 1e9 and (v >> 32) == 0:
            f32s = f" f32={f32:g}"
        print(f"      +{off:<4} u64={v:#018x} u32={w:#010x} {(' '.join(note) + f32s).strip()}")


def dump_pointer_target(mem: dict[int, int], name: str, off: int, addr: int, indent: str = "        ") -> None:
    if not (0x10000 < addr < 0x800000000000):
        return
    head = read(mem, addr, 64)
    if head is None:
        print(f"{indent}+{off:<4} -> {addr:#x} (outside dump)")
        return
    printable = bytes(b if 32 <= b < 127 or b == 0 else 0x2E for b in head[:48])
    text = printable.split(b"\x00")[0].decode("ascii", "replace")
    vals = [u64(head[i:i + 8]) for i in range(0, 64, 8)]
    pretty = []
    for i, v in enumerate(vals):
        n = lookswise_id(v)
        pretty.append(f"[{i * 8}]{v:#x}" + (f"({n})" if n else ""))
    if len(text) >= 6:
        print(f"{indent}+{off:<4} -> {addr:#x} str={text!r}")
    else:
        print(f"{indent}+{off:<4} -> {addr:#x} {head.hex()}  {' '.join(pretty)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", type=Path)
    ap.add_argument("--instance", default="0x2ADF1CA206C")
    ap.add_argument("--stride", type=int, default=400)
    ap.add_argument("--m102-payload", default="0x2ADF1CA3564")
    args = ap.parse_args()

    mem = parse_dump(args.dump)
    if not mem:
        print("empty dump", file=sys.stderr)
        return 2
    lo = min(mem)
    hi = max(mem) + 1
    print(f"dump covers {lo:#x}..{hi:#x} ({len(mem)} bytes)")

    magic = int(args.instance, 16)
    payload_start, records_start, count = find_instance(mem, magic)
    print(f"\ninstance {magic:#x}: payload={payload_start:#x} records_start={records_start:#x} count={count}")

    # The patcher reported the payload array address; find the pointer field that
    # holds it, which localises record 0 exactly.
    target = int(args.m102_payload, 16)
    ptr_fields = find_pointer_fields(mem, target, (magic, magic + 0x2000))
    print(f"pointer fields holding {target:#x}: {[hex(p) for p in ptr_fields]}")
    if not ptr_fields:
        print("cannot localise record 0", file=sys.stderr)
        return 3

    ptr_field = ptr_fields[0]
    base0 = ptr_field - PAYLOAD_FIELD
    print(f"record 0 base = {base0:#x} (pointer field {ptr_field:#x} - {PAYLOAD_FIELD})")

    labels: list[dict[int, list[str]]] = []
    follow: list[tuple[int, int, list[str]]] = []  # (record, field_offset, ids)
    for i in range(count):
        body = read(mem, base0 + i * args.stride, args.stride)
        found: dict[int, list[str]] = {}
        if body:
            for off in range(0, args.stride, 8):
                v = u64(body[off:off + 8])
                if not (0x10000 < v < 0x800000000000 and v % 4 == 0):
                    continue
                head = read(mem, v, 96)
                if head is None:
                    continue
                ids = [lookswise_id(u64(head[k:k + 8])) for k in range(0, 96, 8)]
                ids = [x for x in ids if x]
                if ids:
                    found[off] = ids
                    follow.append((i, off, ids))
        labels.append(found)

    print("\nrecords in this instance, labelled by following their pointer fields:")
    for i, found in enumerate(labels):
        if not found:
            print(f"  record {i} @{base0 + i * args.stride:#x}: (no id-bearing pointer)")
            continue
        parts = [f"+{off}->{'/'.join(ids)}" for off, ids in sorted(found.items())]
        print(f"  record {i} @{base0 + i * args.stride:#x}: {'  '.join(parts)}")

    interesting = sorted({r for r, _, _ in follow if any("frv_" in s for _, ids in labels[r].items() for s in ids)})
    print(f"\nFRV-bearing records: {interesting}")

    for i in interesting:
        dump_record(mem, base0 + i * args.stride, args.stride, f"record {i}")
        print()

    if 0 in interesting and len(interesting) > 1:
        a = read(mem, base0, args.stride)
        for j in interesting:
            if j == 0:
                continue
            b = read(mem, base0 + j * args.stride, args.stride)
            print(f"=== field-by-field diff: record 0 (M-102) vs record {j} ===")
            for off in range(0, args.stride, 8):
                va = u64(a[off:off + 8])
                vb = u64(b[off:off + 8])
                if va != vb:
                    na, nb = lookswise_id(va), lookswise_id(vb)
                    print(f"  +{off:<4} {va:#018x} -> {vb:#018x} {na}{nb}")
            print()

    print("=== every pointer target, with the ids it holds ===")
    for i in interesting:
        body = read(mem, base0 + i * args.stride, args.stride)
        print(f"  record {i}:")
        for off in range(0, args.stride, 8):
            v = u64(body[off:off + 8])
            if 0x10000 < v < 0x800000000000 and v % 4 == 0:
                dump_pointer_target(mem, f"record{i}", off, v)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
