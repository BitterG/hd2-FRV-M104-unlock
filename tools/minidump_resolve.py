#!/usr/bin/env python3
"""Second-stage minidump analysis: image coverage, PE export resolution, stack shape.

Uses only the standard library plus the sibling `minidump_crash.py` parser.

  * how many bytes of each loaded module's image are actually captured
  * if a module's PE headers are captured, parse its EXPORT table (no symbol
    server needed - the export names are in the image) and resolve
    `module+offset` to the nearest preceding exported function
  * hexdump of the raw stack around RSP so the EXCEPTION_RECORD /
    CONTEXT_RECORD the kernel pushes for exception delivery can be seen
  * scan the faulted thread's stack for CONTEXT-shaped blobs
  * byte-compare consecutive 0xD00 stack blocks

Usage: python tools/minidump_resolve.py [dump-path]
"""

import bisect
import struct
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import minidump_crash as m  # noqa: E402

DUMP = r"C:\Users\kugua\AppData\Local\CrashDumps\helldivers2.exe.23892.dmp"

# module+offset values worth naming (taken from the exception context and the
# stack value histogram produced by minidump_crash.py)
OF_INTEREST = [
    ("ntdll.dll", 0x12D2F), ("ntdll.dll", 0x12CE0), ("ntdll.dll", 0x1D5D98),
    ("ntdll.dll", 0x1DD91C), ("ntdll.dll", 0x1D9E30), ("ntdll.dll", 0x1D5B34),
    ("ntdll.dll", 0xAEA29), ("ntdll.dll", 0xAE785), ("ntdll.dll", 0xAF91F),
    ("ntdll.dll", 0x14E99), ("ntdll.dll", 0x1654FF), ("ntdll.dll", 0xCBFE9),
    ("ntdll.dll", 0xCBA43), ("ntdll.dll", 0xCBF2E), ("ntdll.dll", 0xCBFC8),
    ("ntdll.dll", 0x1243AF),
    ("kernel32.dll", 0x12A26), ("kernel32.dll", 0x32150),
    ("VCRUNTIME140.dll", 0x5972),
    ("helldivers2.exe", 0x2C04782), ("helldivers2.exe", 0x328F004),
    ("helldivers2.exe", 0x3184080), ("helldivers2.exe", 0x318408C),
    ("helldivers2.exe", 0x2D96AF8), ("helldivers2.exe", 0x2979000),
    ("helldivers2.exe", 0x12A7DC0), ("helldivers2.exe", 0x5A5E3),
    ("helldivers2.exe", 0x6270F0), ("helldivers2.exe", 0x168E5A0),
]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


class Reader:
    def __init__(self, dump, ranges):
        self.d = dump
        self.ranges = sorted(ranges, key=lambda r: r["start"])
        self.starts = [r["start"] for r in self.ranges]

    def region(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        r = self.ranges[i]
        if r["start"] <= addr < r["start"] + r["size"]:
            return r
        return None

    def read(self, addr, n):
        """Read n bytes, stitching across captured regions if they are adjacent."""
        out = b""
        cur = addr
        while len(out) < n:
            r = self.region(cur)
            if r is None:
                break
            take = min(n - len(out), r["start"] + r["size"] - cur)
            out += self.d.raw(r["file_offset"] + (cur - r["start"]), take)
            cur += take
        return out


# ------------------------------------------------------------------ coverage

def coverage(mods, ranges):
    rng = sorted(ranges, key=lambda r: r["start"])
    starts = [r["start"] for r in rng]
    rows = []
    for mod in mods:
        lo, hi = mod["base"], mod["end"]
        i = bisect.bisect_right(starts, lo) - 1
        if i < 0:
            i = 0
        total = 0
        base_page = 0
        for r in rng[i:]:
            if r["start"] >= hi:
                break
            rs, re = r["start"], r["start"] + r["size"]
            ov = min(re, hi) - max(rs, lo)
            if ov > 0:
                total += ov
                if rs <= lo and re > lo:
                    base_page = min(re, lo + 0x1000) - lo
        rows.append((mod, total, base_page))
    return rows


# ------------------------------------------------------------------ PE exports

def parse_exports(rd, base):
    hdr = rd.read(base, 0x1000)
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return None, "no MZ at image base (header page not captured)"
    e_lfanew = u32(hdr, 0x3C)
    nt = rd.read(base + e_lfanew, 0x120)
    if len(nt) < 0x120 or nt[:4] != b"PE\0\0":
        return None, "no PE signature (NT headers not captured)"
    magic = u16(nt, 0x18)
    if magic != 0x20B:
        return None, "not PE32+ (magic=0x%04X)" % magic
    dd_off = 0x18 + 112  # PE32+ optional header: DataDirectory[0]=Export
    exp_rva = u32(nt, dd_off)
    exp_size = u32(nt, dd_off + 4)
    if exp_rva == 0 or exp_size == 0:
        return None, "no export directory"
    ed = rd.read(base + exp_rva, 0x28)
    if len(ed) < 0x28:
        return None, "export directory not captured"
    num_funcs = u32(ed, 0x14)
    num_names = u32(ed, 0x18)
    addr_funcs = u32(ed, 0x1C)
    addr_names = u32(ed, 0x20)
    addr_ord = u32(ed, 0x24)
    funcs = rd.read(base + addr_funcs, 4 * num_funcs)
    names = rd.read(base + addr_names, 4 * num_names)
    ords = rd.read(base + addr_ord, 2 * num_names)
    if len(funcs) < 4 * num_funcs or len(names) < 4 * num_names or len(ords) < 2 * num_names:
        return None, "export arrays not fully captured"
    out = []
    for i in range(num_names):
        nrva = u32(names, 4 * i)
        o = u16(ords, 2 * i)
        if o >= num_funcs:
            continue
        frva = u32(funcs, 4 * o)
        nm = rd.read(base + nrva, 128).split(b"\0")[0].decode("ascii", "replace")
        out.append((frva, nm))
    out.sort()
    return out, "ok (%d named exports, dir rva=0x%X size=0x%X)" % (
        len(out), exp_rva, exp_size)


def resolve(exports, rva):
    i = bisect.bisect_right([e[0] for e in exports], rva) - 1
    if i < 0:
        return None, None
    return exports[i][0], exports[i][1]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DUMP
    d = m.DumpFile(path)
    hdr = m.parse_header(d)
    streams = m.parse_directory(d, hdr)
    modstream = next(s for s in streams if s["stream_type"] == m.ST_ModuleList)
    mods = m.parse_modules(d, modstream)
    ranges = m.parse_memory_ranges(d, streams)
    rd = Reader(d, ranges)
    modmap = m.ModuleMap(mods)

    print("=" * 78)
    print("CAPTURED-IMAGE COVERAGE PER MODULE")
    print("=" * 78)
    rows = coverage(mods, ranges)
    print("%-40s %-12s %-12s %s" % ("module", "image size", "captured", "base page"))
    for mod, total, basep in sorted(rows, key=lambda r: -r[1]):
        if total == 0:
            continue
        print("%-40s 0x%08X   0x%08X   %s" %
              (os.path.basename(mod["name"]), mod["size"], total,
               "YES" if basep >= 0x400 else ("partial 0x%X" % basep if basep else "no")))
    zero = [r for r in rows if r[1] == 0]
    print("")
    print("%d of %d modules have ZERO captured bytes." % (len(zero), len(mods)))
    print("")

    print("=" * 78)
    print("PE EXPORT RESOLUTION (from the images captured in the dump)")
    print("=" * 78)
    exports_by_mod = {}
    for mod in mods:
        if mod["size"] < 0x1000:
            continue
        exps, why = parse_exports(rd, mod["base"])
        if exps:
            exports_by_mod[os.path.basename(mod["name"]).lower()] = (mod, exps)
            print("%-40s %s" % (os.path.basename(mod["name"]), why))
    print("")
    if not exports_by_mod:
        print("No module's PE headers were captured, so NO export/name resolution is")
        print("possible from this dump. Offsets below stay raw module+offset.")
        print("")
    print("--- resolution of the offsets seen in the context and on the stack ---")
    print("%-24s %-12s %s" % ("module+offset", "nearest exp", "export name"))
    for name, off in OF_INTEREST:
        entry = exports_by_mod.get(name.lower())
        if not entry:
            print("%-24s %-12s %s" % ("%s+0x%X" % (name, off), "-",
                                      "(module headers not captured)"))
            continue
        _, exps = entry
        er, en = resolve(exps, off)
        if er is None:
            print("%-24s %-12s %s" % ("%s+0x%X" % (name, off), "-",
                                      "(below first export)"))
        else:
            print("%-24s %-12s %s   (+0x%X past it)" %
                  ("%s+0x%X" % (name, off), "0x%X" % er, en, off - er))
    print("")

    # ------------------------------------------------------------- raw stack
    exstream = next(s for s in streams if s["stream_type"] == m.ST_Exception)
    ex = m.parse_exception(d, exstream)
    ctx = m.read_context(d, ex["thread_context_rva"], 0x00)
    rsp = ctx["Rsp"]
    print("=" * 78)
    print("RAW STACK AROUND RSP (kernel-pushed exception delivery blocks)")
    print("=" * 78)
    print("RSP = %s" % m.hexv(rsp))
    raw = rd.read(rsp - 0x40, 0x260)
    base_addr = rsp - 0x40
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("  %s  %-47s  %s" % (m.hexv(base_addr + i), hx, asc))
    print("")

    # does a CONTEXT_RECORD follow the exception record?
    print("--- is there a CONTEXT_RECORD immediately after the EXCEPTION_RECORD? ---")
    er_addr = None
    i = raw.find(b"\x26\x00\x00\xc0")
    if i >= 0:
        er_addr = base_addr + i
        print("EXCEPTION_RECORD candidate starts at %s (code 0xC0000026)" % m.hexv(er_addr))
    for delta in (0x98, 0xA0, 0xB0):
        c = er_addr + delta if er_addr else None
        if c is None:
            continue
        blob = rd.read(c, 0x100)
        if len(blob) < 0x100:
            print("  +0x%X: not captured" % delta)
            continue
        flags = u32(blob, 0x30)
        rip = struct.unpack_from("<Q", blob, 0xF8)[0]
        rspv = struct.unpack_from("<Q", blob, 0x98)[0]
        segcs = u16(blob, 0x38)
        ok = (flags & m.CONTEXT_AMD64) == m.CONTEXT_AMD64
        print("  +0x%04X: ContextFlags=0x%08X SegCs=0x%04X Rip=%s Rsp=%s  AMD64=%s %s"
              % (delta, flags, segcs, m.hexv(rip), m.hexv(rspv), ok,
                 "Rip->" + str(modmap.describe(rip)) if modmap.find(rip) else ""))
    print("")

    # --------------------------------------- scan stack for CONTEXT_RECORDs
    print("=" * 78)
    print("CONTEXT_RECORD-SHAPED BLOBS ON THE FAULTED THREAD'S STACK")
    print("=" * 78)
    st = m.parse_threads(d, next(s for s in streams
                                 if s["stream_type"] == m.ST_ThreadList))[0]
    r0, r1 = st["stack_start"], st["stack_end"]
    stack_bytes = rd.read(r0, r1 - r0)
    print("stack bytes available: 0x%X (from %s)" % (len(stack_bytes), m.hexv(r0)))
    found = []
    for off in range(0, max(0, len(stack_bytes) - 0x100), 8):
        flags = u32(stack_bytes, off + 0x30)
        if flags not in (0x0010000F, 0x0010001F, 0x0010000B, 0x00100003):
            continue
        segcs = u16(stack_bytes, off + 0x38)
        if segcs != 0x33:
            continue
        rip = struct.unpack_from("<Q", stack_bytes, off + 0xF8)[0]
        if modmap.find(rip) is None:
            continue
        rspv = struct.unpack_from("<Q", stack_bytes, off + 0x98)[0]
        found.append((r0 + off, flags, rip, rspv))
    print("found %d CONTEXT-shaped blobs (ContextFlags 0x0010000F/1F, SegCs=0x33,"
          % len(found))
    print("Rip inside a loaded module):")
    for a, fl, rip, rspv in found[:60]:
        print("  %s  flags=0x%08X Rip=%s (%s) Rsp=%s" %
              (m.hexv(a), fl, m.hexv(rip), modmap.describe(rip), m.hexv(rspv)))
    if len(found) > 60:
        print("  ... %d more" % (len(found) - 60))
    if len(found) > 1:
        print("")
        print("spacing between consecutive blobs:")
        seen = {}
        for j in range(1, len(found)):
            dl = found[j][0] - found[j - 1][0]
            seen[dl] = seen.get(dl, 0) + 1
        for dl, c in sorted(seen.items(), key=lambda x: -x[1]):
            print("  0x%-6X x%d" % (dl, c))
    print("")

    # ---------------------------- compare consecutive 0xD00 blocks byte-wise
    print("=" * 78)
    print("ARE THE REPEATING 0xD00 STACK BLOCKS IDENTICAL?")
    print("=" * 78)
    print("EXCEPTION_RECORD candidates found by the main tool sit at 0xD00 spacing;")
    print("compare block N against block N+1 byte for byte.")
    er_records = []
    for off in range(0, max(0, len(stack_bytes) - 152), 8):
        if u32(stack_bytes, off) != 0xC0000026:
            continue
        if u32(stack_bytes, off + 4) != 0x81:
            continue
        if struct.unpack_from("<Q", stack_bytes, off + 16)[0] != ex["exception_address"]:
            continue
        er_records.append(r0 + off)
    print("EXCEPTION_RECORD copies on this stack: %d" % len(er_records))
    if er_records:
        print("first = %s  last = %s  span = 0x%X" %
              (m.hexv(er_records[0]), m.hexv(er_records[-1]),
               er_records[-1] - er_records[0]))
        dlt = {}
        for j in range(1, len(er_records)):
            k = er_records[j] - er_records[j - 1]
            dlt[k] = dlt.get(k, 0) + 1
        print("spacings: %s" % ", ".join("0x%X x%d" % (k, v)
                                         for k, v in sorted(dlt.items())))
        step = 0xD00
        a = rd.read(er_records[0] - 0x100, step)
        b = rd.read(er_records[0] - 0x100 + step, step)
        if len(a) == len(b) == step:
            diff = [i for i in range(step) if a[i] != b[i]]
            print("")
            print("block0 vs block1 over 0x%X bytes starting %s:" %
                  (step, m.hexv(er_records[0] - 0x100)))
            print("  differing bytes: %d / %d (%.1f%%)" %
                  (len(diff), step, 100.0 * len(diff) / step))
            if diff:
                print("  first 24 differing offsets (relative to block start):")
                for i in diff[:24]:
                    print("    +0x%04X  block0=%02X block1=%02X" %
                          (i, a[i], b[i]))
        else:
            print("could not read two full 0xD00 blocks for comparison")
    print("")


if __name__ == "__main__":
    main()
