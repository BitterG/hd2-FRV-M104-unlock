#!/usr/bin/env python3
"""Offline Windows user-mode minidump triage - standard library only.

No debugger, no symbol server. Parses the raw MDMP container directly:

    stream 3  ThreadListStream
    stream 4  ModuleListStream
    stream 5  MemoryListStream
    stream 6  ExceptionStream
    stream 7  SystemInfoStream
    stream 9  Memory64ListStream
    stream 10/11 CommentStreamA/W
    stream 15 MiscInfoStream
    stream 16 MemoryInfoListStream

and produces: exception record, module table, faulting RIP/RSP (with an explicit
verification of the AMD64 CONTEXT layout), a heuristic module-pointer stack walk,
stack string extraction, and the VirtualQuery-style memory info for the fault
address and the stack.

Usage:
    python tools/minidump_crash.py [dump-path] [--json OUT.json]

Everything printed is derived from bytes in the file; nothing is assumed beyond
the documented minidump structures.
"""

import bisect
import json
import mmap
import os
import struct
import sys
import tempfile

DEFAULT_DUMP = r"C:\Users\kugua\AppData\Local\CrashDumps\helldivers2.exe.23892.dmp"

MDMP_SIGNATURE = 0x504D444D  # 'MDMP'

# ---------------------------------------------------------------- stream types
ST_Unused = 0
ST_Reserved0 = 1
ST_Reserved1 = 2
ST_ThreadList = 3
ST_ModuleList = 4
ST_MemoryList = 5
ST_Exception = 6
ST_SystemInfo = 7
ST_ThreadExList = 8
ST_Memory64List = 9
ST_CommentA = 10
ST_CommentW = 11
ST_HandleData = 12
ST_FunctionTable = 13
ST_UnloadedModuleList = 14
ST_MiscInfo = 15
ST_MemoryInfoList = 16
ST_ThreadInfoList = 17
ST_HandleOperationList = 18
ST_TokenList = 19
ST_JavaScriptData = 20
ST_SystemMemoryInfo = 21
ST_ProcessVmCounters = 22
ST_IptTrace = 23
ST_ThreadNames = 24

STREAM_NAMES = {
    3: "ThreadListStream", 4: "ModuleListStream", 5: "MemoryListStream",
    6: "ExceptionStream", 7: "SystemInfoStream", 8: "ThreadExListStream",
    9: "Memory64ListStream", 10: "CommentStreamA", 11: "CommentStreamW",
    12: "HandleDataStream", 13: "FunctionTableStream",
    14: "UnloadedModuleListStream", 15: "MiscInfoStream",
    16: "MemoryInfoListStream", 17: "ThreadInfoListStream",
    18: "HandleOperationListStream", 19: "TokenStream",
    20: "JavaScriptDataStream", 21: "SystemMemoryInfoStream",
    22: "ProcessVmCountersStream", 23: "IptTraceStream",
    24: "ThreadNamesStream",
}

DUMP_FLAGS = [
    (0x00000001, "MiniDumpNormal"),
    (0x00000002, "MiniDumpWithDataSegs"),
    (0x00000004, "MiniDumpWithFullMemory"),
    (0x00000008, "MiniDumpWithHandleData"),
    (0x00000010, "MiniDumpFilterMemory"),
    (0x00000020, "MiniDumpScanMemory"),
    (0x00000040, "MiniDumpWithUnloadedModules"),
    (0x00000080, "MiniDumpWithIndirectlyReferencedMemory"),
    (0x00000100, "MiniDumpFilterModulePaths"),
    (0x00000200, "MiniDumpWithProcessThreadData"),
    (0x00000400, "MiniDumpWithPrivateReadWriteMemory"),
    (0x00000800, "MiniDumpWithoutOptionalData"),
    (0x00001000, "MiniDumpWithFullMemoryInfo"),
    (0x00002000, "MiniDumpWithThreadInfo"),
    (0x00004000, "MiniDumpWithCodeSegs"),
    (0x00008000, "MiniDumpWithoutAuxiliaryState"),
    (0x00010000, "MiniDumpWithFullAuxiliaryState"),
    (0x00020000, "MiniDumpWithPrivateWriteCopyMemory"),
    (0x00040000, "MiniDumpIgnoreInaccessibleMemory"),
    (0x00080000, "MiniDumpWithTokenInformation"),
    (0x00100000, "MiniDumpWithModuleHeaders"),
    (0x00200000, "MiniDumpFilterTriage"),
    (0x00400000, "MiniDumpWithAvxXStateContext"),
    (0x00800000, "MiniDumpWithIptTrace"),
    (0x01000000, "MiniDumpScanInaccessiblePartialPages"),
]

EXCEPTION_NAMES = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0xC0000006: "EXCEPTION_IN_PAGE_ERROR",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
    0xC0000026: "STATUS_INVALID_DISPOSITION (exception handler returned an invalid disposition)",
    0xC0000027: "STATUS_UNWIND_CONSOLIDATE",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC000008D: "EXCEPTION_FLT_DENORMAL_OPERAND",
    0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    0xC0000090: "EXCEPTION_FLT_INVALID_OPERATION",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC0000095: "EXCEPTION_INT_OVERFLOW",
    0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN (__fastfail / fail-fast)",
    0xC0000417: "STATUS_INVALID_CRUNTIME_PARAMETER",
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0x80000029: "EXCEPTION_BREAKPOINT (long)",
    0xE06D7363: "C++ exception (throw)",
    0x40010006: "DBG_PRINTEXCEPTION_C",
    0x406D1388: "MS_VC_EXCEPTION (thread name)",
}

# __fastfail subcodes (first ExceptionInformation entry for 0xC0000409)
FASTFAIL_CODES = {
    0: "FAST_FAIL_LEGACY_GS_VIOLATION",
    1: "FAST_FAIL_VTGUARD_CHECK_FAILURE",
    2: "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE",
    3: "FAST_FAIL_CORRUPT_LIST_ENTRY",
    4: "FAST_FAIL_INCORRECT_STACK",
    5: "FAST_FAIL_INVALID_ARG",
    6: "FAST_FAIL_GS_COOKIE_INIT",
    7: "FAST_FAIL_FATAL_APP_EXIT",
    8: "FAST_FAIL_RANGE_CHECK_FAILURE",
    9: "FAST_FAIL_UNSAFE_REGISTRY_ACCESS",
    10: "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
    11: "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE",
    12: "FAST_FAIL_INVALID_FIBER_SWITCH",
    13: "FAST_FAIL_INVALID_SET_OF_CONTEXT",
    14: "FAST_FAIL_INVALID_REFERENCE_COUNT",
    15: "FAST_FAIL_INVALID_JUMP_BUFFER",
    16: "FAST_FAIL_INVALID_LONGJUMP_TARGET",
    17: "FAST_FAIL_INVALID_NONVOLATILE_CONTEXT",
    18: "FAST_FAIL_CORRUPT_REGISTRY_ENTRY",
    19: "FAST_FAIL_INVALID_FIBER_SWITCH_ARG",
    20: "FAST_FAIL_INVALID_FIBER_SWITCH_ARG2",
    21: "FAST_FAIL_INVALID_SET_OF_CONTEXT_ARG",
    24: "FAST_FAIL_INVALID_HANDLE",
    25: "FAST_FAIL_INVALID_FIBER_SWITCH_TEB",
    26: "FAST_FAIL_INVALID_FIBER_SWITCH_ENTRY",
    27: "FAST_FAIL_INVALID_FIBER_SWITCH_ARG3",
    28: "FAST_FAIL_INVALID_FIBER_SWITCH_ARG4",
    29: "FAST_FAIL_INVALID_FIBER_SWITCH_ENTRY2",
    30: "FAST_FAIL_INVALID_FIBER_SWITCH_ENTRY3",
    31: "FAST_FAIL_INVALID_FIBER_SWITCH_ENTRY4",
    32: "FAST_FAIL_INVALID_FIBER_SWITCH_ENTRY5",
}

ACCESS_OP = {0: "READ", 1: "WRITE", 8: "EXECUTE (DEP)", 0x100: "DEP-violation(read)"}

MEM_STATE = {0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE",
             0x1000000: "MEM_IMAGE?no"}  # not used directly

PROT_FLAGS = [
    (0x01, "PAGE_NOACCESS"), (0x02, "PAGE_READONLY"), (0x04, "PAGE_READWRITE"),
    (0x08, "PAGE_WRITECOPY"), (0x10, "PAGE_EXECUTE"),
    (0x20, "PAGE_EXECUTE_READ"), (0x40, "PAGE_EXECUTE_READWRITE"),
    (0x80, "PAGE_EXECUTE_WRITECOPY"), (0x100, "PAGE_GUARD"),
    (0x200, "PAGE_NOCACHE"), (0x400, "PAGE_WRITECOMBINE"),
]


def state_str(s):
    if s == 0x1000:
        return "MEM_COMMIT"
    if s == 0x2000:
        return "MEM_RESERVE"
    if s == 0x10000:
        return "MEM_FREE"
    return "0x%08X" % s


def type_str(t):
    if t == 0x1000000:
        return "MEM_IMAGE"
    if t == 0x40000:
        return "MEM_MAPPED"
    if t == 0x20000:
        return "MEM_PRIVATE"
    return "0x%08X" % t


def prot_str(p):
    if p == 0:
        return "0x00000000 (none)"
    names = [n for bit, n in PROT_FLAGS if p & bit]
    return "0x%08X (%s)" % (p, "|".join(names) if names else "?")


def hexv(v):
    return "0x%016X" % v


class DumpFile:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.size = os.path.getsize(path)
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)

    def u8(self, off):
        return self.mm[off]

    def u16(self, off):
        return struct.unpack_from("<H", self.mm, off)[0]

    def u32(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def i32(self, off):
        return struct.unpack_from("<i", self.mm, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.mm, off)[0]

    def raw(self, off, n):
        return bytes(self.mm[off:off + n])

    def hexdump(self, off, n, per=16):
        out = []
        data = self.raw(off, n)
        for i in range(0, len(data), per):
            chunk = data[i:i + per]
            hx = " ".join("%02X" % b for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append("    %08X  %-47s  %s" % (off + i, hx, asc))
        return "\n".join(out)


# ------------------------------------------------------------------ structures

def parse_header(d):
    sig = d.u32(0)
    version = d.u32(4)
    nstreams = d.u32(8)
    dir_rva = d.u32(12)
    checksum = d.u32(16)
    tds = d.u32(20)
    flags = d.u64(24)
    return dict(signature=sig, signature_ok=(sig == MDMP_SIGNATURE),
                version=version, number_of_streams=nstreams,
                stream_directory_rva=dir_rva, checksum=checksum,
                time_date_stamp=tds, flags=flags,
                flags_hex="0x%016X" % flags)


def parse_directory(d, hdr):
    streams = []
    off = hdr["stream_directory_rva"]
    for i in range(hdr["number_of_streams"]):
        st = d.u32(off)
        size = d.u32(off + 4)
        rva = d.u32(off + 8)
        streams.append(dict(index=i, stream_type=st,
                            name=STREAM_NAMES.get(st, "Unknown(%d)" % st),
                            data_size=size, rva=rva))
        off += 12
    return streams


def read_md_string(d, rva):
    if rva == 0:
        return ""
    length = d.u32(rva)
    data = d.raw(rva + 4, length)
    try:
        return data.decode("utf-16-le", errors="replace")
    except Exception:
        return repr(data)


def parse_modules(d, stream):
    off = stream["rva"]
    n = d.u32(off)
    off += 4
    mods = []
    for i in range(n):
        base = d.u64(off + 0)
        size = d.u32(off + 8)
        checksum = d.u32(off + 12)
        tds = d.u32(off + 16)
        name_rva = d.u32(off + 20)
        vsig = d.u32(off + 24)
        fv_ms = d.u32(off + 32)
        fv_ls = d.u32(off + 36)
        pv_ms = d.u32(off + 40)
        pv_ls = d.u32(off + 44)
        cv_size = d.u32(off + 76)
        cv_rva = d.u32(off + 80)
        mods.append(dict(index=i, base=base, size=size,
                         base_hex=hexv(base), end=base + size,
                         size_hex="0x%08X" % size, checksum="0x%08X" % checksum,
                         timestamp=tds,
                         timestamp_hex="0x%08X" % tds,
                         name=read_md_string(d, name_rva),
                         vs_signature="0x%08X" % vsig,
                         vs_signature_ok=(vsig == 0xFEEF04BD),
                         file_version="%d.%d.%d.%d" % ((fv_ms >> 16) & 0xFFFF,
                                                       fv_ms & 0xFFFF,
                                                       (fv_ls >> 16) & 0xFFFF,
                                                       fv_ls & 0xFFFF),
                         product_version="%d.%d.%d.%d" % ((pv_ms >> 16) & 0xFFFF,
                                                          pv_ms & 0xFFFF,
                                                          (pv_ls >> 16) & 0xFFFF,
                                                          pv_ls & 0xFFFF),
                         cv_size=cv_size, cv_rva=cv_rva,
                         has_cv=(cv_size > 0 and cv_rva > 0)))
        off += 108
    return mods


def parse_exception(d, stream):
    off = stream["rva"]
    tid = d.u32(off)
    rec = off + 8
    ex = dict(thread_id=tid,
              exception_code=d.u32(rec + 0),
              exception_flags=d.u32(rec + 4),
              exception_record=d.u64(rec + 8),
              exception_address=d.u64(rec + 16),
              number_parameters=d.u32(rec + 24))
    ex["exception_code_hex"] = "0x%08X" % ex["exception_code"]
    ex["exception_flags_hex"] = "0x%08X" % ex["exception_flags"]
    ex["exception_address_hex"] = hexv(ex["exception_address"])
    ex["exception_name"] = EXCEPTION_NAMES.get(ex["exception_code"], "unknown")
    n = min(ex["number_parameters"], 15)
    info = [d.u64(rec + 32 + 8 * i) for i in range(15)]
    ex["exception_information_all"] = info
    ex["exception_information"] = info[:n]
    ex["exception_information_hex"] = [hexv(v) for v in info[:n]]
    ctx_size = d.u32(off + 160)
    ctx_rva = d.u32(off + 164)
    ex["thread_context_size"] = ctx_size
    ex["thread_context_rva"] = ctx_rva
    ex["thread_context_present"] = (ctx_size > 0 and ctx_rva > 0)
    ex["raw_exception_record_hex"] = " ".join(
        "%02X" % b for b in d.raw(rec, 152))
    return ex


def parse_threads(d, stream):
    off = stream["rva"]
    n = d.u32(off)
    off += 4
    threads = []
    for i in range(n):
        tid = d.u32(off + 0)
        suspend = d.u32(off + 4)
        pri_class = d.u32(off + 8)
        pri = d.u32(off + 12)
        teb = d.u64(off + 16)
        stack_start = d.u64(off + 24)
        stack_size = d.u32(off + 32)
        stack_rva = d.u32(off + 36)
        ctx_size = d.u32(off + 40)
        ctx_rva = d.u32(off + 44)
        threads.append(dict(index=i, thread_id=tid, suspend_count=suspend,
                            priority_class=pri_class, priority=pri,
                            teb=teb, teb_hex=hexv(teb),
                            stack_start=stack_start,
                            stack_start_hex=hexv(stack_start),
                            stack_size=stack_size,
                            stack_end=stack_start + stack_size,
                            stack_end_hex=hexv(stack_start + stack_size),
                            stack_rva=stack_rva,
                            context_size=ctx_size, context_rva=ctx_rva,
                            context_present=(ctx_size > 0 and ctx_rva > 0)))
        off += 48
    return threads


def parse_memory_ranges(d, streams):
    """Return list of (start, size, file_offset) from stream 5 and/or 9."""
    ranges = []
    for s in streams:
        if s["stream_type"] == ST_MemoryList:
            off = s["rva"]
            n = d.u32(off)
            off += 4
            for i in range(n):
                start = d.u64(off)
                size = d.u32(off + 8)
                rva = d.u32(off + 12)
                ranges.append(dict(start=start, size=size, file_offset=rva,
                                   source="MemoryListStream"))
                off += 16
        elif s["stream_type"] == ST_Memory64List:
            off = s["rva"]
            n = d.u64(off)
            base_rva = d.u64(off + 8)
            off += 16
            cur = base_rva
            for i in range(n):
                start = d.u64(off)
                size = d.u64(off + 8)
                ranges.append(dict(start=start, size=size, file_offset=cur,
                                   source="Memory64ListStream"))
                cur += size
                off += 16
    ranges.sort(key=lambda r: r["start"])
    return ranges


def parse_memory_info(d, streams):
    for s in streams:
        if s["stream_type"] == ST_MemoryInfoList:
            off = s["rva"]
            hdr_size = d.u32(off)
            ent_size = d.u32(off + 4)
            count = d.u64(off + 8)
            entries = []
            o = off + hdr_size
            for i in range(count):
                entries.append(dict(
                    base=d.u64(o + 0),
                    allocation_base=d.u64(o + 8),
                    allocation_protect=d.u32(o + 16),
                    region_size=d.u64(o + 24),
                    state=d.u32(o + 32),
                    protect=d.u32(o + 36),
                    type=d.u32(o + 40)))
                o += ent_size
            return dict(header_size=hdr_size, entry_size=ent_size,
                        count=count, entries=entries)
    return None


def parse_system_info(d, stream):
    o = stream["rva"]
    return dict(processor_architecture=d.u16(o + 0),
                processor_level=d.u16(o + 2),
                processor_revision=d.u16(o + 4),
                number_of_processors=d.u8(o + 6),
                product_type=d.u8(o + 7),
                major_version=d.u32(o + 8),
                minor_version=d.u32(o + 12),
                build_number=d.u32(o + 16),
                platform_id=d.u32(o + 20),
                csd_version=read_md_string(d, d.u32(o + 24)))


def parse_misc_info(d, stream):
    o = stream["rva"]
    size = d.u32(o)
    flags1 = d.u32(o + 4)
    out = dict(size_of_info=size, flags1="0x%08X" % flags1)
    if flags1 & 0x1:
        out["process_id"] = d.u32(o + 8)
    if flags1 & 0x2:
        out["process_create_time"] = d.u32(o + 12)
    if flags1 & 0x4:
        out["process_user_time"] = d.u32(o + 16)
    if flags1 & 0x8:
        out["process_kernel_time"] = d.u32(o + 20)
    if size >= 0x18 and flags1 & 0x10:
        out["processor_max_mhz"] = d.u32(o + 24)
    return out


# ------------------------------------------------------------------- the CONTEXT
# AMD64 CONTEXT (winnt.h, DECLSPEC_ALIGN(16)):
#   0x00 P1Home     0x08 P2Home   0x10 P3Home   0x18 P4Home
#   0x20 P5Home     0x28 P6Home   0x30 ContextFlags (u32)  0x34 MxCsr (u32)
#   0x38 SegCs 0x3A SegDs 0x3C SegEs 0x3E SegFs 0x40 SegGs 0x42 SegSs
#   0x44 EFlags (u32)
#   0x48..0x70 Dr0,Dr1,Dr2,Dr3,Dr6,Dr7
#   0x78 Rax  0x80 Rcx  0x88 Rdx  0x90 Rbx  0x98 Rsp  0xA0 Rbp
#   0xA8 Rsi  0xB0 Rdi  0xB8 R8   0xC0 R9   0xC8 R10  0xD0 R11
#   0xD8 R12  0xE0 R13  0xE8 R14  0xF0 R15  0xF8 Rip
CONTEXT_AMD64 = 0x00100000
CTX_SIZE = 0x4D0  # sizeof(CONTEXT) on x64

REG_OFFSETS = [
    ("Rax", 0x78), ("Rcx", 0x80), ("Rdx", 0x88), ("Rbx", 0x90),
    ("Rsp", 0x98), ("Rbp", 0xA0), ("Rsi", 0xA8), ("Rdi", 0xB0),
    ("R8", 0xB8), ("R9", 0xC0), ("R10", 0xC8), ("R11", 0xD0),
    ("R12", 0xD8), ("R13", 0xE0), ("R14", 0xE8), ("R15", 0xF0),
    ("Rip", 0xF8),
]


def read_context(d, rva, base):
    """Read the AMD64 CONTEXT assuming it starts at rva+base."""
    o = rva + base
    ctx = dict(base_offset=base,
               context_flags=d.u32(o + 0x30),
               context_flags_hex="0x%08X" % d.u32(o + 0x30),
               mxcsr="0x%08X" % d.u32(o + 0x34),
               seg_cs=d.u16(o + 0x38), seg_ds=d.u16(o + 0x3A),
               seg_es=d.u16(o + 0x3C), seg_fs=d.u16(o + 0x3E),
               seg_gs=d.u16(o + 0x40), seg_ss=d.u16(o + 0x42),
               eflags="0x%08X" % d.u32(o + 0x44),
               dr0=d.u64(o + 0x48), dr1=d.u64(o + 0x50),
               dr2=d.u64(o + 0x58), dr3=d.u64(o + 0x60),
               dr6=d.u64(o + 0x68), dr7=d.u64(o + 0x70))
    for nm in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
        ctx[nm + "_hex"] = hexv(ctx[nm])
    for name, off in REG_OFFSETS:
        ctx[name] = d.u64(o + off)
        ctx[name + "_hex"] = hexv(ctx[name])
    return ctx


def ctx_plausible(ctx, ranges, stack_ok):
    """Score a candidate CONTEXT placement."""
    reasons = []
    ok = True
    if (ctx["context_flags"] & CONTEXT_AMD64) != CONTEXT_AMD64:
        ok = False
        reasons.append("ContextFlags missing CONTEXT_AMD64 bit (got %s)" %
                       ctx["context_flags_hex"])
    else:
        reasons.append("ContextFlags has CONTEXT_AMD64 (0x00100000) set: %s" %
                       ctx["context_flags_hex"])
    if ctx["seg_cs"] != 0x33:
        reasons.append("SegCs=%s (x64 user code is normally 0x33)" %
                       hex(ctx["seg_cs"]))
    else:
        reasons.append("SegCs=0x0033 (x64 user-mode code segment)")
    return ok, reasons


# ------------------------------------------------------------------ addressing

class ModuleMap:
    def __init__(self, mods):
        # bisect REQUIRES the key list to be sorted; the on-disk module order is
        # not guaranteed to be ascending by base, so sort a copy here.
        self.mods = sorted(mods, key=lambda m: m["base"])
        self.bases = [m["base"] for m in self.mods]

    def find(self, addr):
        if addr == 0:
            return None
        i = bisect.bisect_right(self.bases, addr) - 1
        if i < 0:
            return None
        m = self.mods[i]
        if m["base"] <= addr < m["end"]:
            return m
        return None

    def describe(self, addr):
        m = self.find(addr)
        if m is None:
            return None
        return "%s+0x%X" % (os.path.basename(m["name"]), addr - m["base"])


class RangeMap:
    """Memory ranges actually present in the dump file."""

    def __init__(self, ranges):
        self.ranges = ranges
        self.starts = [r["start"] for r in ranges]

    def find(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        r = self.ranges[i]
        if r["start"] <= addr < r["start"] + r["size"]:
            return r
        return None


class MemInfoMap:
    def __init__(self, mi):
        self.entries = sorted(mi["entries"], key=lambda e: e["base"]) if mi else []
        self.starts = [e["base"] for e in self.entries]

    def find(self, addr):
        if not self.entries:
            return None
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        e = self.entries[i]
        if e["base"] <= addr < e["base"] + e["region_size"]:
            return e
        return None


def read_mem(d, rangemap, addr, n):
    """Read n bytes of process memory at `addr` from whatever range captured it."""
    r = rangemap.find(addr)
    if r is None:
        return None, None
    avail = min(n, r["start"] + r["size"] - addr)
    if avail <= 0:
        return None, r
    return d.raw(r["file_offset"] + (addr - r["start"]), avail), r


EXC_RECORD_CODES = (
    0xC0000005, 0xC0000006, 0xC000001D, 0xC0000025, 0xC0000026, 0xC000008C,
    0xC000008D, 0xC000008E, 0xC0000090, 0xC0000094, 0xC0000095, 0xC0000096,
    0xC00000FD, 0xC0000135, 0xC0000139, 0xC0000142, 0xC0000374, 0xC0000409,
    0xC0000417, 0x80000003, 0x80000004, 0xE06D7363, 0x40010006, 0x406D1388,
)


def scan_exception_records(data, base_addr, modmap):
    """Look for EXCEPTION_RECORD-shaped structures in raw memory.

    EXCEPTION_RECORD layout (x64):
      0x00 ExceptionCode u32   0x04 ExceptionFlags u32
      0x08 ExceptionRecord u64 0x10 ExceptionAddress u64
      0x18 NumberParameters u32, 0x1C pad
      0x20 ExceptionInformation u64[15]     -> sizeof = 0x98(152)
    Filter: known code, sane flags, ExceptionRecord==0, and ExceptionAddress
    inside a loaded module.  That combination is unlikely by chance.
    """
    out = []
    n = len(data)
    for off in range(0, n - 152, 8):
        code = struct.unpack_from("<I", data, off)[0]
        if code not in EXC_RECORD_CODES:
            continue
        flags = struct.unpack_from("<I", data, off + 4)[0]
        nested = struct.unpack_from("<Q", data, off + 8)[0]
        addr = struct.unpack_from("<Q", data, off + 16)[0]
        nparam = struct.unpack_from("<I", data, off + 24)[0]
        if flags > 0x100 or nparam > 15 or nested != 0:
            continue
        if addr == 0 or modmap.find(addr) is None:
            continue
        info = [struct.unpack_from("<Q", data, off + 32 + 8 * i)[0]
                for i in range(nparam)]
        out.append(dict(mem_addr=base_addr + off, mem_addr_hex=hexv(base_addr + off),
                        code=code, code_hex="0x%08X" % code,
                        name=EXCEPTION_NAMES.get(code, "unknown"),
                        flags="0x%08X" % flags,
                        address=addr, address_hex=hexv(addr),
                        address_module=modmap.describe(addr),
                        number_parameters=nparam,
                        information_hex=[hexv(v) for v in info],
                        information=info))
    return out


def fmt_ts(v):
    import datetime
    try:
        u = datetime.datetime.fromtimestamp(v, datetime.timezone.utc)
        l = datetime.datetime.fromtimestamp(v)
        return "%s UTC / %s local" % (u.strftime("%Y-%m-%d %H:%M:%S"),
                                      l.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        return "(out of range)"


# --------------------------------------------------------------- stack scanning

def scan_module_pointers(d, ranges, modmap, start, max_bytes):
    """Worst-case backtrace: every 8-byte aligned qword at/above `start` that
    lands inside a loaded module."""
    r = ranges.find(start)
    if r is None:
        return None, []
    region_end = r["start"] + r["size"]
    avail = min(region_end - start, max_bytes)
    data = d.raw(r["file_offset"] + (start - r["start"]), avail)
    hits = []
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack_from("<Q", data, off)[0]
        m = modmap.find(v)
        if m is not None:
            hits.append(dict(stack_addr=start + off,
                             stack_addr_hex=hexv(start + off),
                             value=v, value_hex=hexv(v),
                             module=os.path.basename(m["name"]),
                             module_path=m["name"],
                             module_base_hex=m["base_hex"],
                             offset=v - m["base"]))
    return dict(region_start=r["start"], region_start_hex=hexv(r["start"]),
                region_size=r["size"], file_offset=r["file_offset"],
                scanned_bytes=avail, available_bytes=region_end - start,
                source=r["source"]), hits


ASCII_RE = None
UTF16_RE = None


def scan_strings(data, base_addr, min_len=6):
    import re
    ascii_re = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    # UTF-16LE: printable ASCII-ish char followed by 0x00
    utf16_re = re.compile((rb"(?:[\x20-\x7E]\x00){%d,}" % min_len))
    out = []
    for m in ascii_re.finditer(data):
        s = m.group().decode("ascii", errors="replace")
        out.append(dict(kind="ascii", addr=base_addr + m.start(),
                        addr_hex=hexv(base_addr + m.start()), text=s))
    for m in utf16_re.finditer(data):
        s = m.group().decode("utf-16-le", errors="replace")
        out.append(dict(kind="utf16", addr=base_addr + m.start(),
                        addr_hex=hexv(base_addr + m.start()), text=s))
    # dedupe by text, keep first address
    seen = {}
    for e in out:
        key = (e["kind"], e["text"])
        if key not in seen:
            seen[key] = e
    return list(seen.values())


INTEREST_KEYWORDS = [
    "assert", "Assert", "ASSERT", "fail", "Fail", "FAIL", "fatal", "Fatal",
    "error", "Error", "ERROR", "invalid", "Invalid", "corrupt", "Crash",
    "crash", "exception", "Exception", "abort", "Abort", "panic", "Panic",
    "game.dll", "game_dll", "helldivers", "Helldivers", ".lua", ".dl_bin",
    ".stream", ".patch_", "Bingus", "bingus", "loader", "Loader", "addon",
    "Addon", ".dll", ".exe", ".pdb", ".json", ".config", ".ini",
    "could not", "Could not", "failed to", "Failed to", "unable to",
    "out of memory", "Out of memory", "null", "NULL", "nullptr",
    "check failed", "CHECK", "verify", "Verify", "mismatch", "Mismatch",
    "overflow", "Overflow", "stack", "Stack",
]

BORING_RE = None


def score_string(s):
    score = 0
    hits = [k for k in INTEREST_KEYWORDS if k in s]
    score += 3 * len(hits)
    if len(s) >= 12:
        score += 1
    if len(s) >= 24:
        score += 1
    if "/" in s or "\\" in s:
        score += 2
    return score, hits


def main():
    args = [a for a in sys.argv[1:]]
    json_out = None
    if "--json" in args:
        i = args.index("--json")
        json_out = args[i + 1]
        del args[i:i + 2]
    path = args[0] if args else DEFAULT_DUMP
    max_stack = 512 * 1024

    d = DumpFile(path)
    result = {"dump_path": path, "file_size": d.size}
    P = print

    P("=" * 78)
    P("MINIDUMP TRIAGE (pure-Python, no symbols)")
    P("=" * 78)
    P("file            : %s" % path)
    P("size            : %d bytes (%.1f MB)" % (d.size, d.size / 1048576.0))

    hdr = parse_header(d)
    result["header"] = hdr
    P("signature       : 0x%08X %s" % (hdr["signature"],
                                        "'MDMP' OK" if hdr["signature_ok"] else "BAD"))
    P("version         : 0x%08X" % hdr["version"])
    P("streams         : %d" % hdr["number_of_streams"])
    P("dir RVA         : 0x%08X" % hdr["stream_directory_rva"])
    P("TimeDateStamp   : 0x%08X (%d) = %s" % (hdr["time_date_stamp"],
                                               hdr["time_date_stamp"],
                                               fmt_ts(hdr["time_date_stamp"])))
    P("Flags           : %s" % hdr["flags_hex"])
    for bit, name in DUMP_FLAGS:
        if hdr["flags"] & bit:
            P("                  - %s (0x%08X)" % (name, bit))
    P("")

    streams = parse_directory(d, hdr)
    result["streams"] = streams
    P("--- stream directory ---")
    P("%-4s %-28s %-12s %-12s" % ("idx", "type", "data_size", "rva"))
    for s in streams:
        P("%-4d %-28s 0x%08X   0x%08X" % (s["index"], s["name"],
                                          s["data_size"], s["rva"]))
    P("")

    # ---------------------------------------------------------- 1. exception
    exstream = next((s for s in streams if s["stream_type"] == ST_Exception), None)
    P("=" * 78)
    P("1. EXCEPTION RECORD (stream type 6)")
    P("=" * 78)
    ex = None
    if exstream is None:
        P("NO ExceptionStream present in this dump.")
    else:
        ex = parse_exception(d, exstream)
        result["exception"] = ex
        P("faulting thread id          : %d (0x%X)" % (ex["thread_id"], ex["thread_id"]))
        P("ExceptionCode               : %s  ->  %s" % (ex["exception_code_hex"],
                                                         ex["exception_name"]))
        P("ExceptionFlags              : %s" % ex["exception_flags_hex"])
        fl = ex["exception_flags"]
        fdesc = []
        if fl & 1:
            fdesc.append("EXCEPTION_NONCONTINUABLE(0x1)")
        if fl & 2:
            fdesc.append("EXCEPTION_UNWINDING(0x2)")
        if fl & 4:
            fdesc.append("EXCEPTION_EXIT_UNWIND(0x4)")
        if fl & 0x10:
            fdesc.append("EXCEPTION_STACK_INVALID(0x10)")
        if fl & 0x20:
            fdesc.append("EXCEPTION_NESTED_CALL(0x20)")
        P("  flag bits                 : %s" % (", ".join(fdesc) if fdesc else "(none)"))
        P("ExceptionRecord (nested)    : %s" % hexv(ex["exception_record"]))
        P("ExceptionAddress            : %s" % ex["exception_address_hex"])
        P("NumberParameters            : %d" % ex["number_parameters"])
        for i, v in enumerate(ex["exception_information"]):
            P("  ExceptionInformation[%d]   : %s (%d)" % (i, hexv(v), v))
        P("ThreadContext present       : %s (DataSize=0x%X, Rva=0x%X)" %
          (ex["thread_context_present"], ex["thread_context_size"],
           ex["thread_context_rva"]))
        P("raw ExceptionRecord bytes   : %s" % ex["raw_exception_record_hex"])
        P("")

        # ---- interpretation of the parameters
        P("--- exception parameter interpretation ---")
        if ex["exception_code"] == 0xC0000005:
            op = ex["exception_information"][0] if ex["number_parameters"] >= 1 else None
            fa = ex["exception_information"][1] if ex["number_parameters"] >= 2 else None
            P("ACCESS VIOLATION:")
            P("  operation          : %d = %s" % (op, ACCESS_OP.get(op, "unknown")))
            P("  faulting address   : %s (%d)" % (hexv(fa), fa))
            if fa is not None:
                if fa == 0:
                    P("  verdict            : EXACT NULL POINTER dereference")
                elif fa < 0x1000:
                    P("  verdict            : NEAR-NULL (%d = 0x%X) - null base + small offset "
                      "/ null struct field" % (fa, fa))
                elif fa < 0x10000:
                    P("  verdict            : NEAR-NULL low address (0x%X)" % fa)
                else:
                    P("  verdict            : not null - a real (wild or stale) address")
        elif ex["exception_code"] == 0xC0000409:
            sub = ex["exception_information"][0] if ex["number_parameters"] >= 1 else None
            P("FAIL-FAST / __fastfail (0xC0000409):")
            P("  subcode            : %d (0x%X) = %s" %
              (sub, sub, FASTFAIL_CODES.get(sub, "unknown subcode")))
            P("  NOTE: on x64 `__fastfail` is the `int 0x29` instruction; the recorded")
            P("        ExceptionAddress is the int 0x29 site, i.e. inside the CRT or a")
            P("        security check, NOT the original caller.")
        elif ex["exception_code"] == 0xC00000FD:
            P("STACK OVERFLOW: genuine stack exhaustion (or a huge stack allocation).")
        elif ex["exception_code"] == 0xC0000026:
            P("STATUS_INVALID_DISPOSITION (0xC0000026):")
            P("  this is NOT an access violation. The OS raises it when an exception handler")
            P("  (SEH __except / vectored handler / unhandled-exception filter) returns a")
            P("  disposition value that is none of ExceptionContinueExecution(0),")
            P("  ExceptionContinueSearch(1), ExceptionNestedException(2), ExceptionCollidedUnwind(3).")
            P("  NumberParameters is 0, so this record carries NO faulting address.")
            P("  It is almost always a SECONDARY exception: the original fault is elsewhere. Check")
            P("  the stack for a buried EXCEPTION_RECORD with a different code (this tool does).")
        elif ex["exception_code"] == 0xE06D7363:
            P("C++ throw: an unhandled MSVC C++ exception propagated out of the process.")
        elif ex["exception_code"] == 0x80000003:
            P("BREAKPOINT: a debugger breakpoint (int 3) was hit with no debugger attached,")
            P("            or a deliberate __debugbreak()/assert.")
        else:
            P("(no special-cased interpretation for this code)")
        P("")

    # ---------------------------------------------------------- 2. modules
    modstream = next((s for s in streams if s["stream_type"] == ST_ModuleList), None)
    mods = []
    modmap = ModuleMap(mods)
    P("=" * 78)
    P("2. MODULE LIST (stream type 4)")
    P("=" * 78)
    if modstream is None:
        P("NO ModuleListStream present.")
    else:
        mods = parse_modules(d, modstream)
        modmap = ModuleMap(mods)
        result["modules"] = mods
        in_file_order_sorted = all(mods[i]["base"] <= mods[i + 1]["base"]
                                   for i in range(len(mods) - 1))
        P("on-disk module order is ascending by base: %s" % in_file_order_sorted)
        result["module_order_ascending"] = in_file_order_sorted
        mods_sorted = sorted(mods, key=lambda m: m["base"])
        P("%d modules, sorted by base address" % len(mods_sorted))
        P("")
        P("%-3s %-18s %-10s %-11s %-16s %s" %
          ("#", "base", "size", "timestamp", "version", "name"))
        for i, m in enumerate(mods_sorted):
            P("%-3d %-18s 0x%08X 0x%08X  %-16s %s" %
              (i, m["base_hex"], m["size"], m["timestamp"],
               m["file_version"], m["name"]))
        P("")
        P("--- game.dll specifically ---")
        gd = [m for m in mods_sorted if os.path.basename(m["name"]).lower() == "game.dll"]
        if not gd:
            P("  !! no module literally named 'game.dll' in the module list")
            near = [m for m in mods_sorted if "game" in os.path.basename(m["name"]).lower()]
            for m in near:
                P("  candidate: %s base=%s size=0x%08X ts=0x%08X ver=%s" %
                  (m["name"], m["base_hex"], m["size"], m["timestamp"],
                   m["file_version"]))
        for m in gd:
            P("  name      : %s" % m["name"])
            P("  base      : %s" % m["base_hex"])
            P("  size      : 0x%08X (%d bytes)" % (m["size"], m["size"]))
            P("  end       : %s" % hexv(m["end"]))
            P("  timestamp : 0x%08X (%d)" % (m["timestamp"], m["timestamp"]))
            P("  version   : %s" % m["file_version"])
            P("  checksum  : %s" % m["checksum"])
            P("  CV record : DataSize=0x%X Rva=0x%X (CodeView pdb info %s)" %
              (m["cv_size"], m["cv_rva"],
               "present" if m["has_cv"] else "absent"))
        P("")
        # dump a couple of interesting third-party modules
        P("--- non-Microsoft / notable modules (heuristic name filter) ---")
        for m in mods_sorted:
            b = os.path.basename(m["name"]).lower()
            if b in ("game.dll",) or "system32" in m["name"].lower():
                continue
            if any(k in b for k in ("bingus", "loader", "addon", "mod", "d3d",
                                    "dxgi", "nv", "amd", "vulkan", "steam",
                                    "discord", "overlay", "eas", "anticheat",
                                    "denuvo", "vgk", "battleye", "eac")):
                P("  %-18s 0x%08X 0x%08X %-16s %s" %
                  (m["base_hex"], m["size"], m["timestamp"],
                   m["file_version"], m["name"]))
        P("")

    # ---------------------------------------------------------- threads
    thrstream = next((s for s in streams if s["stream_type"] == ST_ThreadList), None)
    threads = []
    if thrstream is not None:
        threads = parse_threads(d, thrstream)
        result["threads"] = threads
    P("=" * 78)
    P("THREADS (stream type 3) - context availability")
    P("=" * 78)
    if not threads:
        P("NO ThreadListStream present.")
    else:
        P("%d threads" % len(threads))
        for t in sorted(threads, key=lambda x: x["thread_id"]):
            mark = ""
            if ex and t["thread_id"] == ex["thread_id"]:
                mark = "   <== FAULTING THREAD"
            P("  tid=%-6d (0x%-5X) stack=[%s .. %s) size=0x%-8X ctx=%s size=0x%-5X%s" %
              (t["thread_id"], t["thread_id"], t["stack_start_hex"],
               t["stack_end_hex"], t["stack_size"],
               "YES" if t["context_present"] else "NO ",
               t["context_size"], mark))
        if ex:
            ft = next((t for t in threads if t["thread_id"] == ex["thread_id"]), None)
            P("")
            P("faulting thread %d present in ThreadListStream: %s" %
              (ex["thread_id"], "YES" if ft else "NO"))
            if ft:
                P("  MINIDUMP_THREAD.Context present : %s (size=0x%X rva=0x%X)" %
                  (ft["context_present"], ft["context_size"], ft["context_rva"]))
                P("  ExceptionStream.ThreadContext   : size=0x%X rva=0x%X" %
                  (ex["thread_context_size"], ex["thread_context_rva"]))
                same = (ft["context_rva"] == ex["thread_context_rva"])
                P("  same CONTEXT blob?              : %s" % ("YES" if same else "NO"))
        P("")

    # ---------------------------------------------------------- 3. faulting loc
    P("=" * 78)
    P("3. FAULTING LOCATION - CONTEXT layout verification (AMD64)")
    P("=" * 78)
    ranges = parse_memory_ranges(d, streams)
    rangemap = RangeMap(ranges)
    result["memory_range_count"] = len(ranges)
    ctx = None
    if ex is None or not ex["thread_context_present"]:
        P("No faulting-thread CONTEXT available (ExceptionStream missing or empty).")
    else:
        rva = ex["thread_context_rva"]
        size = ex["thread_context_size"]
        P("CONTEXT blob: rva=0x%X size=0x%X (%d bytes)" % (rva, size, size))
        P("sizeof(CONTEXT) on x64 = 0x4D0 = %d bytes; blob is %s" %
          (CTX_SIZE, ">= that" if size >= CTX_SIZE else "SMALLER than that"))
        P("")
        P("first 0x60 bytes of the blob (raw evidence):")
        P(d.hexdump(rva, 0x60))
        P("")
        P("candidate placements of the CONTEXT base inside the blob:")
        P("  (an optional MINIDUMP_CONTEXT wrapper would shift the CONTEXT by 0x10)")
        P("")
        P("  %-10s %-12s %-8s %-18s %-18s %s" %
          ("base", "CtxFlags", "SegCs", "Rip", "Rsp", "check"))
        candidates = []
        for base in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40):
            if base + 0x100 > size:
                continue
            c = read_context(d, rva, base)
            flags_ok = (c["context_flags"] & CONTEXT_AMD64) == CONTEXT_AMD64
            rip_in_mod = modmap.find(c["Rip"]) is not None
            reasons = "flagsAMD64=%s ripInModule=%s segcs=0x%04X" % (
                flags_ok, rip_in_mod, c["seg_cs"])
            P("  0x%02X       %-12s 0x%04X   %-18s %-18s %s" %
              (base, c["context_flags_hex"], c["seg_cs"], c["Rip_hex"],
               c["Rsp_hex"], reasons))
            candidates.append((flags_ok, rip_in_mod, base, c))
        P("")
        good = [x for x in candidates if x[0]]
        if good:
            # prefer a candidate whose Rip is inside a module
            good.sort(key=lambda x: (not x[1],))
            _, _, base, ctx = good[0]
        else:
            P("!! no candidate had CONTEXT_AMD64 set in ContextFlags - falling back to 0x00")
            ctx = read_context(d, rva, 0x00)
            base = 0x00
        P("CHOSEN base offset within the blob: 0x%02X" % base)
        P("  justification: ContextFlags=%s has CONTEXT_AMD64 (0x00100000) set, SegCs=0x%04X"
          % (ctx["context_flags_hex"], ctx["seg_cs"]))
        if modmap.find(ctx["Rip"]) is not None:
            P("  and Rip=%s lands inside a loaded module (%s)"
              % (ctx["Rip_hex"], modmap.describe(ctx["Rip"])))
        else:
            P("  (Rip=%s does NOT land inside a loaded module - treat with care)"
              % ctx["Rip_hex"])
        P("")
        result["context"] = dict(ctx)
        result["context"]["chosen_base_offset"] = base
        P("full register file (AMD64 CONTEXT, base 0x%02X):" % base)
        P("  ContextFlags = %s   MxCsr = %s   EFlags = %s" %
          (ctx["context_flags_hex"], ctx["mxcsr"], ctx["eflags"]))
        P("  SegCs=0x%04X SegDs=0x%04X SegEs=0x%04X SegFs=0x%04X SegGs=0x%04X SegSs=0x%04X" %
          (ctx["seg_cs"], ctx["seg_ds"], ctx["seg_es"], ctx["seg_fs"],
           ctx["seg_gs"], ctx["seg_ss"]))
        P("  Dr0=%s Dr1=%s Dr2=%s Dr3=%s" % (ctx["dr0_hex"], ctx["dr1_hex"],
                                             ctx["dr2_hex"], ctx["dr3_hex"]))
        P("  Dr6=%s Dr7=%s" % (ctx["dr6_hex"], ctx["dr7_hex"]))
        for name, _ in REG_OFFSETS:
            P("  %-4s = %s" % (name, ctx[name + "_hex"]))
        P("")

        rip = ctx["Rip"]
        rsp = ctx["Rsp"]
        P("--- address mapping ---")
        P("Rip = %s" % hexv(rip))
        if modmap.find(rip):
            m = modmap.find(rip)
            P("      -> %s (module base %s, offset 0x%X)" %
              (modmap.describe(rip), m["base_hex"], rip - m["base"]))
        else:
            P("      -> NOT inside any loaded module")
        P("Rsp = %s" % hexv(rsp))
        m = modmap.find(rsp)
        P("      -> %s" % ("inside module " + modmap.describe(rsp) if m
                           else "not in a module (normal - stacks are private memory)"))
        if ex and ex["exception_code"] == 0xC0000005 and ex["number_parameters"] >= 2:
            fa = ex["exception_information"][1]
            P("faulting address from ExceptionInformation[1] = %s" % hexv(fa))
            if modmap.find(fa):
                mm_ = modmap.find(fa)
                P("      -> %s (module base %s, offset 0x%X)" %
                  (modmap.describe(fa), mm_["base_hex"], fa - mm_["base"]))
            else:
                P("      -> NOT inside any loaded module")
        P("")
        P("--- every register value that points into a module ---")
        for name, _ in REG_OFFSETS:
            v = ctx[name]
            if v == 0:
                continue
            m = modmap.find(v)
            in_reg = (name in ("Rip",))
            if m:
                P("  %-4s = %-18s -> %s+0x%X" % (name, hexv(v),
                                                  os.path.basename(m["name"]),
                                                  v - m["base"]))
            elif name in ("Rsp", "Rbp"):
                P("  %-4s = %-18s -> (outside modules - expected for stack)" % (name, hexv(v)))
        P("")
        P("  saved non-volatile candidates (these often still hold the caller's state):")
        for name in ("Rbx", "Rbp", "Rsi", "Rdi", "R12", "R13", "R14", "R15"):
            P("    %-4s = %s" % (name, ctx[name + "_hex"]))
        P("")

        # ---- cross-check the two CONTEXT blobs the dump carries for this thread
        ft = next((t for t in threads if t["thread_id"] == ex["thread_id"]), None)
        if ft and ft["context_present"] and ft["context_rva"] != ex["thread_context_rva"]:
            P("--- the dump carries TWO CONTEXT blobs for this thread ---")
            P("    ExceptionStream.ThreadContext rva=0x%X" % ex["thread_context_rva"])
            P("    MINIDUMP_THREAD.Context     rva=0x%X" % ft["context_rva"])
            c1 = read_context(d, ex["thread_context_rva"], base)
            c2 = read_context(d, ft["context_rva"], base)
            P("    %-6s %-20s %-20s %s" % ("reg", "ExceptionStream", "ThreadList", "same?"))
            for name, _ in REG_OFFSETS:
                same = c1[name] == c2[name]
                P("    %-6s %-20s %-20s %s" % (name, c1[name + "_hex"],
                                              c2[name + "_hex"],
                                              "yes" if same else "**NO**"))
            P("    (ExceptionFlags 0x81 vs ThreadList Rsi=0x81 suggest the ThreadList blob is")
            P("     the same capture; differences here are worth knowing about.)")
            P("")

        # ---- code bytes at RIP, if the dump captured the image memory
        P("--- instruction bytes at RIP (only if that memory was captured) ---")
        ripb, rr = read_mem(d, rangemap, ctx["Rip"], 48)
        if ripb is None:
            P("RIP %s is NOT covered by any captured memory range -> cannot read code."
              % ctx["Rip_hex"])
        else:
            P("captured region: base=%s size=0x%X" % (hexv(rr["start"]), rr["size"]))
            P(d.hexdump(rr["file_offset"] + (ctx["Rip"] - rr["start"]), len(ripb)))
        P("")
        P("--- search around RIP for a STATUS_INVALID_DISPOSITION (0xC0000026) immediate ---")
        code, rr2 = read_mem(d, rangemap, ctx["Rip"] - 0x800, 0x1200)
        if code is None:
            P("could not read the code window around RIP (memory not captured).")
        else:
            win_base = rr2["file_offset"] + ((ctx["Rip"] - 0x800) - rr2["start"])
            needle = b"\x26\x00\x00\xc0"
            hits = []
            i = code.find(needle)
            while i != -1 and len(hits) < 40:
                hits.append(i)
                i = code.find(needle, i + 1)
            P("window scanned: [RIP-0x800 .. RIP+0xA00), %d bytes, %d occurrences of the"
              % (len(code), len(hits)))
            P("little-endian dword 26 00 00 C0:")
            for h in hits:
                prev = code[h - 1] if h > 0 else None
                rel = (ctx["Rip"] - 0x800 + h) - ctx["Rip"]
                P("    file off 0x%X  rip%+d  preceding byte %s" %
                  (win_base + h, rel, ("%02X" % prev) if prev is not None else "--"))
            # also look for the whole-value qword form used by RaiseException args
            P("")
            P("context: does `int 3`/`int 0x29` (fastfail) appear immediately at RIP?")
            if ripb:
                first = ripb[0]
                P("    first byte at RIP = 0x%02X %s" % (
                    first,
                    {0xCC: "= int 3 (breakpoint)", 0xC3: "= ret",
                     0xCD: "= int imm8 (check next byte)"}.get(first, "")))
                if first == 0xCD and len(ripb) > 1:
                    P("    int 0x%02X" % ripb[1])
        P("")

    # ---------------------------------------------------------- 5. memory info
    mi = parse_memory_info(d, streams)
    mimap = MemInfoMap(mi)
    result["memory_info"] = mi

    P("=" * 78)
    P("5. MEMORY INFO (stream type 16)")
    P("=" * 78)
    if mi is None:
        P("NO MemoryInfoListStream (type 16) in this dump - VirtualQuery-style")
        P("protection/state data is therefore NOT available from this file.")
    else:
        P("MemoryInfoListStream: header_size=%d entry_size=%d entries=%d" %
          (mi["header_size"], mi["entry_size"], mi["count"]))
        for label, addr in (("faulting address",
                             ex["exception_information"][1]
                             if (ex and ex["exception_code"] == 0xC0000005
                                 and ex["number_parameters"] >= 2) else None),
                            ("ExceptionAddress",
                             ex["exception_address"] if ex else None),
                            ("RSP", ctx["Rsp"] if ctx else None),
                            ("RIP", ctx["Rip"] if ctx else None)):
            if addr is None:
                continue
            e = mimap.find(addr)
            P("")
            P("%s = %s" % (label, hexv(addr)))
            if e is None:
                P("   -> no MEMORY_BASIC_INFORMATION entry covers this address")
                P("      (the region is not described by the dump)")
            else:
                P("   base             = %s" % hexv(e["base"]))
                P("   allocation base  = %s" % hexv(e["allocation_base"]))
                P("   region size      = 0x%X (%d bytes)" % (e["region_size"], e["region_size"]))
                P("   state            = %s" % state_str(e["state"]))
                P("   protect          = %s" % prot_str(e["protect"]))
                P("   alloc protect    = %s" % prot_str(e["allocation_protect"]))
                P("   type             = %s" % type_str(e["type"]))
                P("   offset in region = 0x%X" % (addr - e["base"]))
    P("")

    P("--- memory ranges actually captured in the file ---")
    if not ranges:
        P("NO MemoryListStream (5) and NO Memory64ListStream (9): no memory bytes are")
        P("in this dump - it is a metadata-only (triage) dump.")
    else:
        P("%d captured regions, %d bytes total" %
          (len(ranges), sum(r["size"] for r in ranges)))
    P("")

    # ---------------------------------------------------------- 4. stack walk
    P("=" * 78)
    P("4. ROUGH STACK WALK  (HEURISTIC - no unwind data, no symbols)")
    P("=" * 78)
    P("Method: read the stack bytes captured for the region containing RSP and print")
    P("every 8-byte-aligned qword that falls inside a loaded module's [base,base+size).")
    P("This is NOT a real unwind: it includes stale frames, saved registers, unrelated")
    P("data and false positives. Treat it as an ordered list of suspects only.")
    P("")
    stack_hits = []
    if ctx is None:
        P("No faulting-thread CONTEXT: cannot walk.")
    elif not ranges:
        P("No memory captured in the dump: cannot walk.")
    else:
        rsp = ctx["Rsp"]
        info, hits = scan_module_pointers(d, rangemap, modmap, rsp, max_stack)
        stack_hits = hits
        result["stack_hits"] = hits
        result["stack_region"] = info
        if info is None:
            P("RSP %s is not inside any memory range present in this dump." % hexv(rsp))
            P("The faulting thread's stack bytes were NOT captured, so no stack scan")
            P("is possible. (Reported explicitly - not an error in the parser.)")
        else:
            P("stack region containing RSP : base=%s size=0x%X (source=%s)" %
              (info["region_start_hex"], info["region_size"], info["source"]))
            P("RSP offset into that region : 0x%X" % (rsp - info["region_start"]))
            P("bytes captured from RSP up  : 0x%X of 0x%X available" %
              (info["scanned_bytes"], info["available_bytes"]))
            P("module-pointing qwords      : %d" % len(hits))
            P("")
            from collections import Counter
            cnt = Counter(h["module"] for h in hits)
            P("distribution by module:")
            for name, c in cnt.most_common():
                P("  %-40s %d" % (name, c))
            P("")
            P("distinct pointer VALUES and how often each appears (the repeating pattern")
            P("is the single most informative thing about this stack):")
            vc = Counter((h["value"], h["module"], h["offset"]) for h in hits)
            P("  %-6s %-18s %s" % ("count", "value", "maps to"))
            for (v, modn, off), c in vc.most_common(40):
                P("  %-6d %-18s %s+0x%X" % (c, hexv(v), modn, off))
            P("  (%d distinct values total)" % len(vc))
            # spacing analysis: is this a recursion?
            uniq_addrs = [h["stack_addr"] for h in hits]
            if len(uniq_addrs) > 3:
                P("")
                P("stack-address spacing between consecutive hits (top 12 deltas):")
                deltas = Counter(uniq_addrs[i + 1] - uniq_addrs[i]
                                 for i in range(len(uniq_addrs) - 1))
                for d_, c in deltas.most_common(12):
                    P("  delta 0x%-6X (%d bytes) x%d" % (d_, d_, c))
            P("")
            gd_hits = [h for h in hits
                       if h["module"].lower() == "game.dll"]
            P("qwords mapping into game.dll : %d" % len(gd_hits))
            if gd_hits:
                P("  game.dll stack hits (offset from game.dll base):")
                for h in gd_hits[:80]:
                    P("    stack %s -> game.dll+0x%X  (value %s)" %
                      (h["stack_addr_hex"], h["offset"], h["value_hex"]))
                if len(gd_hits) > 80:
                    P("    ... %d more" % (len(gd_hits) - 80))
            P("")
            cap = 200
            P("full ordered list (%d entries%s):" %
              (len(hits), "" if len(hits) <= cap else ", truncated to %d" % cap))
            P("  %-18s %-18s %s" % ("stack address", "value", "maps to"))
            for h in hits[:cap]:
                P("  %-18s %-18s %s+0x%X" %
                  (h["stack_addr_hex"], h["value_hex"], h["module"], h["offset"]))
            P("")

            # string scan
            P("--- strings on the faulting thread's stack ---")
            region = rangemap.find(rsp)
            data = d.raw(region["file_offset"] + (rsp - region["start"]),
                         min(region["start"] + region["size"] - rsp, max_stack))
            strs = scan_strings(data, rsp, min_len=6)
            result["stack_strings"] = strs
            P("found %d distinct ascii/utf-16 strings (len>=6) between RSP and RSP+0x%X" %
              (len(strs), len(data)))
            scored = []
            for s in strs:
                sc, hits_kw = score_string(s["text"])
                if sc > 0:
                    scored.append((sc, hits_kw, s))
            scored.sort(key=lambda x: (-x[0], x[2]["addr"]))
            P("")
            P("most interesting (%d of %d):" % (min(len(scored), 80), len(strs)))
            for sc, hits_kw, s in scored[:80]:
                P("  [%s] %s score=%d %s" % (s["kind"], s["addr_hex"], sc,
                                             s["text"][:220]))
            P("")
            P("first 40 strings by address (context, unfiltered):")
            for s in sorted(strs, key=lambda x: x["addr"])[:40]:
                P("  [%s] %s %s" % (s["kind"], s["addr_hex"], s["text"][:160]))
            P("")

            # ---- buried EXCEPTION_RECORD structures on the stack
            P("--- EXCEPTION_RECORD-shaped structures found in the stack bytes ---")
            recs = scan_exception_records(data, rsp, modmap)
            result["stack_exception_records"] = recs
            if not recs:
                P("none found (no structure with a known exception code, flags<=0x100,")
                P("NumberParameters<=15, nested record == 0 and an ExceptionAddress inside")
                P("a loaded module).")
            else:
                P("FOUND %d candidate(s). A buried record can reveal the ORIGINAL exception"
                  % len(recs))
                P("that was being dispatched when the final 0xC0000026 was raised:")
                for r_ in recs:
                    P("  at stack %s" % r_["mem_addr_hex"])
                    P("    ExceptionCode      = %s  %s" % (r_["code_hex"], r_["name"]))
                    P("    ExceptionFlags     = %s" % r_["flags"])
                    P("    ExceptionAddress   = %s  (%s)" % (r_["address_hex"],
                                                              r_["address_module"]))
                    P("    NumberParameters   = %d" % r_["number_parameters"])
                    for i, v in enumerate(r_["information_hex"]):
                        P("    ExceptionInformation[%d] = %s (%d)" %
                          (i, v, r_["information"][i]))
            P("")

    # ---------------------------------------------------------- extras
    P("=" * 78)
    P("EXTRA STREAMS")
    P("=" * 78)
    si = next((s for s in streams if s["stream_type"] == ST_SystemInfo), None)
    if si:
        info = parse_system_info(d, si)
        result["system_info"] = info
        archs = {0: "INTEL", 5: "ARM", 6: "IA64", 9: "AMD64", 12: "ARM64"}
        P("SystemInfoStream: arch=%s(%d) cpus=%d ver=%d.%d build=%d platform=%d" %
          (archs.get(info["processor_architecture"], "?"),
           info["processor_architecture"], info["number_of_processors"],
           info["major_version"], info["minor_version"], info["build_number"],
           info["platform_id"]))
        P("  CSD version: %s" % info["csd_version"])
    minf = next((s for s in streams if s["stream_type"] == ST_MiscInfo), None)
    if minf:
        minfo = parse_misc_info(d, minf)
        result["misc_info"] = minfo
        P("MiscInfoStream: %s" % json.dumps(minfo, sort_keys=True))
        for k in ("process_create_time", "process_user_time", "process_kernel_time"):
            if k in minfo:
                P("  %-20s = %d = %s" % (k, minfo[k], fmt_ts(minfo[k])))
    for st, key in ((ST_CommentA, "A"), (ST_CommentW, "W")):
        cs = next((s for s in streams if s["stream_type"] == st), None)
        if cs:
            data = d.raw(cs["rva"], cs["data_size"])
            txt = (data.decode("ascii", errors="replace") if key == "A"
                   else data.decode("utf-16-le", errors="replace"))
            result["comment_" + key] = txt
            P("CommentStream%s (%d bytes): %s" % (key, cs["data_size"], txt[:4000]))
    P("")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1, default=str)
        P("[wrote %s]" % json_out)


if __name__ == "__main__":
    main()
