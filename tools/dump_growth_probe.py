#!/usr/bin/env python3
"""Freeze one dump generation and probe the live growth of the WER dump set.

Two jobs:

  `snapshot`  - copy the newest dump generation that is not still being written
                into a stable file, verify it parses, and report its identity
                (name, size, mtime) so a report can name exactly what it read.

  `probe`     - sample every dump file's key fields (header timestamp, PID,
                process create time, exception code/address, faulting Rsp and
                the thread's captured stack range) on an interval, to show that
                the set is live and whether the stack is still growing.

Usage:
  python tools/dump_growth_probe.py snapshot [--out PATH]
  python tools/dump_growth_probe.py probe [--seconds 180] [--interval 15]
"""

import glob
import os
import shutil
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import minidump_crash as m  # noqa: E402

DIR = r"C:\Users\kugua\AppData\Local\CrashDumps"
PATTERN = os.path.join(DIR, "helldivers2.exe*.23892.dmp")

FIELDS = ["mtime", "size", "hdr_ts", "pid", "proc_create", "exc_code",
          "exc_addr", "tid", "rsp", "rip", "stack_start", "stack_size",
          "nthreads", "nmodules"]


def quick_scan(path):
    """Read only the small header/directory streams - safe on a live file."""
    out = dict(path=path, name=os.path.basename(path))
    try:
        st = os.stat(path)
        out["size"] = st.st_size
        out["mtime"] = st.st_mtime
    except OSError as e:
        out["error"] = "stat: %s" % e
        return out
    f = None
    try:
        f = open(path, "rb")
        data = f.read(0x20000)  # header + stream directory + small streams
    except OSError as e:
        out["error"] = "read: %s" % e
        return out
    finally:
        if f:
            f.close()
    if len(data) < 0x40 or data[:4] != b"MDMP":
        out["error"] = "not a complete MDMP yet (%d bytes readable)" % len(data)
        return out
    try:
        hdr_flags = struct.unpack_from("<Q", data, 24)[0]
        nstreams = struct.unpack_from("<I", data, 8)[0]
        out["hdr_ts"] = struct.unpack_from("<I", data, 20)[0]
        out["flags"] = "0x%X" % hdr_flags
        dir_rva = struct.unpack_from("<I", data, 12)[0]
        streams = {}
        for i in range(nstreams):
            o = dir_rva + 12 * i
            stype, dsize, srva = struct.unpack_from("<III", data, o)
            streams[stype] = (dsize, srva)
        out["stream_types"] = sorted(streams)
        # exception
        if 6 in streams and streams[6][1] + 176 <= len(data):
            rva = streams[6][1]
            out["tid"] = struct.unpack_from("<I", data, rva)[0]
            out["exc_code"] = "0x%08X" % struct.unpack_from("<I", data, rva + 8)[0]
            out["exc_flags"] = "0x%08X" % struct.unpack_from("<I", data, rva + 12)[0]
            out["exc_addr"] = "0x%016X" % struct.unpack_from("<Q", data, rva + 24)[0]
            ctx_rva = struct.unpack_from("<I", data, rva + 164)[0]
            if ctx_rva + 0x100 <= len(data):
                out["rsp"] = "0x%016X" % struct.unpack_from("<Q", data, ctx_rva + 0x98)[0]
                out["rip"] = "0x%016X" % struct.unpack_from("<Q", data, ctx_rva + 0xF8)[0]
                out["ctx_flags"] = "0x%08X" % struct.unpack_from("<I", data, ctx_rva + 0x30)[0]
        # threads
        if 3 in streams and streams[3][1] + 8 <= len(data):
            rva = streams[3][1]
            n = struct.unpack_from("<I", data, rva)[0]
            out["nthreads"] = n
            if n and rva + 4 + 48 <= len(data):
                out["stack_start"] = "0x%016X" % struct.unpack_from("<Q", data, rva + 4 + 24)[0]
                out["stack_size"] = "0x%X" % struct.unpack_from("<I", data, rva + 4 + 32)[0]
        # modules
        if 4 in streams and streams[4][1] + 4 <= len(data):
            out["nmodules"] = struct.unpack_from("<I", data, streams[4][1])[0]
        # misc info
        if 15 in streams and streams[15][1] + 24 <= len(data):
            rva = streams[15][1]
            f1 = struct.unpack_from("<I", data, rva + 4)[0]
            if f1 & 1:
                out["pid"] = struct.unpack_from("<I", data, rva + 8)[0]
            if f1 & 2:
                out["proc_create"] = struct.unpack_from("<I", data, rva + 12)[0]
    except Exception as e:  # a partially written file can yield anything
        out["error"] = "parse: %r" % e
    return out


def cmd_snapshot(argv):
    out_path = os.path.join(os.environ.get("TEMP", "."), "hd2_snapshot.dmp")
    if "--out" in argv:
        out_path = argv[argv.index("--out") + 1]
    files = glob.glob(PATTERN)
    files.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
    print("dump files found: %d" % len(files))
    for p in files:
        st = os.stat(p)
        print("  %s  %12d  %s" % (os.path.basename(p), st.st_size,
                                  time.strftime("%H:%M:%S", time.localtime(st.st_mtime))))
    # newest is probably still being written; try from the second newest down
    for p in files[1:] + files[:1]:
        st = os.stat(p)
        mtime_before = st.st_mtime
        size_before = st.st_size
        shutil.copyfile(p, out_path)
        time.sleep(2.0)
        st2 = os.stat(p)
        if st2.st_mtime != mtime_before or st2.st_size != size_before:
            print("skip %s - still being written" % os.path.basename(p))
            continue
        info = quick_scan(out_path)
        if "error" in info:
            print("skip %s - snapshot did not parse (%s)" % (os.path.basename(p), info["error"]))
            continue
        # full parse check on the frozen copy
        try:
            d = m.DumpFile(out_path)
            h = m.parse_header(d)
            s = m.parse_directory(d, h)
        except Exception as e:
            print("skip %s - full parse failed: %r" % (os.path.basename(p), e))
            continue
        print("")
        print("FROZEN SNAPSHOT: %s" % out_path)
        print("  source file : %s" % p)
        print("  source size : %d bytes" % size_before)
        print("  source mtime: %s" % time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime(mtime_before)))
        print("  signature   : 0x%08X" % h["signature"])
        print("  streams     : %d" % h["number_of_streams"])
        print("  hdr flags   : 0x%016X" % h["flags"])
        for k in FIELDS:
            if k in info:
                print("  %-12s: %s" % (k, info[k]))
        return 0
    print("could not freeze a stable snapshot")
    return 1


def cmd_probe(argv):
    seconds = 180
    interval = 15
    if "--seconds" in argv:
        seconds = int(argv[argv.index("--seconds") + 1])
    if "--interval" in argv:
        interval = int(argv[argv.index("--interval") + 1])
    t0 = time.time()
    hdr = ["time"] + FIELDS
    print(" | ".join("%-13s" % h for h in hdr))
    prev = {}
    while time.time() - t0 < seconds:
        files = sorted(glob.glob(PATTERN), key=lambda p: os.stat(p).st_mtime, reverse=True)
        for p in files:
            info = quick_scan(p)
            if "error" in info:
                continue
            vals = []
            for k in FIELDS:
                v = info.get(k, "-")
                if k == "mtime":
                    v = time.strftime("%H:%M:%S", time.localtime(v))
                vals.append("%-13s" % v)
            key = info["name"]
            line = " | ".join(vals)
            old = prev.get(key)
            if old != line:
                print(line)
                prev[key] = line
        time.sleep(interval)
    print("[probe finished after %ds]" % seconds)
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "snapshot"
    rest = sys.argv[2:]
    sys.exit(cmd_snapshot(rest) if cmd == "snapshot" else cmd_probe(rest))
