import struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import diff_frv_records as D

mem = D.parse_dump(Path(sys.argv[1]))

ADDRS = [
    (0x2ADF1CA34E4, "record0 +16 name"),
    (0x2ADF1CA3507, "record0 +24 desc"),
    (0x2ADF1CA3526, "record0 +32 third"),
    (0x2ADF1CA3548, "record0 +64 array(7 u32)"),
    (0x2ADF1CA3574, "record1 +16 name"),
    (0x2ADF1CA35D4, "record2 +16 name"),
    (0x2ADF1CA3608, "record2 +64 array"),
    (0x2ADF1CA34A0, "before record0 name"),
]
for addr, label in ADDRS:
    raw = D.read(mem, addr, 96)
    if raw is None:
        print(f"{addr:#x} {label}: unreadable")
        continue
    s = raw.split(b"\x00")[0]
    text = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in s)
    print(f"{addr:#x} {label}: len={len(s)} {text!r}")

print()
for base, label in ((0x2ADF1CA2094, "record0"), (0x2ADF1CA2224, "record1"), (0x2ADF1CA23B4, "record2")):
    body = D.read(mem, base, 400)
    print(f"{label}:")
    for off in (16, 24, 32, 64, 152):
        ptr = struct.unpack_from("<Q", body, off)[0]
        cnt = struct.unpack_from("<Q", body, off + 8)[0]
        raw = D.read(mem, ptr, 96)
        prev = D.read(mem, ptr - 1, 1)
        s = raw.split(b"\x00")[0] if raw else b""
        text = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in s)
        aligned = "" if prev and prev[0] == 0 else "  <-- NOT aligned to a string start!"
        print(f"  +{off:<4} ptr={ptr:#x} count={cnt} len={len(s)} {text!r}{aligned}")
