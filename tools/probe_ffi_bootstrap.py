"""Reproduce the in-game FFI bootstrap with the real LuaJIT FFI, on this machine.

The addon died in game with `init_failed: ...: attempt to index field 'c'` at the
fallback line, which means the PRIMARY path - `ffi.cast(ctype, kernel.VirtualQuery)`
- had already failed.  That was never diagnosed, because the typo crashed first.

lupa ships the same LuaJIT, so the exact expressions can be run here against the
real kernel32.  This tells us which of the resolution strategies actually work in
LuaJIT, and which one the game must have rejected.

    python tools/probe_ffi_bootstrap.py
"""
import sys
from lupa.luajit21 import LuaRuntime

SCRIPT = r'''
local ffi = require('ffi')
local out = {}

out.abi64 = ffi.abi('64bit')
out.has_ffi_C = (ffi.C ~= nil)
out.ffi_C_type = type(ffi.C)

ffi.cdef[[
    void *GetCurrentProcess(void);
    void *GetModuleHandleA(const char *module_name);
    void *GetProcAddress(void *module, const char *name);
    size_t VirtualQuery(const void *address, void *buffer, size_t length);
    typedef struct { void *a; void *b; uint32_t c; uint16_t d; uint16_t e;
                     size_t f; uint32_t g; uint32_t h; uint32_t i; } PROBE_MBI;
]]

local ok, kernel = pcall(ffi.load, 'kernel32')
out.load_ok = ok
out.kernel_type = type(kernel)
if not ok then
    out.load_error = tostring(kernel)
    return out
end

-- step 1: the symbol the addon actually got as far as using
local ok1, proc = pcall(function() return kernel.GetCurrentProcess() end)
out.getcurrentprocess_ok = ok1
out.getcurrentprocess_value = ok1 and tostring(proc) or tostring(proc)

-- step 2: is the symbol visible at all?
local ok2, sym = pcall(function() return kernel.VirtualQuery end)
out.symbol_ok = ok2
out.symbol_type = ok2 and type(sym) or nil
out.symbol_tostring = ok2 and tostring(sym) or tostring(sym)

-- step 3: the expression that failed in game
local ok3, cast = pcall(function()
    return ffi.cast('size_t (*)(const void *, void *, size_t)', kernel.VirtualQuery)
end)
out.cast_ok = ok3
out.cast_result_type = ok3 and type(cast) or nil
out.cast_error = ok3 and 'none' or tostring(cast)

-- step 4: the direct-call strategy the fix added
local ok4, direct = pcall(function()
    if kernel.VirtualQuery == nil then error('symbol is nil', 0) end
    return function(a, b, c)
        return tonumber(kernel.VirtualQuery(ffi.cast('const void *', a),
            ffi.cast('void *', b), c))
    end
end)
out.direct_ok = ok4
out.direct_error = ok4 and 'none' or tostring(direct)

-- step 5: GetProcAddress, using only symbols proven to work in game
local ok5, via_gpa = pcall(function()
    local handle = kernel.GetModuleHandleA('kernel32.dll')
    if handle == nil then error('GetModuleHandleA nil', 0) end
    local address = kernel.GetProcAddress(handle, 'VirtualQuery')
    if address == nil then error('GetProcAddress nil', 0) end
    local raw = tonumber(ffi.cast('uintptr_t', address))
    return ffi.cast('size_t (*)(const void *, void *, size_t)', raw)
end)
out.gpa_ok = ok5
out.gpa_error = ok5 and 'none' or tostring(via_gpa)

-- step 6: actually call whichever strategy worked and count a region
local mbi = ffi.new('PROBE_MBI[1]')
local function try(fn)
    if not fn then return 'unavailable' end
    local ok, result = pcall(fn, 0x10000, mbi, ffi.sizeof(mbi[0]))
    if not ok then return 'raised: ' .. tostring(result) end
    return 'returned ' .. tostring(result) .. ' (need 48 for x64)'
end
out.call_casted = try(ok3 and cast or nil)
out.call_direct = try(ok4 and direct or nil)
out.call_gpa = try(ok5 and via_gpa or nil)

-- step 7: does the module namespace have GetTickCount64 too (used elsewhere)?
local ok7, tick = pcall(function() return kernel.GetTickCount64() end)
out.gettickcount64_ok = ok7
out.gettickcount64_value = ok7 and tostring(tick) or tostring(tick)
return out
'''


def main():
    lua = LuaRuntime(unpack_returned_tuples=True)
    out = lua.execute(SCRIPT)
    for key in sorted(out.keys()):
        print('%-26s %s' % (key, out[key]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
