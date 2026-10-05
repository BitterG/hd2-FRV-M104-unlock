"""Run the addon's real build_api on this machine and print what it decided.

The in-game failure said the fallback line ran, which means the primary
`ffi.cast(ctype, kernel.VirtualQuery)` path had failed first.  Running the actual
function here (real LuaJIT, real kernel32) shows whether that path works and, if
not, the exact error - which is far better than inferring it from a crash site.
"""
import sys
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'


def main():
    lua = LuaRuntime(unpack_returned_tuples=True)
    g = lua.globals()
    g.SRC = SOURCE.read_text(encoding='utf-8')
    g.DshFrvM104Test = True
    lua.execute("local a = assert(load(SRC, '@addon')); R = a();")

    # 1. the resolver, in isolation, against the real kernel32
    lua.execute(
        "local ffi = require('ffi')\n"
        "PROBE = {}\n"
        "local ok, kernel = pcall(ffi.load, 'kernel32')\n"
        "PROBE.load_ok = ok\n"
        "PROBE.load_value = tostring(kernel)\n"
        "if ok then\n"
        "  local fn, via = R.resolve_virtual_query(kernel, ffi)\n"
        "  PROBE.resolved = fn ~= nil\n"
        "  PROBE.via = tostring(via)\n"
        "end\n")
    probe = g.PROBE
    print('== resolve_virtual_query against the real kernel32 ==')
    for key in ('load_ok', 'load_value', 'resolved', 'via'):
        print('  %-12s %s' % (key, probe[key]))

    # 2. the whole build_api
    lua.execute(
        "BUILT = {}\n"
        "local ok, api, reason = pcall(R.build_api)\n"
        "BUILT.ok = ok\n"
        "BUILT.api = api ~= nil\n"
        "BUILT.reason = tostring(reason)\n"
        "BUILT.via = tostring(api and api.virtualquery_via)\n")
    built = g.BUILT
    print('\n== build_api ==')
    for key in ('ok', 'api', 'via', 'reason'):
        print('  %-12s %s' % (key, built[key]))

    # 3. and the whole addon constructed for real
    make = lua.eval(
        "function()\n"
        "  return R.new({ dir = false,\n"
        "      config = { enabled = true, apply = true,\n"
        "                 restore_on_shutdown = true, source = 'probe' } })\n"
        "end")
    instance = make()
    print('\n== M104.new with the real api ==')
    print('  phase      %s' % instance['phase'])
    print('  reason     %s' % instance['reason'])
    print('  api built  %s' % (instance['api'] is not None))
    if instance['api'] is not None:
        print('  via        %s' % instance['api']['virtualquery_via'])
        # 4. does region enumeration actually work here?
        lua.execute(
            "local inst = ...\n"
            "local ok, regions = pcall(function() return inst.api.regions(65536) end)\n"
            "REGIONS = { ok = ok, count = ok and #regions or -1,\n"
            "            error = ok and '' or tostring(regions) }\n", instance)
        regions = g.REGIONS
        print('\n== api.regions ==')
        print('  ok         %s' % regions['ok'])
        print('  count      %s' % regions['count'])
        print('  error      %s' % regions['error'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
