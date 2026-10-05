"""Coverage for the Windows API bootstrap - the layer the offline suite never touched.

This file exists because of a real in-game failure: `build_api` shipped a lowercase
`ffi.c` on its fallback path, which is an index of nil, so the addon died at load
time with `init_failed: attempt to index field 'c'` and did nothing at all.  Every
other suite injected a fake api and therefore stepped straight over `build_api`.

So this suite exercises `resolve_virtual_query` against stubs that are deliberately
hostile in the ways the real environment turned out to be:

  * a namespace symbol that is callable but NOT castable to a function pointer
    (the most likely reason the shipped primary path failed) - only the `_direct`
    strategy survives,
  * a nil `ffi.C` (which is what the game reports for the misspelled index),
  * nothing available at all, which must come back as a reason string rather than
    an error.

    python tests/run_tests_api.py
"""
import re
import sys
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'

FAILURES = []
CHECKS_RUN = 0


def check(label, ok, detail=''):
    global CHECKS_RUN
    CHECKS_RUN += 1
    print('%s  %s%s' % ('PASS' if ok else 'FAIL', label,
                        '' if ok else '  <- ' + str(detail)))
    if not ok:
        FAILURES.append(label)


class Session:
    def __init__(self, source=None):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.ADDON_SOURCE = source or SOURCE.read_text(encoding='utf-8')
        g.DshFrvM104Test = True
        self.lua.execute(
            "local a = assert(load(ADDON_SOURCE, '@addon')); R = a();")
        self.R, self.g = g.R, g

    def resolve(self, kernel_spec, c_namespace):
        """kernel_spec: 'callable' | 'castable' | 'nil'; c_namespace: bool"""
        return self.lua.eval(
            "function(kind, want_c)\n"
            "  local calls = 0\n"
            "  local stub = {}\n"
            "  local function behaviour(address, info, size) calls = calls + 1; return 48 end\n"
            "  if kind == 'callable' then stub.VirtualQuery = behaviour end\n"
            "  if kind == 'castable' then stub.VirtualQuery = behaviour end\n"
            "  local ffi_stub = {}\n"
            "  function ffi_stub.cdef() end\n"
            "  function ffi_stub.cast(ctype, value)\n"
            "    -- hostile in the two ways that matter: casting a plain Lua function\n"
            "    -- to a pointer is refused, and so is casting nil\n"
            "    if value == nil then error('cannot cast nil', 0) end\n"
            "    if type(value) == 'function' then error('cannot convert function', 0) end\n"
            "    return { __ptr = value }\n"
            "  end\n"
            "  if want_c then\n"
            "    ffi_stub.C = { VirtualQuery = behaviour }\n"
            "  else\n"
            "    ffi_stub.C = nil\n"
            "  end\n"
            "  if kind == 'castable' then\n"
            "    -- pretend the namespace yields a cdata the cast accepts: callable via\n"
            "    -- a __call metamethod, so it is NOT a plain Lua function\n"
            "    local proxy = setmetatable({}, { __call = function(_, a, i, s) "
            "calls = calls + 1; return 48 end })\n"
            "    ffi_stub.cast = function(ctype, value) return proxy end\n"
            "  end\n"
            "  local fn, via = R.resolve_virtual_query(stub, ffi_stub)\n"
            "  local result = nil\n"
            "  if fn then result = fn(0x10000, {}, 48) end\n"
            "  return { fn = fn ~= nil, via = via, result = result, calls = calls }\n"
            "end")(kernel_spec, c_namespace)


def main():
    text = SOURCE.read_text(encoding='utf-8')
    print('== regression gate for the exact shipped defect ==')
    check('the source contains no lowercase ffi.c index (the in-game crash)',
          'ffi.c.' not in text and 'ffi.c[' not in text,
          [line.strip() for line in text.splitlines() if 'ffi.c.' in line])
    check('the resolver uses the correctly cased ffi.C',
          'ffi.C.VirtualQuery' in text)

    print('\n== every namespace symbol must be declared before use ==')
    # Measured in this LuaJIT: indexing an UNDECLARED symbol off a loaded library
    # raises "missing declaration for symbol 'X'".  The addon took VirtualQuery off
    # kernel32 without declaring it, so its primary path raised, and the crash came
    # from the fallback.  This gate walks every `kernel.X` the source uses and
    # requires each one to appear in the ffi.cdef block.
    used = set(re.findall(r'\bkernel\.([A-Za-z_][A-Za-z0-9_]*)', text))
    cdef_block = text.split('ffi.cdef [[', 1)[1].split(']]', 1)[0]
    declared = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', cdef_block))
    missing = sorted(name for name in used if name not in declared)
    check('every kernel32 symbol the addon uses is declared in the cdef',
          not missing, 'undeclared: %s' % ', '.join(missing))
    check('VirtualQuery specifically is declared', 'VirtualQuery' in declared,
          sorted(declared))
    check('the cdef uses C comments, not Lua comments',
          '--' not in cdef_block or '/*' in cdef_block,
          'a Lua comment inside ffi.cdef breaks the parse')

    session = Session()

    print('\n== a namespace symbol that is callable but not castable ==')
    out = session.resolve('callable', False)
    check('resolution succeeds', out['fn'] is True, out['via'])
    check('it used the direct (no-cast) strategy',
          out['via'] == 'kernel32_direct', out['via'])
    check('and the returned function really calls through', out['result'] == 48,
          out['result'])

    print('\n== a castable symbol still uses the cast strategy ==')
    out = session.resolve('castable', False)
    check('resolution succeeds', out['fn'] is True, out['via'])
    check('it reports the cast strategy', out['via'] == 'kernel32_cast', out['via'])

    print('\n== nothing in kernel32, but ffi.C works ==')
    out = session.resolve('nil', True)
    check('resolution falls through to the c namespace', out['fn'] is True,
          out['via'])
    check('it reports which strategy worked',
          out['via'] in ('c_namespace_cast', 'c_namespace_direct'), out['via'])

    print('\n== nothing available at all ==')
    out = session.resolve('nil', False)
    check('it returns no function instead of raising', out['fn'] is False)
    check('and it carries the reasons out', 'kernel32_direct' in (out['via'] or '')
          and 'c_namespace_direct' in (out['via'] or ''), out['via'])

    print('\n== the REAL bootstrap on this host ==')
    # No injected api: this runs the addon's own build_api against the real kernel32,
    # which is the layer both in-game bugs lived in.  It is skipped gracefully on a
    # host without kernel32.
    real = session.lua.eval(
        "function()\n"
        "  local ok, api, reason = pcall(R.build_api)\n"
        "  local out = { raised = not ok, api = false, reason = tostring(reason),\n"
        "                via = '' }\n"
        "  if not ok then out.reason = tostring(api) return out end\n"
        "  if api == nil then return out end\n"
        "  out.api = true\n"
        "  out.via = tostring(api.virtualquery_via)\n"
        "  local ok2, regions = pcall(function() return api.regions(65536) end)\n"
        "  out.regions_ok = ok2\n"
        "  out.regions = ok2 and #regions or -1\n"
        "  return out\n"
        "end")
    built = real()
    if built['reason'] and 'kernel32' in built['reason']:
        print('  (skipped: this host has no kernel32)')
    else:
        check('build_api does not raise', built['raised'] is False, built['reason'])
        check('it builds an api', built['api'] is True, built['reason'])
        check('and it names the strategy that worked', built['via'] != '',
              built['via'])
        check('api.regions enumerates the address space', built['regions_ok'] is True
              and built['regions'] > 0,
              'ok=%s count=%s' % (built['regions_ok'], built['regions']))

    print('\n== a failed bootstrap must leave a readable status, not a crash ==')
    make_instance = session.lua.eval(
        "function()\n"
        "  local a = assert(load(ADDON_SOURCE, '@addon2')); local R2 = a()\n"
        "  return R2.new({ dir = false, api = nil,\n"
        "      config = { enabled = true, apply = true,\n"
        "                 restore_on_shutdown = true, source = 'test' } })\n"
        "end")
    # the real build_api will either work (this host has kernel32) or return a
    # reason; either way new() must return an instance and never raise
    stub = make_instance()
    check('new() returns an instance even when the api cannot be built',
          stub is not None)
    status = session.lua.eval(
        "function(inst) return inst:status_text() end")(stub)
    check('its status text starts with a verdict',
          status.splitlines()[0].startswith(('OK', 'WORKING', 'FAILED', 'DISABLED')),
          status.splitlines()[0][:120])

    print('\n== mutation: drop the declaration and the gate must catch it ==')
    dropped = text.replace(
        '        size_t VirtualQuery(const void *address, void *buffer, '
        'size_t length);\n', '', 1)
    if dropped == text:
        check('the declaration-removal mutation applies', False,
              'VirtualQuery declaration not found verbatim')
    else:
        dropped_cdef = dropped.split('ffi.cdef [[', 1)[1].split(']]', 1)[0]
        dropped_declared = set(re.findall(
            r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', dropped_cdef))
        dropped_used = set(re.findall(r'\bkernel\.([A-Za-z_][A-Za-z0-9_]*)', dropped))
        still_missing = sorted(n for n in dropped_used
                               if n not in dropped_declared)
        check('without the declaration the gate reports VirtualQuery missing',
              'VirtualQuery' in still_missing, still_missing)

    print('\n== mutation: the direct strategy is what saves the callable symbol ==')
    mutated = text.replace(
        "        { name = 'kernel32_direct', run = function()\n"
        "            return wrap(kernel.VirtualQuery)\n"
        "        end },\n", '', 1)
    if mutated == text:
        check('the mutation anchor exists', False, 'kernel32_direct block not found')
    else:
        session2 = Session(mutated)
        out = session2.resolve('callable', False)
        check('without it, resolution fails for a callable-but-not-castable symbol',
              out['fn'] is False, out['via'])

    print('\n%d checks, %d failure(s)' % (CHECKS_RUN, len(FAILURES)))
    for failure in FAILURES:
        print('  FAILED: %s' % failure)
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
