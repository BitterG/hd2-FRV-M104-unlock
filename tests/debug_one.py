"""Ad-hoc driver: run one fixture and print everything the addon produced.

    python tests/debug_one.py            # absolute-pointer fixture
    python tests/debug_one.py phase2     # table only appears after a mission load
"""
import sys
import traceback
from pathlib import Path
from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_recon.lua'
HARNESS = HERE / 'harness.lua'

source = SOURCE.read_text(encoding='utf-8')
# let the traceback point at the real failure instead of being swallowed
source = source.replace('pcall(function() self:analyze_one(instance) end)',
                        'self:analyze_one(instance)')

lua = LuaRuntime(unpack_returned_tuples=True)
g = lua.globals()
g.HARNESS_SOURCE = HARNESS.read_text(encoding='utf-8')
g.ADDON_SOURCE = source
g.DshFrvM104ReconTest = True
lua.execute(
    "local chunk = assert(load(HARNESS_SOURCE, '@harness')); M = chunk();"
    "local addon = assert(load(ADDON_SOURCE, '@addon')); Recon = addon();"
)

kind = lua.table()
kind['layout'] = 'abs'
kind['count'] = 8
kind['id_at'] = 5
if len(sys.argv) > 1 and sys.argv[1] == 'phase2':
    kind['strat_in_phase2'] = True

try:
    out = lua.eval('function(k) return M.run(Recon, k) end')(kind)
except Exception:
    traceback.print_exc()
    sys.exit(1)

for key in ('phase', 'reason', 'record_hits', 'strat_count', 'census', 'sweeps',
            'self_hits', 'level_loads'):
    print('%-12s %s' % (key, out[key]))
for key in ('census_lines', 'log_lines', 'region_lines', 'strat_lines',
            'strat_dumps'):
    print('--- %s ---' % key)
    print(out[key][:3000])
