"""Compile the addon source with the game's own Lua (LuaJIT)."""
import sys
from pathlib import Path
from lupa.luajit21 import LuaRuntime

path = Path(sys.argv[1])
src = path.read_text(encoding='utf-8')
lua = LuaRuntime()
lua.globals().SRC = src
result = lua.execute(
    'local f, e = load(SRC, "@addon")\n'
    'if f then return "COMPILES OK" else return e end'
)
print(result)
for token in ('goto ', '//', '<<', '>>', 'math.type', 'string.pack', 'table.move'):
    if token in src:
        print('FORBIDDEN TOKEN PRESENT: %r' % token)
sys.exit(0 if result == 'COMPILES OK' else 1)
