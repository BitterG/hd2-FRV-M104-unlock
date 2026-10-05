import json, io, sys
from pathlib import Path

p = Path(r"C:\Users\kugua\Desktop\hd2-mod\work\hddata\data\settings\generated_stratagem_settings.json")
d = json.load(io.open(p, encoding="utf-8"))
print("instances:", len(d))
total = 0
for n, inst in enumerate(d):
    items = inst["StratagemSettings"]["items"]
    total += len(items)
    print(f"\n--- instance {n}: {len(items)} records ---")
    for it in items:
        pl = it.get("payload") or []
        dbg = it.get("debug_name")
        if isinstance(dbg, int):
            dbg = f"<loc {dbg}>"
        print(f"  id={it['id']:<12} type={str(it.get('type'))[:38]:<38} "
              f"pkg={it.get('package')} icon={it.get('icon')} payload={pl} {dbg!r}")
print("\ntotal records:", total)
