"""What does a *vehicle* stratagem record look like in the community snapshot?

The snapshot (manifest 6656621620609811302, 2024-09-17) predates the FRV, but it
does contain the Exosuit (COMBAT WALKER) stratagems, which are the only other
player-called vehicle. That is the same-family reference the workflow asks for:
the payload/package convention for a vehicle stratagem can be read off it.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
JSON = REPO / 'work/hddata/data/settings/generated_stratagem_settings.json'


def items():
    doc = json.loads(JSON.read_text(encoding='utf-8'))
    for group in doc:
        for it in group['StratagemSettings']['items']:
            yield it


def main():
    want = sys.argv[1:] or ['VEHICLES.']
    for it in items():
        name = it.get('debug_name', '')
        if not any(w.lower() in name.lower() for w in want):
            continue
        print('=' * 78)
        for key in ('type', 'id', 'debug_name', 'name_upper', 'name_cased',
                    'description', 'fluff', 'category', 'uses', 'spawn_time',
                    'cooldown_duration_success', 'origin_type', 'call_in_type',
                    'selectable', 'cooldown_type', 'payload', 'package', 'icon',
                    'hud_type', 'cost', 'enabled', 'depends_on',
                    'additional_stratagem', 'max_in_loadout'):
            if key in it:
                v = it[key]
                if isinstance(v, int) and v > 0xFFFFFFFF:
                    v = '%d (%#018x)' % (v, v)
                elif isinstance(v, list):
                    v = ['%d (%#018x)' % (x, x) for x in v]
                print('  %-26s %s' % (key, v))
        extra = {k: v for k, v in it.items() if k not in {
            'type', 'id', 'debug_name', 'name_upper', 'name_cased',
            'description', 'fluff', 'category', 'uses', 'spawn_time',
            'cooldown_duration_success', 'origin_type', 'call_in_type',
            'selectable', 'cooldown_type', 'payload', 'package', 'icon',
            'hud_type', 'cost', 'enabled', 'depends_on',
            'additional_stratagem', 'max_in_loadout'}}
        for k, v in extra.items():
            print('  (other) %-17s %s' % (k, v))
    return 0


if __name__ == '__main__':
    sys.exit(main())
