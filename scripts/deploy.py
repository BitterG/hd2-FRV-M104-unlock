"""Install the addon straight into the game's data directory (quick test path).

Why this exists: the ZIP is the right way to ship a mod, but importing it through a
mod manager is one more step that can silently fail (the manager renumbers slots on
every deploy, and the skill records it once dropping a mod entirely).  For a
30-second check it is useful to be able to drop the archive in by hand.

It is a *temporary* path and the script says so: the next Deploy from the manager
will not know about this file.  Dry run by default.

    python scripts/deploy.py                     # show what it would do
    python scripts/deploy.py --apply             # write patch_<max+1>
    python scripts/deploy.py --uninstall --apply # remove what it wrote
"""
import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL_TOOLS = REPO.parent / 'hd2-lua-mod-skill' / 'tools'
sys.path.insert(0, str(SKILL_TOOLS))
import hd2_archive as A  # noqa: E402

DEFAULT_GAME_DIR = Path(r'E:\SteamLibrary\steamapps\common\Helldivers 2')
STATE = REPO / 'work' / 'manual_deploy.json'
RESOURCE = 'mods/dsh/frv_m104'
SOURCE = REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua'
FAMILY = A.FAMILY


def slots(data_dir):
    found = {}
    for path in data_dir.glob(FAMILY + '.patch_*'):
        suffix = path.name[len(FAMILY) + len('.patch_'):]
        if suffix.isdigit():
            found[int(suffix)] = path
    return found


def build_archive():
    text = SOURCE.read_text(encoding='utf-8')
    if text.startswith('\ufeff') or '\r' in text:
        raise SystemExit('source is not LF-only / has a BOM (6.53, 6.55)')
    marker = '-- HD2-Addon: ' + RESOURCE + '\n'
    if not text.startswith(marker):
        raise SystemExit('source does not declare the addon')
    body = text.encode('utf-8')
    archive = A.make_archive({RESOURCE: A.envelope(body)})
    parsed = A.parse(archive)
    entry = parsed['entries'][0]
    if entry['body'] != body or entry['name'] != A.resource_hash(RESOURCE):
        raise SystemExit('archive round-trip failed')
    return archive


def show_loader_log():
    import os
    appdata = os.environ.get('LOCALAPPDATA')
    if not appdata:
        return
    log = Path(appdata) / 'CowboyBingus/Helldivers2/Logs/BingusSharedLoader.log'
    if not log.exists():
        print('  (no loader log yet)')
        return
    print('  last loader discovery:')
    for line in log.read_text(encoding='utf-8', errors='replace').splitlines():
        if 'Discovery' in line or 'frv_m104' in line or 'loader-v' in line:
            print('    ' + line)


def find_our_slot(data_dir):
    """The slot that already holds this addon, so an update replaces it in place.

    Deploying to a fresh slot while the manager's copy is still there would leave two
    addons with the same resource path declared to the loader, which is a confusing
    state to debug.  Only small archives are parsed: the multi-MB ones are the game's
    own data.
    """
    want = A.resource_hash(RESOURCE)
    for index, path in sorted(slots(data_dir).items()):
        if path.stat().st_size > 2_000_000:
            continue
        try:
            parsed = A.parse(path.read_bytes())
        except Exception:
            continue
        for entry in parsed['entries']:
            if entry['name'] == want:
                return index
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gamedir', default=str(DEFAULT_GAME_DIR))
    parser.add_argument('--apply', action='store_true',
                        help='actually write; without it this is a dry run')
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--new-slot', action='store_true',
                        help='force a fresh slot instead of updating in place')
    args = parser.parse_args()

    data_dir = Path(args.gamedir) / 'data'
    if not data_dir.is_dir():
        raise SystemExit('game data directory not found: %s' % data_dir)
    print('game data dir: %s' % data_dir)

    existing = slots(data_dir)
    print('  occupied slots: %s' % ', '.join(str(k) for k in sorted(existing)))
    print('  loader discovery (from the previous game run):')
    show_loader_log()

    if args.uninstall:
        if not STATE.exists():
            raise SystemExit('nothing recorded as manually deployed')
        state = json.loads(STATE.read_text(encoding='utf-8'))
        target = data_dir / state['file']
        print('\nwould remove %s' % target)
        if args.apply:
            for suffix in ('', '.stream', '.gpu_resources'):
                path = Path(str(target) + suffix)
                if path.exists():
                    path.unlink()
                    print('  removed %s' % path.name)
            STATE.unlink()
        return 0

    archive = build_archive()
    found = None if args.new_slot else find_our_slot(data_dir)
    if found is not None:
        index = found
        print('\nthis addon is already in slot %d - updating it in place' % index)
    else:
        index = (max(existing) + 1) if existing else 0
        print('\nno existing slot holds this addon - using a fresh one')
    name = '%s.patch_%d' % (FAMILY, index)
    target = data_dir / name
    print('archive: %d bytes, resource %s (hash 0x%016X)'
          % (len(archive), RESOURCE, A.resource_hash(RESOURCE)))
    print('would write %s' % target)
    print('  plus the two empty sidecars the game expects:')
    print('    %s.stream, %s.gpu_resources' % (name, name))
    if not args.apply:
        print('\n(dry run - pass --apply to write)')
        print('NOTE: this is for a quick check only.  The next Deploy from the mod')
        print('      manager will not know about this file; import the ZIP there for')
        print('      a permanent install.')
        return 0

    target.write_bytes(archive)
    Path(str(target) + '.stream').write_bytes(b'')
    Path(str(target) + '.gpu_resources').write_bytes(b'')
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({'file': name, 'resource': RESOURCE,
                                 'bytes': len(archive)}, indent=2) + '\n',
                     encoding='utf-8')
    print('\nwrote %s' % target)
    print('now start the game and sit in the ship for ~10 seconds, then read')
    print('  %%LOCALAPPDATA%%\\CowboyBingus\\Helldivers2\\Logs\\FRVM104_STATUS.txt')
    print('undo with: python scripts/deploy.py --uninstall --apply')
    return 0


if __name__ == '__main__':
    sys.exit(main())
