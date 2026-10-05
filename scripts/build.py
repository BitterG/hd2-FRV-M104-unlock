"""Package the addons into installer ZIPs.

Reuses the skill's archive writer instead of hand-rolling the .patch_N layout, and
re-checks the *packaged body* rather than the source file: the BOM incident
(skill 6.53) proved that a gate compiling the source can miss what actually ships.

    python scripts/build.py            # the patcher (mods/dsh/frv_m104)
    python scripts/build.py --recon    # the read-only recon (mods/dsh/frv_m104_recon)
    python scripts/build.py --all
"""
import json
import sys
import uuid
import zipfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

REPO = Path(__file__).resolve().parent.parent
SKILL_TOOLS = REPO.parent / 'hd2-lua-mod-skill' / 'tools'
sys.path.insert(0, str(SKILL_TOOLS))
import hd2_archive as A  # noqa: E402

PATCHER_DESCRIPTION = (
    'Makes the M-102 Gunner FRV stratagem deliver the M-104 Incinerator FRV. '
    'The game data already contains the Incinerator as its own unit '
    '(frv_heavy/frv_flamer), so the change is one 8-byte payload id in the '
    'stratagem table. The addon finds that id by content, and refuses to write '
    'unless a second, definitely-live FRV stratagem (the M-103) uses the same '
    'payload field at a different record - two independent records agreeing on the '
    'field is what makes the target unambiguous. Every copy of the table is patched '
    'and re-checked; original bytes are backed up in memory and on disk and put '
    'back when the addon is retired. It never patches code and never calls '
    'VirtualProtect. Diagnostics always land in '
    '%LOCALAPPDATA%/CowboyBingus/Helldivers2/Logs. Requires Bingus Shared Loader '
    'v15 or newer (API 1 is that loader\'s own Lua API level, printed in '
    'BingusSharedLoader.log; it is not a second mod).'
)

RECON_DESCRIPTION = (
    'Phase 1 of the M-104 Incinerator FRV work: a READ-ONLY reconnaissance addon. '
    'It never writes to game memory and never patches code. It finds the '
    'stratagem table in the running game and writes a census of every LDLD data '
    'table, every occurrence of the FRV-related 64-bit ids with a hex dump, and '
    'the full bytes of every StratagemSettings table plus which record and field '
    'holds the M-102 FRV id. Requires Bingus Shared Loader v15 or newer (API 1 is '
    'that loader\'s own Lua API level, printed in BingusSharedLoader.log; it is not '
    'a second mod). Output goes to %LOCALAPPDATA%/CoxboyBingus/Helldivers2/Logs.'
).replace('CoxboyBingus', 'CowboyBingus')

UNLOCK_DESCRIPTION = (
    'Directly unlocks the native M-104 Incinerator FRV stratagem in the '
    'StratagemSettings table as a standalone stratagem, leaving the M-102 Gunner '
    'FRV 100% untouched. Activates the built-in Record 2 without causing multiplayer '
    'desync or crashes.'
)

ADDONS = {
    'patch': {
        'resource': 'mods/dsh/frv_m104',
        'source': REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua',
        'display': 'M104 FRV Standalone Unlock 3.0.0',
        'description': UNLOCK_DESCRIPTION,
        'zip': REPO.parent / 'M104-FRV-Unlock-3.0.0.zip',
        'read_only': False,
    },
    'recon': {
        'resource': 'mods/dsh/frv_m104_recon',
        'source': REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_recon.lua',
        'display': 'M104 FRV Recon 1.0 (Read-Only)',
        'description': RECON_DESCRIPTION,
        'zip': REPO.parent / 'M104-FRV-Recon-1.0.0.zip',
        'read_only': True,
    },
    'unlock': {
        'resource': 'mods/dsh/frv_m104_unlock',
        'source': REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_unlock.lua',
        'display': 'M104 FRV Standalone Unlock 1.0.0',
        'description': UNLOCK_DESCRIPTION,
        'zip': REPO.parent / 'M104-FRV-Unlock-1.0.0.zip',
        'read_only': False,
    },
}


def source_body(source, resource):
    # read_text applies universal newlines, so the body is normalised to LF here on
    # purpose: 6.55 - line endings go into the packaged body verbatim, and a
    # CRLF/LF flip between runs makes the same source produce a different mod.
    text = source.read_text(encoding='utf-8')
    if text.startswith('\ufeff'):
        raise SystemExit('%s: source starts with a UTF-8 BOM (6.53)' % source.name)
    if '\r' in text:
        raise SystemExit('%s: source contains CR: it must be LF-only (6.55)'
                         % source.name)
    marker = '-- HD2-Addon: ' + resource + '\n'
    if not text.startswith(marker):
        raise SystemExit('%s: source does not start with: %s'
                         % (source.name, marker.strip()))
    if text.count('-- HD2-Addon:') != 1:
        raise SystemExit('%s: the declaration must appear exactly once' % source.name)
    body = text[len(marker):]
    if '\ufeff' in body:
        raise SystemExit('%s: body contains U+FEFF' % source.name)
    if any(line.startswith('-- HD2-Addon:') for line in body.splitlines()):
        raise SystemExit('%s: a second declaration is hiding in the body' % source.name)
    return marker, body


def check_packaged(body_bytes, read_only):
    """Compile the exact bytes that will ship, and scan them for LuaJIT-only gaps."""
    text = body_bytes.decode('utf-8')
    runtime = LuaRuntime(unpack_returned_tuples=True)
    result = runtime.eval('(function() local f, e = load(%r, "packaged"); '
                          'if f then return "ok" else return e end end)()' % text)
    if result != 'ok':
        raise SystemExit('packaged body does not compile: %s' % result)
    problems = []
    for needle in ('VirtualProtect(', 'os.execute', 'io.popen'):
        if needle in text:
            problems.append(needle)
    if read_only:
        if 'WriteProcessMemory(' in text:
            problems.append('WriteProcessMemory(')
    elif 'WriteProcessMemory(' not in text:
        problems.append('expected WriteProcessMemory call site')
    for token in ('goto ', '//', '<<', '>>', 'math.type', 'string.pack', 'table.move'):
        if token in text:
            problems.append(token)
    if problems:
        raise SystemExit('packaged body contains forbidden constructs: %s' % problems)
    print('  packaged body: %d bytes, LuaJIT compile ok, %s'
          % (len(body_bytes),
             'read-only (no writes)' if read_only else 'one guarded data writer'))


def build(spec):
    print('== %s (%s)' % (spec['display'], spec['resource']))
    marker, body = source_body(spec['source'], spec['resource'])
    body_bytes = (marker + body).encode('utf-8')     # the loader searches the body
    if b'\r' in body_bytes:
        raise SystemExit('packaged body contains CR (6.55)')
    check_packaged(body_bytes, spec['read_only'])

    archive = A.make_archive({spec['resource']: A.envelope(body_bytes)})
    parsed = A.parse(archive)
    entry = parsed['entries'][0]
    if entry['name'] != A.resource_hash(spec['resource']):
        raise SystemExit('round-trip: resource hash mismatch')
    if entry['body'] != body_bytes:
        raise SystemExit('round-trip: body mismatch')
    print('  archive: %d bytes, resource hash 0x%016X, round-trip ok'
          % (len(archive), entry['name']))

    for illegal in '\\/:*?"<>|':
        if illegal in spec['display']:
            raise SystemExit('display name has a character Windows forbids (6.16)')
    if not spec['display'].isascii():
        raise SystemExit('display name must stay pure ASCII (6.16)')

    guid = str(uuid.uuid5(uuid.NAMESPACE_URL, 'hd2:' + spec['resource']))
    manifest = {
        'Version': 1,
        'Guid': guid,
        'Name': spec['display'],
        'Description': spec['description'],
        'Options': [
            {'Name': spec['display'], 'Description': spec['description'],
             'Include': ['Addon']},
        ],
    }
    files = {
        'manifest.json': (json.dumps(manifest, indent=2, ensure_ascii=True)
                          + '\n').encode('utf-8'),
        'Addon/' + A.ARCHIVE_NAME: archive,
        'Addon/' + A.ARCHIVE_NAME + '.stream': b'',
        'Addon/' + A.ARCHIVE_NAME + '.gpu_resources': b'',
    }
    readme = REPO / 'README.md'
    if readme.exists():
        files['README.md'] = readme.read_bytes()
    with zipfile.ZipFile(spec['zip'], 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, content)
    print('  built %s (%d bytes)' % (spec['zip'], spec['zip'].stat().st_size))
    print('  guid %s' % guid)


def main():
    args = sys.argv[1:]
    if '--all' in args:
        wanted = ['recon', 'patch', 'unlock']
    elif '--recon' in args:
        wanted = ['recon']
    elif '--unlock' in args or 'unlock' in args:
        wanted = ['unlock']
    else:
        wanted = ['patch']
    for key in wanted:
        build(ADDONS[key])
    return 0


if __name__ == '__main__':
    sys.exit(main())
