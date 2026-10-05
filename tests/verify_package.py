"""Verify the built installer ZIPs end to end.

Checks the things that have actually broken this ecosystem before:
  * the manifest Name is pure ASCII with no Windows-illegal character (6.16),
  * the one Addon/*.patch_0 archive parses and its resource body is byte-identical
    to the source file (so nothing was rewritten on the way into the archive),
  * the body that ships starts with the `-- HD2-Addon:` declaration (a packaged
    BOM makes the loader silently skip the mod) and carries no Lua-5.3 syntax,
  * the declared safety properties hold for the exact shipped bytes.

    python tests/verify_package.py
"""
import json
import sys
import zipfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SKILL_TOOLS = REPO.parent / 'hd2-lua-mod-skill' / 'tools'
sys.path.insert(0, str(SKILL_TOOLS))
import hd2_archive as A  # noqa: E402

PACKAGES = [
    {
        'zip': REPO.parent / 'M104-FRV-Replacer-2.3.0.zip',
        'resource': 'mods/dsh/frv_m104',
        'source': REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104.lua',
        'read_only': False,
    },
    {
        'zip': REPO.parent / 'M104-FRV-Recon-1.0.0.zip',
        'resource': 'mods/dsh/frv_m104_recon',
        'source': REPO / 'Source' / 'mods' / 'dsh' / 'frv_m104_recon.lua',
        'read_only': True,
    },
]

FAILED = []


def check(label, ok, detail=''):
    print('%s  %s%s' % ('PASS' if ok else 'FAIL', label,
                        '' if ok else '  <- ' + str(detail)))
    if not ok:
        FAILED.append(label)


def verify(spec):
    archive_name = A.FAMILY + '.patch_0'
    print('\n== %s ==' % spec['zip'].name)
    check('zip exists', spec['zip'].exists(), spec['zip'])
    if not spec['zip'].exists():
        return
    with zipfile.ZipFile(spec['zip']) as z:
        names = sorted(z.namelist())
        check('zip contains manifest.json', 'manifest.json' in names, names)
        check('zip contains Addon/%s' % archive_name,
              'Addon/' + archive_name in names, names)
        check('zip contains the README', 'README.md' in names, names)
        manifest = json.loads(z.read('manifest.json').decode('utf-8'))
        archive = z.read('Addon/' + archive_name)

    name = manifest['Name']
    check('manifest Name is pure ASCII', name.isascii(), name)
    check('manifest Name has no Windows-illegal character',
          not any(c in name for c in '\\/:*?"<>|'), name)
    check('manifest Description is written by hand (no "Enable both" template)',
          'Enable both' not in manifest['Description'])
    check('manifest Options include Addon',
          manifest['Options'][0]['Include'] == ['Addon'])

    parsed = A.parse(archive)
    check('archive advertises exactly one resource', parsed['count'] == 1,
          parsed['count'])
    entry = parsed['entries'][0]
    check('archive resource name hash matches the addon path',
          entry['name'] == A.resource_hash(spec['resource']),
          '%#x vs %#x' % (entry['name'], A.resource_hash(spec['resource'])))
    check('archive resource type is the Lua marker', entry['type'] == A.TYPE)
    check('envelope version is 2', entry['version'] == 2, entry['version'])

    body = spec['source'].read_text(encoding='utf-8').encode('utf-8')
    check('packaged body is byte-identical to the source file',
          entry['body'] == body, '%d vs %d bytes' % (len(entry['body']), len(body)))
    check('packaged body starts with the declaration',
          entry['body'].startswith(b'-- HD2-Addon: ' + spec['resource'].encode()))
    check('packaged body has no BOM', not entry['body'].startswith(b'\xef\xbb\xbf'))
    check('packaged body has no CR', b'\r' not in entry['body'])

    text = entry['body'].decode('utf-8')
    lua = LuaRuntime()
    lua.globals().SRC = text
    result = lua.execute('local f, e = load(SRC, "@packaged")\n'
                         'if f then return "ok" else return e end')
    check('packaged body compiles under LuaJIT', result == 'ok', result)
    check('packaged body never calls VirtualProtect', 'VirtualProtect(' not in text)
    if spec['read_only']:
        # match the call, not the word: the read-only addon's own comments explain
        # that it does not write, and a bare substring check trips on that prose
        check('packaged body is read-only (6.50)',
              'WriteProcessMemory(' not in text)
    else:
        check('packaged body has exactly one data writer',
              text.count('kernel.WriteProcessMemory(') == 1,
              text.count('kernel.WriteProcessMemory('))


def main():
    for spec in PACKAGES:
        verify(spec)
    print('\n%d failure(s)' % len(FAILED))
    for failure in FAILED:
        print('  FAILED: %s' % failure)
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
