"""Run the whole offline suite for the M-104 recon addon.

    python tests/run_all.py

Order matters: the constants guard runs first (a stale literal invalidates
everything downstream), then the behavioural suite with its mutations, then the
packaged artefact.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STEPS = [
    ('constants guard', HERE / 'verify_constants.py'),
    ('Windows API bootstrap (the in-game crash)', HERE / 'run_tests_api.py'),
    ('table-layout guard (real game data)', HERE / 'verify_table_layout.py'),
    ('patcher addon vs REAL game table bytes', HERE / 'run_tests_real.py'),
    ('patcher addon vs REAL stratagem field values',
     HERE / 'run_tests_reconstructed.py'),
    ('recon addon: behaviour + mutations', HERE / 'run_tests.py'),
    ('patcher addon: behaviour + mutations', HERE / 'run_tests_patch.py'),
    ('dump analyzer agrees independently', HERE / 'run_tests_analyzer.py'),
    ('packaged artefacts', HERE / 'verify_package.py'),
]


def main():
    failures = []
    for label, script in STEPS:
        print('\n' + '=' * 78)
        print('== %s (%s)' % (label, script.name))
        print('=' * 78)
        result = subprocess.run([sys.executable, str(script)], cwd=str(HERE.parent))
        if result.returncode != 0:
            failures.append(label)
    print('\n' + '=' * 78)
    if failures:
        print('FAILED: %s' % ', '.join(failures))
        return 1
    print('all offline checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
