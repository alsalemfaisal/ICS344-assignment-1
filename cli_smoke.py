"""Exercise real CLI processes using temporary private-key files."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from secure_exchange import digest


def run(student_id):
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = os.environ.copy()
        env['ICS344_KEY_PASSWORD'] = os.urandom(24).hex()

        def call(*args):
            return subprocess.run([sys.executable, 'secure_exchange.py', *map(str, args)],
                                  env=env, capture_output=True, text=True)

        state = root / 'state'
        result = call('setup', '--state', state)
        assert result.returncode == 0, result.stderr
        rows.append(dict(command='setup', exit_code=0, result=result.stdout.strip()))

        original = Path('test_data/random_1031.bin')
        for mode in ('CBC', 'CTR'):
            artifact = root / (mode + '.json')
            recovered = root / (mode + '.bin')
            result = call('send', '--state', state, '--student-id', student_id,
                          '--input', original, '--output', artifact, '--mode', mode)
            assert result.returncode == 0, result.stderr
            result = call('receive', '--state', state, '--student-id', student_id,
                          '--input', artifact, '--output', recovered)
            assert result.returncode == 0 and recovered.read_bytes() == original.read_bytes(), result.stderr
            rows.append(dict(command='send/receive ' + mode, exit_code=0, exact_match=True,
                             sha256=digest(recovered.read_bytes())))

            # Change the start of the ciphertext and check that nothing is released.
            modified = json.loads(artifact.read_text())
            modified['ciphertext'] = 'AA' + modified['ciphertext'][2:]
            artifact.write_text(json.dumps(modified))
            forbidden = root / (mode + '_rejected.bin')
            result = call('receive', '--state', state, '--student-id', student_id,
                          '--input', artifact, '--output', forbidden)
            assert result.returncode == 1 and not forbidden.exists()
            rows.append(dict(command='receive tampered ' + mode, exit_code=1,
                             output_created=False, result=result.stderr.splitlines()[-1]))

        # Sending to an existing file must fail and leave that file unchanged.
        occupied = root / 'existing.bin'
        occupied.write_bytes(b'preserve me')
        result = call('send', '--state', state, '--student-id', student_id,
                      '--input', original, '--output', occupied)
        assert result.returncode == 1 and occupied.read_bytes() == b'preserve me'
        rows.append(dict(command='send to existing output', exit_code=1,
                         existing_content_preserved=True))

    Path('evidence/E08_cli.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps({'cli_checks': len(rows), 'all_passed': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--student-id', required=True)
    run(parser.parse_args().student_id)
