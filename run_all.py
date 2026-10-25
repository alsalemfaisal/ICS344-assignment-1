"""Run the security tests and command-line checks, saving both logs."""
import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--student-id', default='202245540')
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    evidence = folder / 'evidence'
    evidence.mkdir(exist_ok=True)

    suites = [('test_suite.py', 'test_run.log'), ('cli_smoke.py', 'cli_run.log')]
    for script, log_name in suites:
        command = [sys.executable, script, '--student-id', args.student_id]
        result = subprocess.run(command, cwd=folder, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (evidence / log_name).write_text(log)
        print(f'Running {script}')
        print(log, end='')
        if result.returncode != 0:
            return result.returncode

    print('All checks passed. Results and logs are in evidence/.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
