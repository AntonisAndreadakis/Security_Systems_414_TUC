"""Build and test disposable copies.

Submitted binary artifacts are not executed, with one explicitly approved
exception: assignment 8's test_exploit.py runs the supplied Greeter binary
against its generated exploit payload, inside this network-disabled,
non-root, UID-10001 container, to verify the buffer-overflow exploit it
asks for actually works (see 8th_assignment/2013030059_assign8/Readme.md).
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

PROJECTS = {
    1: '1st assignment/2013030059_assign1',
    2: '2nd assignment/2013030059_assign2',
    3: '3d assignment/2013030059_assign3',
    4: '4th assignment/2013030059_assign4',
    5: '5th assignment/2013030059_assign5',
    6: '6th assignment/2013030059_assign6',
    7: '7th assignment/2013030059_assign7',
    8: '8th_assignment/2013030059_assign8',
}

def main():
    number = int(sys.argv[1])
    if os.geteuid() == 0:
        raise SystemExit('Refusing to test as root')
    if number == 0:
        if '--python' not in sys.argv[2:]: raise SystemExit('Assignment 0 is the Python suite; add -Python')
        results = []
        for assignment in PROJECTS:
            completed = subprocess.run([sys.executable, __file__, str(assignment), '--python'], timeout=200)
            results.append((assignment, completed.returncode))
        print('Python suite exit codes:', dict(results), flush=True)
        if not any(code for _, code in results):
            integration = subprocess.run([sys.executable, '/src/sandbox/python_cli_checks.py'], timeout=180)
            if integration.returncode: raise SystemExit(integration.returncode)
        raise SystemExit(1 if any(code for _, code in results) else 0)
    source = Path('/src') / PROJECTS[number]
    dest = Path('/work') / f'project{number}'
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns('__pycache__', '*.o', '*.so', '*.exe'))
    os.chdir(dest)
    print(f'Assignment {number}: disposable copy; uid={os.geteuid()}', flush=True)
    if '--python' in sys.argv[2:]:
        command = (['python3', '-m', 'unittest', '-v', 'assignment.Tests', 'test_assignment']
                   if number == 7 else ['python3', 'assignment.py', '--self-test'])
    elif number == 8:
        command = ['python3', '-m', 'unittest', '-v', 'test_safe', 'test_exploit']
    elif number == 7:
        command = ['python3', 'test_safe.py']
    else:
        command = ['make', '-B', 'check']
    try:
        result = subprocess.run(command, timeout=180)
    except subprocess.TimeoutExpired:
        raise SystemExit('Test exceeded 180 seconds')
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()
