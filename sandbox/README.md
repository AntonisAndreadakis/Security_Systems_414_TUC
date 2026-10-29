# Assignment test sandbox

## Python projects (current workflow)

All eight projects now have a standalone `assignment.py`. Run all Python
self-tests and CLI integration checks with:

```powershell
docker build --tag student-assignments-sandbox:local --file sandbox/Dockerfile sandbox
powershell -NoProfile -File sandbox/run.ps1 -Assignment 0 -Python
```

The latest combined run passed **46 self-tests and 8 command-line integration
tests**. Select 1 through 8 to run one project's self-tests. Assignment 5's
`-Python` run exercises the maintained `assignment.py`; a plain run instead
builds and smoke-tests its fixed C/Bash deliverables (logger.c, acmonitor.c,
ransomware.sh).
See [the script index and limits](../PYTHON_PROJECTS.md).

The image includes Python cryptography 50.0.1, cffi 2.1.1, and pycparser 3.0
from sandbox/requirements.txt. They are installed into an image-local directory
as UID 10001; the Windows Python installation is unchanged. Package retrieval
occurs only during image construction; tests remain network-disabled.

The real assignment-5 generated-fixture encryption/deletion/recovery lab,
assignment-6 live capture, assignment-7 kernel firewall integration, and
assignment-8 native exploit validation remain unverified under the existing
approval boundary. Simulation/mocks do not prove those workflows complete.

## Original C/shell status

This is a Docker container setup inside Docker Desktop's Linux VM, not a
separately created VM. The image is `student-assignments-sandbox:local`.
Test containers are removed when they exit, so they normally disappear from
Docker Desktop's running-container list.

| Assignment | Verified status |
| --- | --- |
| 1 | Repaired; unit/demo tests and ASan/UBSan passed |
| 2 | Repaired; crypto/fixture/tamper tests and ASan/UBSan passed |
| 3 | Corrected *_fixed sources; RSA regression suite passed |
| 4 | Revised C logger/monitor; assertion-based tests passed |
| 5 | Python `make check` passed 14 tests; C/Bash `make check` builds logger.so/acmonitor/ransomware.sh and passes a 10-step smoke test in `tests/check_legacy.sh` |
| 6 | Four offline tests passed; supplied capture has 14,261 packets |
| 7 | Twelve Python and seven shell mock tests passed; real firewall integration pending |
| 8 | Three Python and seven safe native/model tests passed; original exploit deliverables pending |

Passing these tests does not certify every project as 100% complete.
Historical submission outputs may still be stale. Old prebuilt binaries and
test leftovers were moved to [archive](../archive/README.md).
Each assignment README describes the scope and remaining work.

## Build and run

From the `testing` workspace in PowerShell, with Docker Desktop using its
Linux engine:

```powershell
docker build --tag student-assignments-sandbox:local --file sandbox/Dockerfile sandbox
powershell -NoProfile -File sandbox/run.ps1 -Assignment 1
```

Without `-Python`, replace 1 with 2, 3, 4, 5, 6, 7, or 8. Assignment 5's
default check now builds and smoke-tests its C/Bash deliverables too (see
`5th assignment/2013030059_assign5/Readme.md`).
No PowerShell execution-policy changes are required by this setup.
Build downloads require network access; test containers have none.

The Dockerfile pins the GCC base image by digest. It extracts Debian libpcap
and D-Bus runtime packages as UID 10001 without running package installation
scripts or starting services. See the Dockerfile for exact versions and URLs.
The package URLs use HTTPS but package checksums are not separately pinned.

## How tests are isolated

`run.ps1` launches Docker; `run.py` copies the selected project into temporary
`/work/projectN` and runs `make -B check`, or `test_safe.py` for assignments 7/8.
With `-Python`, it runs `assignment.py --self-test`. Assignment 0 runs all eight
copies followed by sandbox/python_cli_checks.py in the same disposable container.

- UID/GID 10001; all Linux capabilities dropped; no-new-privileges.
- No network, published ports, Docker socket, or host device access.
- Read-only root filesystem and read-only source mount.
- Writable temporary /work and /tmp; /tmp is non-executable.
- 512 MiB memory, two CPUs, 128-process limit, and 180-second test timeout.
- Forced rebuilds; old submitted executables are not used by the test commands.

The whole testing workspace is readable by the container. Temporary writes and
test outputs vanish on exit; the console contains the test results. No permanent
background container or test-results volume is created.

## Approval boundary

Real firewall changes, live packet capture, destructive ransomware workflows,
and exploit execution require separate approval under the user's instructions.
Use offline captures and mocked/synthetic events for ordinary tests.

The editor session may request permission to access Docker or edit files.
Those application approvals do not change the container's non-root UID or grant
it Linux capabilities.
