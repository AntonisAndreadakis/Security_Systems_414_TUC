# Assignment 7 - Ad-blocking firewall script

Andreadakis Antonios - report ID 2013030059

For a Chrome-only trial that blocks confirmed Taboola image requests without
firewall changes, see [the extension instructions](chrome_extension/README.md).

## Python version (current entry point)

`assignment.py` requires Python 3.11+ and the standard library. It supports
`-domains`, `-ips`, `-save`, `-load`, `-list`, `-reset`, and `-help`.
The Python regression suite uses fake DNS and an in-memory firewall runner.

```sh
python assignment.py --self-test
python assignment.py -domains
python assignment.py -list
python assignment.py -ips --data-directory DIRECTORY_WITH_IPADDRESSES
```

Default DNS/firewall commands print JSON plans without applying them.
Real resolution requires `--allow-network`; real firewall calls require
`--apply`, appropriate existing privileges, and separate user approval.
The script never invokes sudo or attempts elevation. All addresses are
validated before the first mutation. Replacement rules are built in a staging
chain before switching from the previous ADBLOCK chain, and pre-commit failures
trigger best-effort rollback. Reset is scoped to ADBLOCK.

`-save` stores the validated desired IPv4 blocklist in adblockRules.json;
`-load` reads that project format. Unlike the historical shell script, the
Python port never saves/restores unrelated host firewall rules. It does not
claim to snapshot kernel state. An empty address list is an explicit error.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 7 -Python
```

Input/state reads are size-bounded and reject final-component symlinks. Atomic
writes flush file contents before replacement and refuse symlink destinations.

Kernel integration and real DNS remain untested; see the limitations below.

## Earlier C/shell validation status

Eight tests passed in Docker using mocked firewall commands and a fake DNS
resolver. No real DNS resolution, firewall modification, or privileged operation
was performed. Actual firewall integration remains unverified.


## Updates

The maintained script is **this directory's adblock.sh**, with its own
`domainNames.txt`/`IPAddresses.txt`/`adblockRules` beside it. The original,
unmodified course skeleton is now at
`archive/7th assignment/adblock.sh`.

The maintained script resolves paths relative to itself, validates inputs,
deduplicates addresses, and writes generated files atomically. A dedicated
ADBLOCK chain holds, per blocked IP, a `-d` rule (rejects outbound traffic to
it, attached to OUTPUT) and an `-s` rule (rejects inbound traffic from it,
attached to INPUT), so a request to an ad domain never leaves and a reply or
unsolicited packet from it is dropped too. `-domains` resolves
`domainNames.txt` into `IPAddresses.txt` **and** installs rules from the
result, not just the file write. Invalid or empty IP replacements fail before
changing existing rules. `-reset` detaches the chain from both OUTPUT and
INPUT before removing it. `-list` scopes to the ADBLOCK chain instead of
dumping every chain on the host.

## Safe usage and tests

Requires Bash and Python 3 for mock tests.

```sh
bash adblock.sh -help
python3 test_safe.py
```

From the testing workspace in PowerShell:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 7
```

Tests cover syntax/help/invalid arguments, refusal of unprivileged firewall
operations, scoped OUTPUT+INPUT rules, deduplication, invalid replacements,
`-domains` resolving and installing in one step, scoped reset, mocked
save/restore, and fake DNS output.

## Options and data

- `-domains`: resolve domainNames.txt into IPAddresses.txt and install rules
  from the result (OUTPUT + INPUT, see "Updates" above).
- `-ips`: install rules from IPAddresses.txt.
- `-save` / `-load`: save or restore a firewall snapshot.
- `-list`: list this script's rules.
- `-reset`: remove this script's chain and both its jumps (accept all again).
- `-help`: show usage.

`domainNames.txt`, `IPAddresses.txt` and `adblockRules` live in this
directory. The supplied list contains 301 domain lines and 299 unique names.

## Remaining approval and design limits

Real firewall changes require separate approval. A full saved snapshot can
include unrelated firewall rules: `-load` refuses unless the explicit
`ADBLOCK_ALLOW_FULL_RESTORE=1` guard is enabled. Do not enable it as part of
ordinary tests. Syntax validation alone does not make a restore safe.

Mock tests do not prove kernel integration. DNS changes, shared IP hosting,
IPv6 traffic, and first-party ads limit the approach. IPAddresses.txt and
adblockRules have not been populated by real network/firewall operations.
	
	
