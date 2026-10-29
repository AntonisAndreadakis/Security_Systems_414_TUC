param(
    [ValidateRange(0,8)][int]$Assignment = 1,
    [switch]$Python
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$image = 'student-assignments-sandbox:local'
$arguments = @(
    'run', '--rm', '--user', '10001:10001', '--network', 'none',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
    '--pids-limit', '128', '--memory', '512m', '--cpus', '2',
    '--tmpfs', '/work:rw,exec,nosuid,size=256m,mode=1777',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--mount', "type=bind,source=$workspace,target=/src,readonly",
    '--workdir', '/work', $image,
    'python3', '/src/sandbox/run.py', "$Assignment"
)
if ($Python) { $arguments += '--python' }
& docker @arguments
exit $LASTEXITCODE
