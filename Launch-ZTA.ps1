param(
    [ValidateSet('check','start','test','perf','verify','dashboard','status','stop','restore-strict','jwt-refresh')]
    [string]$Action = 'status'
)
if ($PSScriptRoot -notmatch '^([A-Za-z]):\\') { throw 'Expected a local Windows drive worktree.' }
# Docker bind mounts can make wslpath select a transient alias; use the stable automount path.
$linuxRoot = '/mnt/' + $PSScriptRoot.Substring(0,1).ToLowerInvariant() + $PSScriptRoot.Substring(2).Replace('\','/')
& wsl.exe -d Ubuntu -- python3 ($linuxRoot + '/scripts/zta.py') $Action
exit $LASTEXITCODE
