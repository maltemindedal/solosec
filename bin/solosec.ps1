[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SourcePath = Join-Path $ProjectRoot "src"

if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$SourcePath;$($env:PYTHONPATH)"
} else {
    $env:PYTHONPATH = $SourcePath
}

if ((Get-Command uv -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $ProjectRoot "pyproject.toml"))) {
    & uv run --directory $ProjectRoot solosec @RemainingArgs
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if ($Python) {
    & $Python.Source -m solosec @RemainingArgs
    exit $LASTEXITCODE
}

$Python3 = Get-Command python3 -ErrorAction SilentlyContinue
if ($Python3) {
    & $Python3.Source -m solosec @RemainingArgs
    exit $LASTEXITCODE
}

Write-Error "Python was not found on PATH."
exit 1