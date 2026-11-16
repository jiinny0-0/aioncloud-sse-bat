# AIONCLOUD SSE BAT - setup helper
# Run from the project root (the folder containing pyproject.toml):
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
#
# ASCII only: Windows PowerShell 5.1 misreads UTF-8 scripts without a BOM.

Set-Location $PSScriptRoot

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "FAILED: $Step (exit code $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "Setup stopped. Fix the error above and run setup.ps1 again."
        exit $LASTEXITCODE
    }
}

if (-not (Test-Path "pyproject.toml")) {
    Write-Host "pyproject.toml not found." -ForegroundColor Red
    Write-Host "Run this script from the extracted project root."
    exit 1
}

Write-Host "[1/4] Creating virtual environment" -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Assert-LastExitCode "python -m venv .venv"
}
& .\.venv\Scripts\Activate.ps1
$python = ".\.venv\Scripts\python.exe"

Write-Host "[2/4] Installing dependencies" -ForegroundColor Cyan
& $python -m pip install --upgrade pip --quiet
Assert-LastExitCode "pip upgrade"

& $python -m pip install -e .
Assert-LastExitCode "pip install -e ."

& $python -m playwright install chromium
Assert-LastExitCode "playwright install chromium"

Write-Host "[3/4] Creating config files" -ForegroundColor Cyan
$pairs = @(
    @("env.example", ".env"),
    @("config\environments.example.yaml", "config\environments.yaml")
)
foreach ($pair in $pairs) {
    $src = $pair[0]
    $dst = $pair[1]
    if (Test-Path $dst) {
        Write-Host "  skip (exists): $dst"
    } else {
        Copy-Item $src $dst
        Write-Host "  created: $dst"
    }
}

Write-Host "[4/4] Framework self-check" -ForegroundColor Cyan
& $python -m pytest tests\test_selfcheck.py -q
Assert-LastExitCode "self-check"

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1) Put the console account and Open API tokens into .env"
Write-Host "  2) Fill in URLs, workspaces and endpoints in config\environments.yaml"
Write-Host "  3) .\.venv\Scripts\Activate.ps1   (each new terminal)"
Write-Host "  4) bat doctor"
Write-Host "  5) bat lanes"
Write-Host "  6) bat run --case BAT-SWG-001 --headed"
