$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectDir

$candidates = @(
  "python",
  "py",
  "$env:LocalAppData\Programs\Python\Python314\python.exe",
  "$env:LocalAppData\Programs\Python\Python313\python.exe",
  "$env:LocalAppData\Programs\Python\Python312\python.exe"
)

$pythonCmd = $null
foreach ($c in $candidates) {
  try {
    if ($c -eq "python" -or $c -eq "py") {
      & $c --version *> $null
      if ($LASTEXITCODE -eq 0) {
        $pythonCmd = $c
        break
      }
    } elseif (Test-Path $c) {
      $pythonCmd = $c
      break
    }
  } catch {
    # Continue trying candidates.
  }
}

if (-not $pythonCmd) {
  throw "Python not found. Install Python 3.12+ and retry."
}

Write-Host "Using Python: $pythonCmd"
& $pythonCmd -m pip install -r requirements.txt
& $pythonCmd app.py
