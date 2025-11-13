param(
  [string]$VenvName = ".venv",
  [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPath = Join-Path $repoRoot $VenvName
$pythonExe = Join-Path $venvPath "Scripts\\python.exe"
$requirements = Join-Path $repoRoot "requirements-windows.txt"

function Invoke-Safe {
  param([scriptblock]$Script)
  try {
    & $Script
  } catch {
    Write-Error $_
    exit 1
  }
}

function Ensure-Venv {
  if (Test-Path $pythonExe) { return }
  Write-Host "Creating virtual environment at $venvPath"
  $create = {
    if (Get-Command py -ErrorAction SilentlyContinue) {
      py -3 -m venv $VenvName
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
      python -m venv $VenvName
    } else {
      throw "Python 3 is required but was not found in PATH."
    }
  }
  Push-Location $repoRoot
  Invoke-Safe $create
  Pop-Location
  if (-not (Test-Path $pythonExe)) {
    throw "Failed to create virtual environment at $venvPath"
  }
}

function Ensure-Requirements {
  if (-not (Test-Path $requirements)) {
    throw "Could not find $requirements"
  }
  Write-Host "Installing/validating Python dependencies..."
  Push-Location $repoRoot
  Invoke-Safe { & $pythonExe -m pip install --upgrade pip setuptools wheel }
  Invoke-Safe { & $pythonExe -m pip install -r $requirements }
  Pop-Location
}

function Launch-App {
  Write-Host "Launching NetMapper GUI..."
  Push-Location $repoRoot
  & $pythonExe "app.py"
  $code = $LASTEXITCODE
  Pop-Location
  if ($code -ne 0) {
    throw "app.py exited with status $code"
  }
}

if (-not $SkipSetup) {
  Ensure-Venv
  Ensure-Requirements
} elseif (-not (Test-Path $pythonExe)) {
  Write-Warning "SkipSetup was requested but the virtual environment is missing. Running setup anyway."
  Ensure-Venv
  Ensure-Requirements
}

Launch-App
