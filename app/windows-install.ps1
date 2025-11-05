# Requires: PowerShell (run as Administrator recommended)
param(
  [string]$VenvName = ".venv"
)

function Require-Winget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Warning "winget is not available. Install from Microsoft Store (App Installer) and re-run."
    exit 1
  }
}

function Install-WithWinget($id) {
  try {
    winget install -e --id $id --accept-package-agreements --accept-source-agreements | Out-Null
  } catch {
    Write-Warning "Failed to install $id via winget. You may install it manually."
  }
}

function Test-Admin {
  try {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Test-NpcapInstalled {
  try {
    if (Get-Service -Name npcap -ErrorAction SilentlyContinue) { return $true }
  } catch {}
  try { if (Test-Path "HKLM:\\SOFTWARE\\Npcap") { return $true } } catch {}
  try { if (Test-Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\npcap") { return $true } } catch {}
  return $false
}

function Ensure-Npcap {
  if (-not (Test-NpcapInstalled)) {
    Write-Host "Npcap not detected; installing via winget..."
    Install-WithWinget "Npcap.Npcap"
    Start-Sleep -Seconds 3
    if (-not (Test-NpcapInstalled)) {
      Write-Warning "Npcap still not detected. You may need to reboot, then rerun this script, or install manually from https://npcap.com."
    } else {
      Write-Host "Npcap installed successfully."
    }
  } else {
    Write-Host "Npcap detected."
  }
}

Write-Host "Installing prerequisites (Python, Npcap, Nmap) via winget..."
Require-Winget
if (-not (Test-Admin)) {
  Write-Warning "It is recommended to run this script in an elevated PowerShell (Run as Administrator)."
}
Install-WithWinget "Python.Python.3.11"
Ensure-Npcap
Install-WithWinget "Nmap.Nmap"

Write-Host "Creating virtual environment: $VenvName"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
  Write-Host "'py' launcher not found; using 'python'"
  python -m venv $VenvName
} else {
  py -3 -m venv $VenvName
}

Write-Host "Activating venv and installing Python dependencies..."
". $VenvName\Scripts\Activate.ps1" | Out-Null
. "$VenvName\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements-windows.txt

Write-Host "Done. Start the app with:"
Write-Host ". $VenvName\Scripts\Activate.ps1; python app.py"
