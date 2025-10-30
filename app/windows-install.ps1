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

Write-Host "Installing prerequisites (Python, Npcap, Nmap) via winget..."
Require-Winget
Install-WithWinget "Python.Python.3.11"
Install-WithWinget "Npcap.Npcap"
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
