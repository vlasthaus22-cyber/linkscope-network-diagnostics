$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Error 'Python 3 не найден. Установите Python 3 и включите Add Python to PATH.'
    exit 1
}
Start-Process 'http://127.0.0.1:8765'
& $python.Source server.py
