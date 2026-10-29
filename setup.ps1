param(
    [string]$PythonExe,
    [switch]$SkipInit
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $Root

$PythonPrefixArgs = @()
if (-not $PythonExe) {
    $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        $PythonExe = $PyLauncher.Source
        $PythonPrefixArgs = @("-3")
    } else {
        $PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $PythonCommand) {
            throw "Python 3.11 or newer is required. Install Python or pass -PythonExe."
        }
        $PythonExe = $PythonCommand.Source
    }
}

$VersionText = (& $PythonExe @PythonPrefixArgs -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')").Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Could not run the selected Python interpreter."
}
try {
    $PythonVersion = [version]$VersionText
} catch {
    throw "Could not read Python version from '$VersionText'."
}
if ($PythonVersion -lt [version]"3.11") {
    throw "Python 3.11 or newer is required; found $VersionText."
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    & $PythonExe @PythonPrefixArgs -m venv (Join-Path $Root ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the .venv virtual environment."
    }
}

& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Could not upgrade pip in .venv."
}
& $VenvPython -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) {
    throw "Could not install Jobops dependencies."
}
& $VenvPython -m playwright install chromium
if ($LASTEXITCODE -ne 0) {
    throw "Could not install Playwright Chromium."
}

if (-not $SkipInit) {
    & $VenvPython jobctl.py init
    if ($LASTEXITCODE -ne 0) {
        throw "Jobops initialization failed. Review the error above and rerun setup.ps1."
    }
}

Write-Host "Jobops Windows setup is ready. Private data is stored under %LOCALAPPDATA%\Jobops and credentials use Windows Credential Manager."
Write-Host "Run commands with: .\.venv\Scripts\python.exe jobctl.py <command>"
