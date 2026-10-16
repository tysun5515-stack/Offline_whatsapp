param(
    [switch]$SkipHarness,
    [switch]$RecreateEnvironments,
    [string]$Python
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path $PSScriptRoot).Path
$bundleRoot = (Resolve-Path (Join-Path $projectRoot "..")).Path
$wheelhouse = Join-Path $bundleRoot "wheels"
$primaryLock = Join-Path $projectRoot "requirements.lock.txt"
$harnessLock = Join-Path $projectRoot "whatsapp_ai_harness\requirements.lock.txt"

function Resolve-Python312 {
    if ($Python) {
        $explicitCommand = Get-Command $Python -ErrorAction SilentlyContinue
        if (-not $explicitCommand) { throw "Configured Python executable does not exist: $Python" }
        $explicit = $explicitCommand.Source
        $candidates = @(,@($explicit))
    }
    else {
        $candidates = @()
        $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($pyLauncher) { $candidates += ,@($pyLauncher.Source, "-3.12") }
        $discoveredPython = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($discoveredPython) { $candidates += ,@($discoveredPython.Source) }
    }

    foreach ($candidate in $candidates) {
        $executable = $candidate[0]
        $prefix = @($candidate | Select-Object -Skip 1)
        try {
            $result = & $executable @prefix -c "import json,platform,sys; print(json.dumps({'executable':sys.executable,'version':list(sys.version_info[:3]),'bits':platform.architecture()[0]}))"
            if ($LASTEXITCODE -ne 0) { continue }
            $info = $result | ConvertFrom-Json
            if ($info.version[0] -eq 3 -and $info.version[1] -eq 12 -and $info.bits -eq "64bit") {
                return $info.executable
            }
        }
        catch { continue }
    }
    throw "Python 3.12 x64 is required. Run the bundle-root INSTALL.bat to use the included installer."
}

function Install-Environment {
    param(
        [Parameter(Mandatory=$true)][string]$BasePython,
        [Parameter(Mandatory=$true)][string]$EnvironmentPath,
        [Parameter(Mandatory=$true)][string]$LockFile,
        [Parameter(Mandatory=$true)][string[]]$ImportNames
    )

    if ($RecreateEnvironments -and (Test-Path -LiteralPath $EnvironmentPath)) {
        $resolvedEnvironment = [IO.Path]::GetFullPath($EnvironmentPath)
        if (-not $resolvedEnvironment.StartsWith($projectRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove an environment outside the project: $resolvedEnvironment"
        }
        Remove-Item -LiteralPath $resolvedEnvironment -Recurse -Force
    }

    $environmentPython = Join-Path $EnvironmentPath "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $environmentPython)) {
        & $BasePython -m venv $EnvironmentPath
        if ($LASTEXITCODE -ne 0) { throw "Failed to create $EnvironmentPath" }
    }

    & $environmentPython -m pip install --disable-pip-version-check --no-index --find-links $wheelhouse --require-hashes -r $LockFile
    if ($LASTEXITCODE -ne 0) { throw "Offline dependency installation failed for $EnvironmentPath" }
    & $environmentPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Dependency consistency check failed for $EnvironmentPath" }

    $imports = ($ImportNames | ForEach-Object { "import $_" }) -join ";"
    & $environmentPython -c $imports
    if ($LASTEXITCODE -ne 0) { throw "Runtime import verification failed for $EnvironmentPath" }
}

foreach ($required in @(
    $wheelhouse, $primaryLock, $harnessLock,
    (Join-Path $projectRoot "GeoLite2-City.mmdb"),
    (Join-Path $projectRoot "GeoLite2-ASN.mmdb")
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Offline bundle is incomplete; missing: $required"
    }
}

$basePython = Resolve-Python312
Install-Environment -BasePython $basePython -EnvironmentPath (Join-Path $projectRoot ".venv") -LockFile $primaryLock -ImportNames @("flask", "werkzeug", "jinja2", "cryptography", "geoip2")

if (-not $SkipHarness) {
    Install-Environment -BasePython $basePython -EnvironmentPath (Join-Path $projectRoot "whatsapp_ai_harness\.venv") -LockFile $harnessLock -ImportNames @("flask", "langgraph", "reportlab", "waitress")
}

$primaryPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
Push-Location $projectRoot
try {
    & $primaryPython -c "from src.webapp.app import create_app; create_app(); print('Primary analyzer import check: OK')"
    if ($LASTEXITCODE -ne 0) { throw "Primary application startup import check failed" }
}
finally { Pop-Location }

Write-Output "Offline installation complete. Run run_offline.cmd to start the analyzer."
if (-not $SkipHarness) {
    Write-Output "Run whatsapp_ai_harness\start_harness.cmd for the optional companion. Route A works without Ollama."
}
