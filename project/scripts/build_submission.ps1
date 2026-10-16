param(
    [string]$Output = "whatsapp-offline-win64.zip",
    [string]$Python = "py"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repositoryRoot = (Resolve-Path (Join-Path $projectRoot "..")).Path
$stagingRoot = $null

Push-Location $repositoryRoot
try {
    git diff --quiet
    if ($LASTEXITCODE -ne 0) { throw "Commit or stash working-tree changes before building the bundle." }
    git diff --cached --quiet
    if ($LASTEXITCODE -ne 0) { throw "Commit staged changes before building the bundle." }

    $untracked = @(git ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect untracked files." }
    if ($untracked.Count -gt 0) { throw "Commit or remove untracked files before building: $($untracked -join ', ')" }

    $target = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Output))
    if (Test-Path -LiteralPath $target) { throw "Refusing to overwrite existing archive: $target" }

    $pythonArguments = @()
    $pythonName = [IO.Path]::GetFileName($Python)
    if ($pythonName -ieq "py" -or $pythonName -ieq "py.exe") { $pythonArguments = @("-3.12") }
    $pythonInfo = & $Python @pythonArguments -c "import json,platform,sys; print(json.dumps({'executable':sys.executable,'version':list(sys.version_info[:3]),'bits':platform.architecture()[0]}))"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.12 x64 is required to build the Windows offline bundle." }
    $parsedPython = $pythonInfo | ConvertFrom-Json
    if ($parsedPython.version[0] -ne 3 -or $parsedPython.version[1] -ne 12 -or $parsedPython.bits -ne "64bit") {
        throw "Expected Python 3.12 x64; detected $($parsedPython.version -join '.') $($parsedPython.bits)."
    }
    $pythonExe = $parsedPython.executable

    $stagingRoot = Join-Path ([IO.Path]::GetTempPath()) ("whatsapp-offline-" + [Guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $stagingRoot "source.zip"
    $bundleRoot = Join-Path $stagingRoot "bundle"
    New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null

    git archive --format=zip --output=$archivePath HEAD
    if ($LASTEXITCODE -ne 0) { throw "git archive failed." }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $bundleRoot

    $wheelhouse = Join-Path $bundleRoot "wheels"
    if (Test-Path -LiteralPath $wheelhouse) {
        Get-ChildItem -LiteralPath $wheelhouse -File | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
    else {
        New-Item -ItemType Directory -Path $wheelhouse | Out-Null
    }

    foreach ($required in @(
        (Join-Path $bundleRoot "python-3.12.0-amd64.exe"),
        (Join-Path $bundleRoot "Wireshark-x64.exe"),
        (Join-Path $bundleRoot "project\GeoLite2-City.mmdb"),
        (Join-Path $bundleRoot "project\GeoLite2-ASN.mmdb")
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required offline asset is missing from committed HEAD: $required"
        }
    }

    $locks = @("project\requirements.lock.txt", "project\whatsapp_ai_harness\requirements.lock.txt")
    foreach ($lock in $locks) {
        $lockPath = Join-Path $bundleRoot $lock
        if (-not (Test-Path -LiteralPath $lockPath)) { throw "Missing dependency lock in committed HEAD: $lock" }
        & $pythonExe -m pip download --disable-pip-version-check --dest $wheelhouse --only-binary=:all: --require-hashes -r $lockPath
        if ($LASTEXITCODE -ne 0) { throw "Failed to download every binary wheel for $lock" }
    }

    $verification = Join-Path $stagingRoot "offline-verification"
    New-Item -ItemType Directory -Path $verification | Out-Null
    foreach ($lock in $locks) {
        & $pythonExe -m pip download --disable-pip-version-check --no-index --find-links $wheelhouse --dest $verification --only-binary=:all: --require-hashes -r (Join-Path $bundleRoot $lock)
        if ($LASTEXITCODE -ne 0) { throw "Wheelhouse offline verification failed for $lock" }
    }

    $manifestPath = Join-Path $bundleRoot "OFFLINE_BUNDLE_MANIFEST.sha256"
    $manifestFiles = Get-ChildItem -LiteralPath $bundleRoot -Recurse -File |
        Where-Object { $_.FullName -ne $manifestPath } |
        Sort-Object FullName
    $manifestLines = foreach ($file in $manifestFiles) {
        $relative = $file.FullName.Substring($bundleRoot.Length + 1).Replace("\", "/")
        "{0}  {1}" -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
    [IO.File]::WriteAllLines($manifestPath, $manifestLines, [Text.UTF8Encoding]::new($false))

    Compress-Archive -Path (Join-Path $bundleRoot "*") -DestinationPath $target -CompressionLevel Optimal
    Write-Output "Created fully offline Windows/Python 3.12 x64 bundle: $target"
    Write-Output "Included $((Get-ChildItem -LiteralPath $wheelhouse -File).Count) wheels, both application environments, installers, and local runtime assets."
}
finally {
    Pop-Location
    if ($stagingRoot -and (Test-Path -LiteralPath $stagingRoot)) {
        $resolvedStaging = [IO.Path]::GetFullPath($stagingRoot)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if ($resolvedStaging.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($resolvedStaging).StartsWith("whatsapp-offline-")) {
            Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
        }
    }
}
