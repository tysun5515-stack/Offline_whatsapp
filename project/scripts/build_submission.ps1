param(
    [string]$Output = "mentor-submission.zip"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $projectRoot
try {
    git diff --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Commit or stash working-tree changes before building the submission."
    }
    git diff --cached --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Commit staged changes before building the submission."
    }

    $target = [IO.Path]::GetFullPath((Join-Path $projectRoot $Output))
    if (Test-Path -LiteralPath $target) {
        throw "Refusing to overwrite existing archive: $target"
    }
    git archive --format=zip --output=$target HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "git archive failed."
    }
    Write-Output "Created $target from tracked files at HEAD."
}
finally {
    Pop-Location
}
