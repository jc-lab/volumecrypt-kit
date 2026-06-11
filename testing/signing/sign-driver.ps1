# SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
#
# SPDX-License-Identifier: Apache-2.0

param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$SigningDir,
    [string]$Password = "changeit"
)

$ErrorActionPreference = "Stop"

if (-not $SigningDir) {
    if ($PSScriptRoot) {
        $SigningDir = $PSScriptRoot
    } else {
        $SigningDir = Split-Path -Parent $PSCommandPath
    }
}

$pfxPath = Join-Path $SigningDir "MyTestDriverCert.pfx"
if (-not (Test-Path $pfxPath)) {
    & (Join-Path $SigningDir "prepare-test-cert.ps1") -OutputDir $SigningDir -Password $Password
}

$signtoolCandidates = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -ExpandProperty FullName
# Prefer the x64 build: the x86 signtool may fail to launch on hosts without
# WoW64. Fall back to whatever is available.
$signtool = $signtoolCandidates | Where-Object { $_ -match '\\x64\\' } | Select-Object -First 1
if (-not $signtool) {
    $signtool = $signtoolCandidates | Select-Object -First 1
}
if (-not $signtool) {
    throw "signtool.exe not found under Windows Kits"
}

$workPath = Join-Path ([System.IO.Path]::GetTempPath()) "vck-signed-driver.dll"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
Copy-Item -LiteralPath $InputPath -Destination $workPath -Force

# Use Start-Process so the exit code is read directly from the process object.
# `$LASTEXITCODE` is unreliable for native commands when this script is invoked
# across a shell boundary (e.g. make -> msys bash -> powershell).
$signArgs = @(
    "sign", "/v", "/fd", "SHA256", "/f", $pfxPath, "/p", $Password,
    "/tr", "http://timestamp.digicert.com", "/td", "SHA256", $workPath
)
$proc = Start-Process -FilePath $signtool -ArgumentList $signArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    throw "signtool sign failed with exit code $($proc.ExitCode)"
}

Copy-Item -LiteralPath $workPath -Destination $OutputPath -Force
Write-Host "Signed driver written to $OutputPath"
