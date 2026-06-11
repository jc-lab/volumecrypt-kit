# SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
#
# SPDX-License-Identifier: Apache-2.0

param(
    [Parameter(Mandatory = $true)]
    [string]$DriverSys,         # Path to the signed .sys file
    [Parameter(Mandatory = $true)]
    [string]$DriverInf,         # Path to the .inf file
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,         # Output directory for the package
    [string]$SigningDir,
    [string]$Password = "changeit"
)

$ErrorActionPreference = "Stop"

if (-not $SigningDir) {
    if ($PSScriptRoot) { $SigningDir = $PSScriptRoot }
    else { $SigningDir = Split-Path -Parent $PSCommandPath }
}

# Find signtool.exe (prefer x64).
$signtoolCandidates = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -ExpandProperty FullName
$signtool = ($signtoolCandidates | Where-Object { $_ -match '\\x64\\' } | Select-Object -First 1)
if (-not $signtool) { $signtool = $signtoolCandidates | Select-Object -First 1 }
if (-not $signtool) { throw "signtool.exe not found" }

# Find makecat.exe (prefer x64).
$makecatCandidates = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter makecat.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -ExpandProperty FullName
$makecat = ($makecatCandidates | Where-Object { $_ -match '\\x64\\' } | Select-Object -First 1)
if (-not $makecat) { $makecat = $makecatCandidates | Select-Object -First 1 }
if (-not $makecat) { throw "makecat.exe not found" }

Write-Host "signtool: $signtool"
Write-Host "makecat:  $makecat"

$pfxPath = Join-Path $SigningDir "MyTestDriverCert.pfx"
if (-not (Test-Path $pfxPath)) {
    & (Join-Path $SigningDir "prepare-test-cert.ps1") -OutputDir $SigningDir -Password $Password
}

# --- Prepare output directory ---
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
# Use absolute paths throughout to avoid CWD issues with makecat.
$OutputDir = (New-Item -ItemType Directory -Force -Path $OutputDir).FullName
$sysName  = Split-Path -Leaf $DriverSys
$infName  = Split-Path -Leaf $DriverInf
$catName  = [System.IO.Path]::ChangeExtension($infName, ".cat")
$catPath  = Join-Path $OutputDir $catName
$sysOut   = Join-Path $OutputDir $sysName
$infOut   = Join-Path $OutputDir $infName
Copy-Item -LiteralPath $DriverSys -Destination $sysOut -Force
Copy-Item -LiteralPath $DriverInf -Destination $infOut -Force

# --- Build catalog definition file (.cdf) ---
# The catalog contains hashes of the driver package files.
# CatalogHeader: Name, PublicVersion=0x0000001 (Windows 10+), EncodingType=0x00010001 (PKCS#7)
$cdfContent = @"
[CatalogHeader]
Name=$catName
PublicVersion=0x0000001
EncodingType=0x00010001
CATATTR1=0x10010001:attr1:Windows 10 X64

[CatalogFiles]
<hash>$sysName=$sysOut
<hash>$infName=$infOut
"@
$cdfPath = Join-Path $OutputDir ([System.IO.Path]::ChangeExtension($catName, ".cdf"))
[System.IO.File]::WriteAllText($cdfPath, $cdfContent, [System.Text.Encoding]::ASCII)
Write-Host "CDF written to $cdfPath"

# makecat writes the .cat into the WORKING DIRECTORY of the process.
# Use Start-Process with -WorkingDirectory set to OutputDir (absolute path).
$proc = Start-Process -FilePath $makecat -ArgumentList @($cdfPath) `
    -WorkingDirectory $OutputDir -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$OutputDir\makecat_out.txt" -RedirectStandardError "$OutputDir\makecat_err.txt"
$mcOut = Get-Content "$OutputDir\makecat_out.txt" -ErrorAction SilentlyContinue
$mcErr = Get-Content "$OutputDir\makecat_err.txt" -ErrorAction SilentlyContinue
Remove-Item "$OutputDir\makecat_out.txt","$OutputDir\makecat_err.txt" -ErrorAction SilentlyContinue
Write-Host "makecat stdout: $mcOut  stderr: $mcErr  exit: $($proc.ExitCode)"
if (-not (Test-Path $catPath)) {
    throw "makecat did not produce $catPath"
}
Write-Host "Catalog created: $catPath"

# --- Sign the catalog with the test certificate ---
$signArgs = @(
    "sign", "/v", "/fd", "SHA256", "/f", $pfxPath, "/p", $Password,
    "/tr", "http://timestamp.digicert.com", "/td", "SHA256", $catPath
)
$proc = Start-Process -FilePath $signtool -ArgumentList $signArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    throw "signtool sign (catalog) failed with exit code $($proc.ExitCode)"
}
Write-Host "Catalog signed: $catPath"

# Clean up .cdf
Remove-Item -LiteralPath $cdfPath -Force -ErrorAction SilentlyContinue
Write-Host "Driver package ready in $OutputDir"
