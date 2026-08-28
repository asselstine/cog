$ErrorActionPreference = "Stop"

$Repository = if ($env:COG_REPO) { $env:COG_REPO } else { "asselstine/cog" }
$Version = if ($env:COG_VERSION) { $env:COG_VERSION } else { "latest" }
$InstallDir = if ($env:COG_INSTALL_DIR) {
    $env:COG_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA "Programs\cog\bin"
}

$Archive = "cog-x86_64-pc-windows-msvc.zip"
if ($Version -eq "latest") {
    $BaseUrl = "https://github.com/$Repository/releases/latest/download"
} else {
    $Tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $BaseUrl = "https://github.com/$Repository/releases/download/$Tag"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cog-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $TempDir | Out-Null
try {
    $ArchivePath = Join-Path $TempDir $Archive
    $ChecksumsPath = Join-Path $TempDir "SHA256SUMS"
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $ChecksumsPath

    $EscapedArchive = [regex]::Escape($Archive)
    $ChecksumLine = Get-Content $ChecksumsPath | Where-Object { $_ -match "^[0-9a-fA-F]{64}\s+\*?$EscapedArchive$" } | Select-Object -First 1
    if (-not $ChecksumLine) { throw "Release checksum does not contain $Archive" }
    $Expected = ($ChecksumLine -split '\s+')[0].ToLowerInvariant()
    $Actual = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) { throw "Checksum verification failed" }

    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force (Join-Path $TempDir "cog.exe") (Join-Path $InstallDir "cog.exe")
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}

Write-Host "Installed cog to $InstallDir\cog.exe"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = @($UserPath -split ';' | Where-Object { $_ })
if ($PathEntries -notcontains $InstallDir) {
    $NewPath = (@($PathEntries) + $InstallDir) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "Added $InstallDir to your user PATH. Open a new terminal to run cog."
}
