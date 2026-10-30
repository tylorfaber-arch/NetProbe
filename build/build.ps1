# Builds NetProbe-Portable.exe and NetProbe-Setup-<version>.exe into ..\..\release
#   powershell -ExecutionPolicy Bypass -File build\build.ps1
# Needs: .NET 10 SDK, Inno Setup 6 (winget install JRSoftware.InnoSetup)
$ErrorActionPreference = 'Stop'
$src = Split-Path $PSScriptRoot -Parent
$release = Join-Path (Split-Path $src -Parent) 'release'
$publish = Join-Path $env:LOCALAPPDATA 'NetProbeBuild\publish'
[xml]$proj = Get-Content (Join-Path $src 'NetProbe.csproj')
$version = $proj.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
Write-Host "Building NetProbe $version" -ForegroundColor Cyan

if (-not (Test-Path (Join-Path $src 'Assets\netprobe.ico'))) { & (Join-Path $PSScriptRoot 'make-icon.ps1') }

dotnet publish (Join-Path $src 'NetProbe.csproj') -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none -o $publish
if ($LASTEXITCODE) { throw 'dotnet publish failed' }

New-Item -ItemType Directory -Force $release | Out-Null
Copy-Item (Join-Path $publish 'NetProbe.exe') (Join-Path $release 'NetProbe-Portable.exe') -Force

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { Write-Warning 'Inno Setup not found - skipped installer (winget install JRSoftware.InnoSetup)'; return }
& $iscc /Q "/DAppVersion=$version" "/DPublishDir=$publish" "/DOutDir=$release" (Join-Path $PSScriptRoot 'installer.iss')
if ($LASTEXITCODE) { throw 'Inno Setup failed' }

Get-ChildItem $release -Filter *.exe | ForEach-Object { '{0,-32} {1,6:N1} MB' -f $_.Name, ($_.Length / 1MB) }
