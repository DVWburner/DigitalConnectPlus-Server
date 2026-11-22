$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir = Join-Path $Root "dist"
$PortableDir = Join-Path $DistDir "portable-win-x64"
$SetupDir = Join-Path $Root "src\DigitalConnectPlus.Setup"
$PayloadZip = Join-Path $SetupDir "payload.zip"

Write-Host "=== [1/5] Running Automated E2EE & TLS Integration Test Suite ===" -ForegroundColor Cyan
dotnet test (Join-Path $Root "tests\DigitalConnectPlus.Tests\DigitalConnectPlus.Tests.csproj") -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests failed; aborting build." }

if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir -Force | Out-Null }
Get-ChildItem $DistDir -Filter "*.old" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
if (Test-Path $PortableDir) { Remove-Item $PortableDir -Recurse -Force }
New-Item -ItemType Directory -Path $PortableDir -Force | Out-Null

Write-Host "=== [2/5] Publishing Self-Contained DigitalConnectPlus.Server (win-x64) ===" -ForegroundColor Cyan
$ServerStage = Join-Path $DistDir "_stage_server"
dotnet publish (Join-Path $Root "src\DigitalConnectPlus.Server\DigitalConnectPlus.Server.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=none -p:DebugSymbols=false `
    -o $ServerStage
if ($LASTEXITCODE -ne 0) { throw "Server publish failed." }

Write-Host "=== [3/5] Publishing Self-Contained DigitalConnectPlus.Tray (win-x64) ===" -ForegroundColor Cyan
$TrayStage = Join-Path $DistDir "_stage_tray"
dotnet publish (Join-Path $Root "src\DigitalConnectPlus.Tray\DigitalConnectPlus.Tray.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=none -p:DebugSymbols=false `
    -o $TrayStage
if ($LASTEXITCODE -ne 0) { throw "Tray publish failed." }

Copy-Item (Join-Path $ServerStage "*") $PortableDir -Recurse -Force
Copy-Item (Join-Path $TrayStage "DigitalConnectPlus.Tray.exe") $PortableDir -Force
Remove-Item $ServerStage -Recurse -Force
Remove-Item $TrayStage -Recurse -Force

# Remove default appsettings development artifacts so user settings live cleanly in %ProgramData%\DigitalConnectPlus
Remove-Item (Join-Path $PortableDir "appsettings*.json") -Force -ErrorAction SilentlyContinue

Write-Host "=== [4/5] Creating Portable Archive & Installer Payload ===" -ForegroundColor Cyan
$PortableZip = Join-Path $DistDir "DigitalConnectPlus-Portable-win-x64.zip"
Compress-Archive -Path (Join-Path $PortableDir "*") -DestinationPath $PortableZip -CompressionLevel Optimal -Force
Copy-Item $PortableZip $PayloadZip -Force

Write-Host "=== [5/5] Building Single-File Self-Contained Setup & Updater (DigitalConnectPlus-Setup.exe) ===" -ForegroundColor Cyan
$SetupStage = Join-Path $DistDir "_stage_setup"
try {
    dotnet publish (Join-Path $SetupDir "DigitalConnectPlus.Setup.csproj") `
        -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -p:DebugType=none -p:DebugSymbols=false `
        -o $SetupStage
    if ($LASTEXITCODE -ne 0) { throw "Setup publish failed." }

    $TargetSetupExe = Join-Path $DistDir "DigitalConnectPlus-Setup.exe"
    if (Test-Path $TargetSetupExe) {
        try {
            Remove-Item $TargetSetupExe -Force -ErrorAction Stop
        }
        catch {
            # On Windows NTFS, a running .exe cannot be deleted directly, but CAN be renamed out of the way!
            $OldExe = Join-Path $DistDir ("DigitalConnectPlus-Setup." + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".old")
            Move-Item $TargetSetupExe $OldExe -Force
        }
    }
    Move-Item (Join-Path $SetupStage "DigitalConnectPlus-Setup.exe") $TargetSetupExe -Force
}
finally {
    Remove-Item $SetupStage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $PayloadZip -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Build Succeeded!" -ForegroundColor Green
Get-ChildItem $DistDir -File | Select-Object Name, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}}
