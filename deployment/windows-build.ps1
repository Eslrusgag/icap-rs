Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$targetTriple = "x86_64-unknown-linux-musl"
$buildProfile = "release"
$deploymentDir = $scriptDir
$buildedDir = Join-Path $deploymentDir "builded"
$deploymentSenderPath = "C:\Users\warka\Desktop\rust\bins\deployment-sender.exe"
$logFile = Join-Path $buildedDir "build-output.log"

function Get-CargoRoot([string]$startDir)
{
    $d = Resolve-Path $startDir
    while ($true)
    {
        if (Test-Path (Join-Path $d "Cargo.toml"))
        {
            return $d
        }
        $parent = Split-Path $d -Parent
        if (-not $parent -or $parent -eq $d)
        {
            break
        }
        $d = $parent
    }
    return $startDir
}

$cargoRoot = Get-CargoRoot $deploymentDir

function Map-CrossPathToHost([string]$p)
{
    if (-not $p)
    {
        return $null
    }
    if ( $p.StartsWith("/target/"))
    {
        $rel = $p.TrimStart("/").Replace("/", "\")   # "target\..."
        return Join-Path $cargoRoot $rel
    }
    return $p
}

function Is-RealBinPath([string]$p)
{
    if (-not $p)
    {
        return $false
    }
    $norm = $p.Replace('/', '\')
    if ($norm -notmatch "\\target\\[^\\]+\\(release|debug)\\")
    {
        return $false
    }
    if ($norm -match "\\target\\(release|debug)\\build\\")
    {
        return $false
    }
    return (Test-Path $p)
}


if (-not (Get-Command cargo -ErrorAction SilentlyContinue))
{
    Write-Host "Error: 'cargo' not found in PATH." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command cross -ErrorAction SilentlyContinue))
{
    Write-Host "Error: 'cross' not found in PATH. Install with: cargo install cross" -ForegroundColor Red
    exit 1
}

Write-Host "Check: cargo check" -ForegroundColor Cyan
$checkOutput = & cargo check 2>&1 | Tee-Object -Variable checkOutput
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Error: cargo check failed. See output above." -ForegroundColor Red
    exit 1
}
Write-Host "cargo check completed successfully." -ForegroundColor Green

Write-Host "Build: cross +stable build --$buildProfile --target $targetTriple" -ForegroundColor Cyan
if (Test-Path $logFile)
{
    Remove-Item $logFile -Force -ErrorAction SilentlyContinue
}

$mf = "json-diagnostic-rendered-ansi"
$buildOutput = & cross +stable build --$buildProfile --target $targetTriple --message-format=$mf 2>&1 `
    | Tee-Object -Variable buildOutput `
    | Tee-Object -FilePath $logFile
$exitCode = $LASTEXITCODE
$buildOutputText = ($buildOutput -join "`n")


$binNames = New-Object System.Collections.Generic.HashSet[string]
$exeCandidates = @()

foreach ($line in ($buildOutputText -split "`r?`n"))
{
    if ( [string]::IsNullOrWhiteSpace($line))
    {
        continue
    }
    try
    {
        $obj = $line | ConvertFrom-Json -ErrorAction Stop

        if ($obj.reason -eq "compiler-artifact" -and $obj.target)
        {
            if ($obj.target.kind -contains "bin" -and $obj.target.name)
            {
                if ($obj.package_id -and ($obj.package_id -like "path+file://*"))
                {
                    [void]$binNames.Add([string]$obj.target.name)
                }
            }
            if ($obj.target.kind -contains "bin" -and $obj.PSObject.Properties.Name -contains "executable" -and $obj.executable)
            {
                if ($obj.package_id -and ($obj.package_id -like "path+file://*"))
                {
                    $exeCandidates += $obj | Select-Object `
                        @{ n = "executable"; e = { $_.executable } }, `
                         @{ n = "name"; e = { $_.target.name } }
                }
            }
        }

        if ($exitCode -ne 0 -and $obj.reason -eq "compiler-message" -and $obj.message -and $obj.message.rendered)
        {
            Write-Host $obj.message.rendered
        }
    }
    catch
    {
    }
}

if ($exitCode -ne 0)
{
    Write-Host "Error: build failed." -ForegroundColor Red
    if (Test-Path $logFile)
    {
        Write-Host "---- Last 200 lines of build-output.log ----" -ForegroundColor Yellow
        Get-Content $logFile -Tail 200 | ForEach-Object { Write-Host $_ }
        Write-Host "-------------------------------------------" -ForegroundColor Yellow
        Write-Host ("Full build log saved to: {0}" -f $logFile) -ForegroundColor Yellow
    }
    exit 1
}

Write-Host "Build completed successfully." -ForegroundColor Green

$executables = @(
$exeCandidates |
        ForEach-Object {
            $mapped = Map-CrossPathToHost $_.executable
            $fileBase = [IO.Path]::GetFileName($mapped)
            $nameMatch = ($fileBase -eq $_.name) -or ($fileBase -eq "$( $_.name ).exe")
            if ($nameMatch -and (Is-RealBinPath $mapped))
            {
                $mapped
            }
        } |
        Select-Object -Unique
)


if (-not $executables -or @($executables).Count -eq 0)
{
    $fallbackDir = Join-Path $cargoRoot "target\$targetTriple\$buildProfile"
    if (Test-Path $fallbackDir)
    {
        $names = @($binNames)
        if (-not $names -or @($names).Count -eq 0)
        {
            $names = @()
        }

        $fallback = @()

        if (@($names).Count -gt 0)
        {
            foreach ($n in @($names))
            {
                $cand1 = Join-Path $fallbackDir $n
                $cand2 = Join-Path $fallbackDir ($n + ".exe")
                if (Test-Path $cand1)
                {
                    $fallback += $cand1
                }
                if (Test-Path $cand2)
                {
                    $fallback += $cand2
                }
            }
        }
        else
        {
            $fallback = Get-ChildItem -Path $fallbackDir -File |
                    Where-Object { [IO.Path]::GetExtension($_.Name) -eq "" } |
                    Select-Object -ExpandProperty FullName
        }

        $executables = @($fallback | Where-Object { Test-Path $_ } | Select-Object -Unique)
    }
}

if (-not $executables -or @($executables).Count -eq 0)
{
    Write-Host "Could not determine built executables." -ForegroundColor Red
    Write-Host "Tip: verify [[bin]] names and inspect $( Split-Path -Leaf $logFile )." -ForegroundColor Yellow
    exit 1
}

Write-Host ("Executables found: {0}" -f (@($executables).Count))
@($executables) | ForEach-Object { Write-Host "  $_" }

if (Test-Path $buildedDir)
{
    Remove-Item "$buildedDir\*" -Recurse -Force -ErrorAction SilentlyContinue
}
else
{
    New-Item -ItemType Directory -Path $buildedDir | Out-Null
}

foreach ($exe in @($executables))
{
    Copy-Item -Path $exe -Destination $buildedDir -Force
}
Write-Host "Binaries copied to: $buildedDir" -ForegroundColor Green

if (-not (Test-Path $deploymentSenderPath))
{
    Write-Host "Warning: deployment-sender not found at: $deploymentSenderPath" -ForegroundColor Yellow
    Write-Host "Skipping deploy step." -ForegroundColor Yellow
    exit 0
}

$files = @(Get-ChildItem -Path $buildedDir -File | Where-Object { $_.Extension -ne '.d' })
if (-not $files -or @($files).Count -eq 0)
{
    Write-Host "No files to send in $buildedDir." -ForegroundColor Yellow
    exit 0
}
$filePaths = @($files | ForEach-Object { $_.FullName })

Write-Host "Sending files via deployment-sender..." -ForegroundColor Cyan
& $deploymentSenderPath $filePaths
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Error: deployment-sender failed." -ForegroundColor Red
    exit 1
}
Write-Host "Files sent successfully via deployment-sender." -ForegroundColor Green
