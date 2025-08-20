Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$targetTriple = "x86_64-unknown-linux-musl"
$buildProfile = "release"
$buildedDir = Join-Path $projectRoot "builded"
$deploymentSenderPath = "C:\Users\warka\Desktop\rust\bins\deployment-sender.exe"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue))
{
    Write-Host "Ошибка: cargo не найден в PATH." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command cross -ErrorAction SilentlyContinue))
{
    Write-Host "Ошибка: cross не найден в PATH. Установите: cargo install cross" -ForegroundColor Red
    exit 1
}

Write-Host "Проверка: cross +stable check --target $targetTriple" -ForegroundColor Cyan
$check = & cross +stable check --target $targetTriple 2>&1
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Ошибка: cross check не прошёл. Исправьте ошибки выше." -ForegroundColor Red
    exit 1
}
Write-Host "cross check успешно завершён." -ForegroundColor Green

Write-Host "Сборка: cross +stable build --release --target $targetTriple (c JSON-выводом)" -ForegroundColor Cyan
# Важно: --message-format=json позволяет корректно вытащить пути к исполняемым файлам
$buildOutput = & cross +stable build --$buildProfile --target $targetTriple --message-format=json 2>&1
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Ошибка: сборка завершилась неуспешно." -ForegroundColor Red
    exit 1
}
Write-Host "Сборка успешно завершена." -ForegroundColor Green

# --- Парсинг JSON-вывода и сбор путей к итоговым бинарям ---
# Ищем объекты с reason = "compiler-artifact" и непустым полем "executable"
$executables = @()
foreach ($line in ($buildOutput -split "`r?`n"))
{
    if ( [string]::IsNullOrWhiteSpace($line))
    {
        continue
    }
    try
    {
        $obj = $line | ConvertFrom-Json -ErrorAction Stop
        if ($obj.reason -eq "compiler-artifact" -and $obj.PSObject.Properties.Name -contains "executable")
        {
            if ($obj.executable)
            {
                $executables += $obj.executable
            }
        }
    }
    catch
    {
        # Игнор строк, которые не являются JSON
    }
}
$executables = $executables | Where-Object { $_ } | Select-Object -Unique

if (-not $executables -or $executables.Count -eq 0)
{
    # Фолбэк: берём все файлы без расширения из target/<triple>/release
    $fallbackDir = Join-Path $projectRoot "target\$targetTriple\$buildProfile"
    if (Test-Path $fallbackDir)
    {
        $executables = Get-ChildItem -Path $fallbackDir -File |
                Where-Object { [IO.Path]::GetExtension($_.Name) -eq "" } |
                Select-Object -ExpandProperty FullName
    }
}

if (-not $executables -or $executables.Count -eq 0)
{
    Write-Host "Не удалось определить собранные исполняемые файлы." -ForegroundColor Red
    exit 1
}

Write-Host "Найдено исполняемых файлов: $( $executables.Count )"
$executables | ForEach-Object { Write-Host "  $_" }

# --- Подготовка папки builded ---
if (Test-Path $buildedDir)
{
    Remove-Item "$buildedDir\*" -Recurse -Force -ErrorAction SilentlyContinue
}
else
{
    New-Item -ItemType Directory -Path $buildedDir | Out-Null
}

# Копируем только бинарники (без .d, .rlib, и т.п.)
foreach ($exe in $executables)
{
    # На musl таргете расширения обычно нет; просто копируем как есть
    Copy-Item -Path $exe -Destination $buildedDir -Force
}

Write-Host "Бинарные файлы скопированы в: $buildedDir" -ForegroundColor Green

# --- Отправка через deployment-sender ---
if (-not (Test-Path $deploymentSenderPath))
{
    Write-Host "Предупреждение: deployment-sender не найден по пути: $deploymentSenderPath" -ForegroundColor Yellow
    Write-Host "Пропускаю шаг отправки." -ForegroundColor Yellow
    exit 0
}

# Формируем список путей к файлам в builded
$files = Get-ChildItem -Path $buildedDir -File | Where-Object { $_.Extension -ne '.d' }
if (-not $files -or $files.Count -eq 0)
{
    Write-Host "Нет файлов для отправки в $buildedDir." -ForegroundColor Yellow
    exit 0
}
$filePaths = $files | ForEach-Object { $_.FullName }

Write-Host "Отправка файлов через deployment-sender..." -ForegroundColor Cyan
& $deploymentSenderPath $filePaths
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Ошибка: Не удалось отправить файлы через deployment-sender." -ForegroundColor Red
    exit 1
}
Write-Host "Файлы успешно отправлены через deployment-sender." -ForegroundColor Green
