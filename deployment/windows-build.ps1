$composeFile = "$PSScriptRoot\docker-compose-build.yml"
$composeName = "rs-icap-builder"
$containerName = "Centos"

$cargoCheckResult = & cargo check

if ($LASTEXITCODE -ne 0)
{
    Write-Host "Ошибка: cargo check не прошел успешно. Исправьте ошибки перед созданием Docker-контейнера."
    exit 1
}
else
{
    Write-Host "Cargo check успешно завершен."
}

if (-Not (Test-Path $composeFile))
{
    Write-Host "Файл docker-compose не найден: $composeFile"
    exit 1
}
else
{
    Write-Host "Файл docker-compose найден."
}
docker-compose -f $composeFile up -d $composeName

Start-Sleep -Seconds 5

$containerId = docker ps -qf "name=$containerName"

if (-not $containerId)
{
    Write-Host "Контейнер с именем $containerName не найден."
    exit 1
}

$hostDirectory = "$PSScriptRoot\builded"

if (Test-Path $hostDirectory)
{
    Remove-Item "$hostDirectory\*" -Recurse -Force
}
else
{
    New-Item -ItemType Directory -Path $hostDirectory
}

docker cp "${containerId}:`/builded/." $hostDirectory

# Проверка успешности операции
if ($?)
{
    Write-Host "Бинарные файлы успешно извлечены и перезаписаны."
}
else
{
    Write-Host "Произошла ошибка при извлечении бинарных файлов."
}

$binaryPath = "$hostDirectory"
$deploymentSenderPath = "C:\Users\warka\Desktop\rust\bins\deployment-sender.exe"

# Получаем только исполняемые файлы, исключая .d файлы
$files = Get-ChildItem -Path $binaryPath -File | Where-Object { $_.Extension -ne '.d' }

# Формируем список путей к файлам
$filePaths = $files | ForEach-Object { $_.FullName }

$deploymentSenderResult = & $deploymentSenderPath $filePaths
if ($LASTEXITCODE -ne 0)
{
    Write-Host "Ошибка: Не удалось отправить файлы через deployment-sender."
    exit 1
}
else
{
    Write-Host "Файлы отправлены через deployment-sender."
}

docker-compose -f $composeFile down --rmi all

if ($?)
{
    Write-Host "Docker Compose удален."
}
else
{
    Write-Host "Произошла ошибка при удалении Docker Compose."
}
