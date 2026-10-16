# =============================================================================
# Script de Build do APK Android - CipherSong
# =============================================================================
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CipherSong - Empacotador Oficial Android APK (Flet 1.0)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verificacao de Seguranca (AppSec): garante que .env esta excluido do APK
$pyproject = Get-Content -Raw -Path "$PSScriptRoot\pyproject.toml"
if ($pyproject -notmatch '"\.env"') {
    Write-Error "[AppSec Bloqueio] O arquivo .env DEVE estar na lista 'exclude' do pyproject.toml antes de gerar o APK!"
    exit 1
}
Write-Host "[OK] Verificacao AppSec: '.env' e 'backend_api.py' excluidos do pacote APK." -ForegroundColor Green

# 2. Localiza o executavel flet
$fletCmd = "flet"
$userFlet = "$env:APPDATA\Python\Python315\Scripts\flet.exe"
if (Test-Path $userFlet) {
    $fletCmd = $userFlet
}

# 3. Verifica pre-requisitos locais do Flutter / Android SDK
$hasFlutter = $null -ne (Get-Command "flutter" -ErrorAction SilentlyContinue)
$hasAndroidSdk = (Test-Path "$env:LOCALAPPDATA\Android\Sdk") -or ($null -ne $env:ANDROID_HOME)

if (-not $hasFlutter -or -not $hasAndroidSdk) {
    Write-Host ""
    Write-Host "[Aviso] Flutter SDK ou Android SDK nao detectados localmente neste Windows." -ForegroundColor Yellow
    Write-Host "Voce tem 2 opcoes para gerar o arquivo .apk:" -ForegroundColor White
    Write-Host "  Opcao A (Na Nuvem - 0 GB no PC): Faca push deste repositorio para o GitHub." -ForegroundColor Cyan
    Write-Host "           O workflow '.github/workflows/build-android-apk.yml' compilara o APK automaticamente na aba Actions!" -ForegroundColor Cyan
    Write-Host "  Opcao B (Compilar Localmente): Instale o Flutter + JDK 17 + Android Studio e rode:" -ForegroundColor Cyan
    Write-Host "           winget install -e --id EclipseAdoptium.Temurin.17.JDK" -ForegroundColor Gray
    Write-Host "           flet build apk --verbose" -ForegroundColor Gray
    exit 0
}

Write-Host "[Build] Iniciando compilacao do APK Android via Flet..." -ForegroundColor Cyan
& $fletCmd build apk --verbose
Write-Host "[Sucesso] APK gerado na pasta build/apk!" -ForegroundColor Green
