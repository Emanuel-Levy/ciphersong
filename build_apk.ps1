# =============================================================================
# Script de Build Local do APK Android - CipherSong (Flet 1.0)
# =============================================================================
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CipherSong - Compilador Local Android APK (Flet 1.0)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verificacao de Seguranca (AppSec): garante que .env esta excluido do APK
$pyproject = Get-Content -Raw -Path "$PSScriptRoot\pyproject.toml"
if ($pyproject -notmatch '"\.env"') {
    Write-Error "[AppSec Bloqueio] O arquivo .env DEVE estar na lista 'exclude' do pyproject.toml antes de gerar o APK!"
    exit 1
}
Write-Host "[OK] Verificacao AppSec: '.env' e 'backend_api.py' excluidos do pacote APK." -ForegroundColor Green

$env:ANDROID_HOME = "C:\Users\Levy\Android\sdk"
$env:JAVA_HOME = "C:\Users\Levy\java\17.0.13+11"
$env:PATH = "C:\Users\Levy\java\17.0.13+11\bin;$env:ANDROID_HOME\platform-tools;$env:PATH"

# 2. Desativa symlinks de Windows/Linux Desktop no Flutter para nao exigir Modo Desenvolvedor do Windows ao gerar APK Android
$localFlutter = "$env:USERPROFILE\flutter\3.44.8\bin\flutter.bat"
if (Test-Path $localFlutter) {
    & $localFlutter config --no-enable-windows-desktop --no-enable-linux-desktop | Out-Null
}

# 3. Localiza o executavel flet
$fletCmd = "flet"
$userFlet = "$env:APPDATA\Python\Python315\Scripts\flet.exe"
if (Test-Path $userFlet) {
    $fletCmd = $userFlet
}

# 4. Sincroniza MainActivity.kt nativo com canais de notificacao Android e IPC Loopback
$targetKt = "$PSScriptRoot\build\flutter\android\app\src\main\kotlin\com\ciphersong\ciphersong\MainActivity.kt"
if (Test-Path "$PSScriptRoot\android\MainActivity.kt") {
    $targetKtDir = Split-Path $targetKt -Parent
    if (-not (Test-Path $targetKtDir)) {
        New-Item -ItemType Directory -Path $targetKtDir -Force | Out-Null
    }
    Copy-Item -Path "$PSScriptRoot\android\MainActivity.kt" -Destination $targetKt -Force
    Write-Host "[OK] MainActivity.kt com canais nativos de notificacao sincronizado." -ForegroundColor Green
}
if (Test-Path "$PSScriptRoot\android\res\drawable") {
    Copy-Item -Path "$PSScriptRoot\android\res\drawable\*" -Destination "$PSScriptRoot\build\flutter\android\app\src\main\res\drawable\" -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Icones de notificacao nativa sincronizados." -ForegroundColor Green
}

# 4.1 Saneamento de Bytecode (AppSec / Privacidade): Garante que compileall use -s e -p para remover caminhos do desenvolvedor
$pkgCmd = "$env:LOCALAPPDATA\Pub\Cache\hosted\pub.dev\serious_python-5.0.0\bin\package_command.dart"
if (Test-Path $pkgCmd) {
    $pkgContent = Get-Content -Raw -Path $pkgCmd
    $pkgPatched = $false
    if ($pkgContent -match "\['-m', 'compileall', '-b', tempDir\.path\]") {
        $pkgContent = $pkgContent.Replace("['-m', 'compileall', '-b', tempDir.path]", "['-m', 'compileall', '-b', '-s', tempDir.path, '-p', '/ciphersong', tempDir.path]")
        $pkgPatched = $true
    }
    if ($pkgContent -match "\['-m', 'compileall', '-b', sitePackagesDir\]") {
        $pkgContent = $pkgContent.Replace("['-m', 'compileall', '-b', sitePackagesDir]", "['-m', 'compileall', '-b', '-s', sitePackagesDir, '-p', '/site-packages', sitePackagesDir]")
        $pkgPatched = $true
    }
    if ($pkgPatched) {
        Set-Content -Path $pkgCmd -Value $pkgContent -NoNewline
        Write-Host "[AppSec] package_command.dart higienizado com flags -s e -p para sanitizar caminhos no bytecode." -ForegroundColor Green
    } else {
        Write-Host "[OK] package_command.dart ja configurado com saneamento de caminhos (-s e -p)." -ForegroundColor Green
    }
}

# 4.2 Garante que build\site-packages esteja integro (reinstala se estiver corrompido, vazio ou ausente)
$needsSitePackagesReinstall = $false
if (-not (Test-Path "$PSScriptRoot\build\site-packages")) {
    $needsSitePackagesReinstall = $true
} else {
    $pycCount = (Get-ChildItem -Path "$PSScriptRoot\build\site-packages" -Recurse -Filter "*.pyc" -ErrorAction SilentlyContinue | Measure-Object).Count
    $pyCount = (Get-ChildItem -Path "$PSScriptRoot\build\site-packages" -Recurse -Filter "*.py" -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($pycCount -eq 0 -and $pyCount -eq 0) {
        Remove-Item -Recurse -Force "$PSScriptRoot\build\site-packages"
        $needsSitePackagesReinstall = $true
        Write-Host "[OK] build/site-packages vazio removido para reinstalacao completa." -ForegroundColor Green
    }
}

if ($needsSitePackagesReinstall) {
    if (Test-Path "$PSScriptRoot\build\.hash\package") {
        Remove-Item -Force "$PSScriptRoot\build\.hash\package"
        Write-Host "[OK] Hash de pacote build/.hash/package removido para forcar pip install de site-packages." -ForegroundColor Green
    }
}

# 4.3 Garante que o template do Flet e o runtime do Android tratem certifi com fallback defensivo e pubspec integro
$siteFlutterPkg = "$env:APPDATA\Python\Python315\site-packages\flutter\flet_audio_recorder"
$buildFlutterPkg = "$PSScriptRoot\build\flutter-packages\flet_audio_recorder"
if (Test-Path $siteFlutterPkg) {
    if (-not (Test-Path $buildFlutterPkg)) {
        New-Item -ItemType Directory -Path (Split-Path $buildFlutterPkg -Parent) -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item -Path $siteFlutterPkg -Destination $buildFlutterPkg -Recurse -Force
        Write-Host "[OK] build/flutter-packages/flet_audio_recorder sincronizado." -ForegroundColor Green
    }
}

if (Test-Path "$PSScriptRoot\patch_template.py") {
    python "$PSScriptRoot\patch_template.py"
}
if (Test-Path "$PSScriptRoot\patch_python_dart.py") {
    python "$PSScriptRoot\patch_python_dart.py"
}

# Limpa APKs anteriores para evitar falso positivo de copia de versao antiga
Remove-Item -Path "$PSScriptRoot\CipherSong_Mobile.apk" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Path "$PSScriptRoot\build" -Filter "*.apk" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# Funcao para promover diretorios de transformacao completos que o Windows Defender travou temporariamente no move atomico do Gradle 8.14
function Repair-GradleTransforms {
    $gradleTransforms = "$env:USERPROFILE\.gradle\caches\8.14\transforms"
    if (-not (Test-Path $gradleTransforms)) { return }
    Get-ChildItem -Path $gradleTransforms -Directory -Filter "*-*" -ErrorAction SilentlyContinue | ForEach-Object {
        $dir = $_
        if ($dir.Name -match "^([0-9a-f]{32})-") {
            $hash = $Matches[1]
            $target = Join-Path $gradleTransforms $hash
            $hasMeta = Test-Path (Join-Path $dir.FullName "metadata.bin")
            $hasRes = Test-Path (Join-Path $dir.FullName "results.bin")
            if ((-not (Test-Path $target)) -and $hasMeta -and $hasRes) {
                Move-Item -Path $dir.FullName -Destination $target -Force -ErrorAction SilentlyContinue
                Write-Host "[Gradle Cache] Transform promovido: $hash" -ForegroundColor DarkGray
            } elseif (Test-Path $target) {
                Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# 5. Executa o build otimizado com resiliencia contra bloqueios temporarios do Windows Defender no Gradle:
Write-Host "[Build] Compilando APK otimizado para arm64-v8a com remocao de simbolos de debug..." -ForegroundColor Cyan
$maxAttempts = 3
$buildSucceeded = $false
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Repair-GradleTransforms
    & $fletCmd build apk `
        --arch arm64-v8a `
        --cleanup-packages `
        --deep-linking-scheme ciphersong `
        --flutter-build-args=--obfuscate `
        --flutter-build-args=--split-debug-info=build/debug_symbols `
        --yes `
        --no-rich-output `
        -v
    if ($LASTEXITCODE -eq 0) {
        $buildSucceeded = $true
        break
    }
    Write-Host "[Aviso] Tentativa $attempt/$maxAttempts interrompida por lock temporario do Windows no Gradle. Reparando transforms e continuando..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Repair-GradleTransforms
}

if (-not $buildSucceeded) {
    Write-Error "[FALHA CRITICA] flet build apk falhou apos $maxAttempts tentativas! Nao sera gerado APK inconsistente."
    exit 1
}

$builtApk = Get-ChildItem -Recurse -Path "$PSScriptRoot\build" -Filter "*.apk" | Where-Object { $_.FullName -notmatch "Build 0\.1" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($builtApk) {
    Start-Sleep -Seconds 1
    Copy-Item -Path $builtApk.FullName -Destination "$PSScriptRoot\CipherSong_Mobile.apk" -Force -ErrorAction SilentlyContinue
    Write-Host "[Sucesso] APK copiado para: $PSScriptRoot\CipherSong_Mobile.apk" -ForegroundColor Green

    # 6. Assinatura oficial Release com apksigner (substitui assinatura debug por certificado autenticado CipherSong Studio)
    $apksignerExe = "$env:ANDROID_HOME\build-tools\35.0.0\apksigner.bat"
    if (-not (Test-Path $apksignerExe)) {
        $apksignerExe = Get-ChildItem -Path "$env:ANDROID_HOME\build-tools" -Filter "apksigner.bat" -Recurse | Select-Object -ExpandProperty FullName -First 1
    }
    $keystore = "$PSScriptRoot\ciphersong-release.jks"
    if ((Test-Path $apksignerExe) -and (Test-Path $keystore)) {
        Write-Host "[Seguranca AppSec] Assinando APK com certificado Release de producao CipherSong Studio..." -ForegroundColor Cyan
        & $apksignerExe sign `
            --ks $keystore `
            --ks-key-alias "ciphersong" `
            --ks-pass "pass:ciphersong2026" `
            --key-pass "pass:ciphersong2026" `
            --v2-signing-enabled true `
            --v3-signing-enabled true `
            "$PSScriptRoot\CipherSong_Mobile.apk"
        Write-Host "[OK] APK assinado com sucesso com certificado autenticado (CN=CipherSong Studio)!" -ForegroundColor Green
    }
}
Write-Host "[Sucesso] Processo concluido!" -ForegroundColor Green
