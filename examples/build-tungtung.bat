@echo off
setlocal enabledelayedexpansion

:: ==========================================================================
:: BUILD "TungTung Poster" pakai tungtungarmor (pengganti build2.bat / PyArmor)
:: Semua opsi PyInstaller dibaca dari file config TOML.
:: ==========================================================================

:: Pindah ke folder tempat .bat ini berada (= root project).
cd /d "%~dp0"

:: Nama file config. Ganti kalau file Anda bernama lain.
set "TTA_CONFIG=tungtungarmor.toml"

cls
echo [INFO] Kompilasi (ONEDIR) "TungTung Poster" via tungtungarmor...
echo [INFO] Folder kerja : %CD%
echo [INFO] File config  : %TTA_CONFIG%
echo.

if not exist "%TTA_CONFIG%" (
    echo [ERROR] File config "%TTA_CONFIG%" tidak ditemukan di %CD%.
    echo [ERROR] Salin examples\tungtung-poster.toml ke sini dan beri nama %TTA_CONFIG%,
    echo [ERROR] atau ubah variabel TTA_CONFIG di atas.
    goto :eof
)

echo [SETUP] Membersihkan direktori lama...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist dist_protected rmdir /s /q dist_protected
echo.

:: Obfuscate seluruh project + build PyInstaller (opsi dari file config).
tungtungarmor pyinstaller --config "%TTA_CONFIG%"
if errorlevel 1 (
    echo [ERROR] Build gagal.
    goto :eof
)
echo.

if not defined CERT_PASS (
    echo [ERROR] Variabel environment CERT_PASS tidak ditemukan.
    echo [ERROR] Proses code signing dibatalkan.
    goto :eof
)

echo [INFO] Menandatangani executable...
signtool sign /f "D:\Tool\Auto Upload\Certificate\TungTungUploader.pfx" /p "%CERT_PASS%" /tr "http://timestamp.digicert.com" /td SHA256 /fd SHA256 "D:\Tool\Auto Upload\dist\TungTung Poster\TungTung Poster.exe"

python generate_hash.py "D:\Tool\Auto Upload\dist\TungTung Poster\TungTung Poster.exe"

echo.
echo [DONE] Selesai -^> dist\TungTung Poster\TungTung Poster.exe
