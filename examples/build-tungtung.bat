@echo off
setlocal enabledelayedexpansion

:: ==========================================================================
:: BUILD "TungTung Poster" pakai tungtungarmor (pengganti build2.bat / PyArmor)
:: Semua opsi PyInstaller dibaca dari tungtungarmor.toml
:: ==========================================================================

cls
echo [INFO] Kompilasi (ONEDIR) "TungTung Poster" via tungtungarmor...
echo.

echo [SETUP] Membersihkan direktori lama...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist dist_protected rmdir /s /q dist_protected
echo.

:: Obfuscate seluruh project + build PyInstaller (opsi dari tungtungarmor.toml).
tungtungarmor pyinstaller
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
