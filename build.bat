@echo off

echo ============================================
echo       C PASSWORD MANAGER BUILD
echo ============================================
echo.

gcc -std=c11 -O2 -Wall -Wextra ^
    CPasswordManager.c ^
    -o CPasswordManager.exe ^
    -lbcrypt ^
    -ladvapi32 ^
    -luser32

if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    pause
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Created:
echo CPasswordManager.exe
echo.

pause