@echo off
echo =========================================
echo   SM4-CBC Test Suite Auto-Runner
echo   Date: %date% %time%
echo =========================================

cd /d "%~dp0.."

echo [1/3] Building test suite...
make clean
make
if errorlevel 1 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo [2/3] Running tests...
bin\sm4_cbc_test
set TEST_RESULT=%errorlevel%

echo [3/3] Generating report...
if exist logs\test_results.json (
    echo [OK] Test log saved to logs\test_results.json
) else (
    echo [ERROR] No log file generated!
    pause
    exit /b 1
)

if %TEST_RESULT% equ 0 (
    echo [OK] All tests passed!
) else (
    echo [FAIL] Some tests failed!
)

pause
exit /b %TEST_RESULT%