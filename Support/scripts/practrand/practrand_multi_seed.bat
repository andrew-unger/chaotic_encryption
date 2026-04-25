@echo off
REM Multi-seed PractRand validation script
REM Runs PractRand (16 GB each) across 10 different seed indices.
REM
REM Prerequisites:
REM   - cargo build --release (catwalk keystream_dump binary)
REM   - PractRand RNG_test.exe compiled and on PATH or set PRACTRAND below
REM
REM Usage:
REM   Support\scripts\practrand\practrand_multi_seed.bat
REM (Run from the repo root.)

setlocal enabledelayedexpansion

REM ── Resolve repo root from this script's location ─────────────────────────
REM   %~dp0 = ...\Support\scripts\practrand\
REM   ..\..\..\ takes us up to the repo root.
set "REPO_ROOT=%~dp0..\..\.."
pushd "%REPO_ROOT%"

REM ── Configuration ──────────────────────────────────────────────────────────
set "KEYSTREAM_DUMP=Catwalk\target\release\cml_keystream_dump.exe"
set "PRACTRAND=C:\Users\Unger\Documents\Code\PractRand\build\RNG_test.exe"
set "MAX_LENGTH=16GB"
set "SEED_COUNT=10"
set "LOG_DIR=Support\practrand_logs"

REM ── Verify binaries exist ──────────────────────────────────────────────────
if not exist "%KEYSTREAM_DUMP%" (
    echo ERROR: %KEYSTREAM_DUMP% not found. Run: cargo build --release
    exit /b 1
)
if not exist "%PRACTRAND%" (
    echo ERROR: %PRACTRAND% not found. Compile PractRand first.
    exit /b 1
)

REM ── Create log directory ───────────────────────────────────────────────────
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo ============================================================
echo  CATWALK Multi-Seed PractRand Validation
echo  Seeds: 0-%SEED_COUNT%   Length: %MAX_LENGTH% each
echo ============================================================
echo.

set PASS=0
set FAIL=0

for /L %%S in (0,1,%SEED_COUNT%) do (
    echo [Seed %%S] Starting PractRand test to %MAX_LENGTH%...
    "%KEYSTREAM_DUMP%" %%S | "%PRACTRAND%" stdin64 -tlmax %MAX_LENGTH% > "%LOG_DIR%\seed_%%S.log" 2>&1
    set "EC=!errorlevel!"

    if !EC! equ 0 (
        echo [Seed %%S] PASS
        set /a PASS+=1
    ) else (
        echo [Seed %%S] FAIL ^(exit code !EC!^)
        set /a FAIL+=1
    )
    echo.
)

echo ============================================================
echo  Results: !PASS! passed, !FAIL! failed out of %SEED_COUNT% seeds
echo  Logs saved to %LOG_DIR%\
echo ============================================================

if !FAIL! gtr 0 (
    echo OVERALL: FAIL
    popd
    exit /b 1
) else (
    echo OVERALL: PASS
    popd
    exit /b 0
)

endlocal
