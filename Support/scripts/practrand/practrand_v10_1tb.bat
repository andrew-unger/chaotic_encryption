@echo off
REM CATWALK v10 PractRand 1 TB validation — all 8 seeds, sequential
REM Commit: c002dfb6f92018197614a56b1b36764ab5fc0582
REM Binary: cml_keystream_dump (built from that commit)
REM
REM Tier 1: seeds 0, 1, 2, 254, 255
REM Tier 2: seeds 3, 128, 64
REM
REM Usage:
REM   Support\scripts\practrand\practrand_v10_1tb.bat
REM (Run from the repo root.)

REM ── Resolve repo root from this script's location ─────────────────────────
REM   %~dp0 = ...\Support\scripts\practrand\
REM   ..\..\..\ takes us up to the repo root.
set "REPO_ROOT=%~dp0..\..\.."
pushd "%REPO_ROOT%"

set PRACTRAND="C:\Users\Unger\Documents\Code\PractRand\build\RNG_test.exe"
set DUMP=.\Catwalk\target\release\cml_keystream_dump.exe
set LOGDIR=.\Support\practrand_logs_v10

mkdir %LOGDIR% 2>nul

echo [%date% %time%] Starting CATWALK v10 PractRand 1TB validation > %LOGDIR%\run.log
echo Commit: c002dfb6f92018197614a56b1b36764ab5fc0582 >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1: Seed 0 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 0
%DUMP% 0 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed0.log 2>&1
echo [%date% %time%] Seed 0 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1: Seed 1 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 1
%DUMP% 1 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed1.log 2>&1
echo [%date% %time%] Seed 1 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1: Seed 2 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 2
%DUMP% 2 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed2.log 2>&1
echo [%date% %time%] Seed 2 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1: Seed 254 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 254
%DUMP% 254 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed254.log 2>&1
echo [%date% %time%] Seed 254 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1: Seed 255 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 255
%DUMP% 255 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed255.log 2>&1
echo [%date% %time%] Seed 255 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 1 COMPLETE --- >> %LOGDIR%\run.log
echo [%date% %time%] --- Tier 2: Seed 3 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 3
%DUMP% 3 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed3.log 2>&1
echo [%date% %time%] Seed 3 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 2: Seed 128 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 128
%DUMP% 128 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed128.log 2>&1
echo [%date% %time%] Seed 128 complete >> %LOGDIR%\run.log

echo [%date% %time%] --- Tier 2: Seed 64 --- >> %LOGDIR%\run.log
echo [%date% %time%] Starting Seed 64
%DUMP% 64 | %PRACTRAND% stdin64 -tlmax 1TB > %LOGDIR%\seed64.log 2>&1
echo [%date% %time%] Seed 64 complete >> %LOGDIR%\run.log

echo [%date% %time%] ALL SEEDS COMPLETE >> %LOGDIR%\run.log
echo [%date% %time%] All seeds complete.

popd
