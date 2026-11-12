@echo off
rem ===========================================================================
rem  autopwn offline auto-exploit - Windows entry (no bash / WSL needed)
rem
rem  Usage (run in this folder):
rem     solve.bat bench\ch01_note
rem     solve.bat bench
rem     solve.bat bench\ch13_zip76c8 --facts-only
rem     solve.bat note
rem     solve.bat pwn --host 1.2.3.4 --port 31337 --libc libc.so.6
rem ===========================================================================
setlocal
cd /d "%~dp0"

if "%~1"=="" (
  echo [usage] solve.bat ^<challenge-dir^|binary^> [options]
  echo    e.g. solve.bat bench
  echo         solve.bat bench\ch01_note --facts-only
  exit /b 2
)

where docker >nul 2>nul
if errorlevel 1 (
  echo [error] docker not found. Start Docker Desktop first.
  exit /b 3
)

docker image inspect autopwn:pwn22 >nul 2>nul
if errorlevel 1 (
  echo [error] image autopwn:pwn22 missing. Run build_pwn.bat first.
  exit /b 4
)

rem the engine runs inside Linux, so backslashes in the target path must go
set "TARGET=%~1"
set "TARGET=%TARGET:\=/%"

docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "%CD%:/work" -w /work autopwn:pwn22 python3 -m autopwn.engine.cli "%TARGET%" %2 %3 %4 %5 %6 %7
exit /b %errorlevel%
