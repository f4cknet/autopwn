@echo off
rem ===========================================================================
rem  autopwn offline / remote auto-exploit - Windows entry (no bash needed)
rem
rem  Usage (run in this folder):
rem     solve.bat bench\ch01_note
rem     solve.bat bench
rem     solve.bat bench\ch13 --facts-only
rem     solve.bat note --cmd "cat /flag" --cmd "ls -la /"
rem     solve.bat pwn --host 1.2.3.4 --port 31337 --ssl --cmd "cat /flag"
rem ===========================================================================
setlocal
cd /d "%~dp0"

if "%~1"=="" goto usage

where docker >nul 2>nul
if errorlevel 1 goto nodocker

docker image inspect autopwn:pwn22 >nul 2>nul
if errorlevel 1 goto noimage

rem --host 127.0.0.1 / localhost means "a target on the host" -> share host network.
rem Otherwise reach the host via host.docker.internal (works on Desktop and Linux).
set "NETARGS=--add-host=host.docker.internal:host-gateway"
echo %* | findstr /i /c:"127.0.0.1" /c:"localhost" >nul 2>nul && set "NETARGS=--network host"

rem %%* passed through as-is (keeps quotes for --cmd "ls -la /")
docker run --rm %NETARGS% --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -e AUTOPWN_HOST_ROOT="%CD%" -v "%CD%:/work" -w /work autopwn:pwn22 python3 -m autopwn.engine.cli %*
exit /b %errorlevel%

:usage
echo [usage] solve.bat ^<challenge-dir^|binary^> [options]
echo    e.g. solve.bat bench
echo         solve.bat bench\ch01_note --facts-only
echo         solve.bat pwn --host 1.2.3.4 --port 31337 --ssl --cmd "cat /flag"
exit /b 2

:nodocker
echo [error] docker not found. Start Docker Desktop first.
exit /b 3

:noimage
echo [error] image autopwn:pwn22 missing. Run build_pwn.bat first.
exit /b 4
