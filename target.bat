@echo off
rem ===========================================================================
rem  Serve a challenge as a TCP target inside the pwn container, so it can be
rem  attacked exactly like a real remote (fresh ASLR on every connection).
rem
rem  Usage:
rem     target.bat                                    :: chellenges\pwn on 4444
rem     target.bat chellenges\pwn 4444
rem     target.bat chellenges\pwn 4444 noaslr         :: ASLR off, reproducible
rem     target.bat stop                               :: stop and remove
rem
rem  Then attack it:
rem     solve.bat chellenges\pwn --host 127.0.0.1 --port 4444 --max-attempts 80
rem ===========================================================================
setlocal
cd /d "%~dp0"

if /i "%~1"=="stop" goto stop

set BIN=%~1
if "%BIN%"=="" set BIN=chellenges\pwn
set PORT=%~2
if "%PORT%"=="" set PORT=4444
set MODE=%~3

where docker >nul 2>nul
if errorlevel 1 goto nodocker
docker image inspect autopwn:pwn22 >nul 2>nul
if errorlevel 1 goto noimage

set EXTRA=
if /i "%MODE%"=="noaslr" set EXTRA=-e NO_ASLR=1 --security-opt seccomp=unconfined

echo [*] restarting target container pwn-target ...
docker rm -f pwn-target >nul 2>nul
docker run -d --name pwn-target -p %PORT%:%PORT% %EXTRA% -v "%CD%:/work" -w /work autopwn:pwn22 sh /work/docker/serve.sh "%BIN%" %PORT% "CTF2{docker-local-target}"
if errorlevel 1 goto runfail

echo [*] waiting for listener ...
ping -n 3 127.0.0.1 >nul 2>nul
docker logs pwn-target 2>&1 | findstr /c:"mode" /c:"listen" /c:"error"
echo.
echo [+] target ready: 127.0.0.1:%PORT%   (container: pwn-target)
echo     solve.bat %BIN% --host 127.0.0.1 --port %PORT% --max-attempts 80
exit /b 0

:stop
echo [*] stopping pwn-target ...
docker rm -f pwn-target >nul 2>nul
echo [+] done
exit /b 0

:nodocker
echo [error] docker not found. Start Docker Desktop first.
exit /b 3

:noimage
echo [error] image autopwn:pwn22 missing. Run build_pwn.bat first.
exit /b 4

:runfail
echo [error] docker run failed
exit /b 5
