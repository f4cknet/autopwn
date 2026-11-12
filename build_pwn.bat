@echo off
rem 重建 pwn 环境镜像（ubuntu 22.04 + pwntools/one_gadget/seccomp-tools/i386 库）
rem 用法：build_pwn.bat
setlocal
cd /d "%~dp0"
where docker >nul 2>nul
if errorlevel 1 (
  echo [错误] 找不到 docker，请先启动 Docker Desktop
  exit /b 3
)
echo [*] 开始构建 autopwn:pwn22（首次约 8-12 分钟）
docker build -t autopwn:pwn22 docker
if errorlevel 1 (
  echo [错误] 构建失败
  exit /b 1
)
echo [OK] 构建完成
docker images autopwn:pwn22 --format "{{.Repository}}:{{.Tag}}  {{.Size}}"
