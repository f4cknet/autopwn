@echo off
rem 进入 pwn 容器交互 shell（做题/手工调试用，里面 pwntools/gdb/one_gadget 都有）
rem 用法：shell.bat            进入 /work（就是本目录）
setlocal
cd /d "%~dp0"
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ^
  -v "%CD%:/work" -w /work autopwn:pwn22 bash
