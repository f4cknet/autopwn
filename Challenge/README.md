附件中的 `ret2libc` 为 64 位 Linux ELF，`libc.so.6` 是容器使用的配套 glibc。

源码和编译参数见 `docker/src/ret2libc.c`。服务端 Flag 位于 `/home/ctf/flag`。
