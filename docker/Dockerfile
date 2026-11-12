FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# ---------------------------------------------------------------- apt 基础环境
# 官方源 + i386 多架构（32 位题目必需）
RUN dpkg --add-architecture i386 \
 && apt-get -o Acquire::Retries=5 update \
 && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      ca-certificates curl wget git file unzip zip xz-utils vim less procps \
      build-essential gcc g++ make pkg-config \
      gdb gdbserver strace ltrace \
      binutils patchelf socat netcat-openbsd \
      python3 python3-pip python3-dev python3-venv \
      libc6:i386 libc6-dbg libc6-dbg:i386 libstdc++6:i386 zlib1g:i386 \
      ruby ruby-dev libssl-dev zlib1g-dev \
      qemu-user \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------- python 侧工具链
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
 && pip3 install --upgrade pip setuptools wheel \
 && pip3 install \
      pwntools==4.14.1 \
      ropper==1.13.13 \
      ROPGadget==7.6 \
      pyelftools requests \
      capstone keystone-engine \
      python-docx

# LibcSearcher（离线 libc 数据库，pip 源不一定有，失败不阻断）
RUN pip3 install LibcSearcher || echo "[warn] LibcSearcher skipped"

# ------------------------------------------------------------- ruby 侧工具链
RUN gem sources --add https://mirrors.tuna.tsinghua.edu.cn/rubygems/ --remove https://rubygems.org/ 2>/dev/null || true; \
    (gem install one_gadget --no-document || echo "[warn] one_gadget failed"); \
    (gem install seccomp-tools --no-document || echo "[warn] seccomp-tools failed")

# ------------------------------------------------------------------ gdb 增强
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg 2>/dev/null \
 && cd /opt/pwndbg && (./setup.sh || echo "[warn] pwndbg setup failed") || echo "[warn] pwndbg clone failed"

# ------------------------------------------------------- 常用辅助脚本 / 工具
RUN (curl -fsSL -o /usr/local/bin/pwninit https://github.com/io12/pwninit/releases/latest/download/pwninit \
      && chmod +x /usr/local/bin/pwninit) || echo "[warn] pwninit skipped"

# libc 数据库（仅克隆索引，不下载全量 libc）
RUN git clone --depth 1 https://github.com/niklasb/libc-database /opt/libc-database 2>/dev/null \
    || echo "[warn] libc-database skipped"

# 容器内默认用户 root，工作目录挂载点
WORKDIR /work
CMD ["/bin/bash"]
