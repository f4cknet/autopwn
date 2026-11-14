"""L1 交互层：`Send` / `Wait` 步骤与唯一一份收发时序实现。

本模块只依赖标准库与 tube 的 `send` / `recvrepeat` / `connected` 三个方法，
不 import `run.py`，避免循环依赖。成功判定仍由 `run.py` 负责，这里只管
「按步骤发、按步骤读、失败时把已读到的输出原样交回」。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional, Union

POLL = 0.06


@dataclass(frozen=True)
class Send:
    data: bytes


@dataclass(frozen=True)
class Wait:
    """等一段输出。

    needle=b"" 表示「读到静默」（旧 `_sync` 语义）；否则在累积缓冲中从游标处
    查找 needle。timeout=None 时使用 `Interaction.needle_timeout`。
    """
    needle: bytes = b""
    timeout: Optional[float] = None


Step = Union[Send, Wait]


def normalize_steps(steps) -> list:
    """把旧式 `list[bytes]` 与显式 Step 混用归一化；空 Send 丢弃（旧 execute 本就跳过）。"""
    out: list = []
    for s in steps:
        if isinstance(s, Wait):
            out.append(s)
        elif isinstance(s, Send):
            if s.data:
                out.append(s)
        elif isinstance(s, (bytes, bytearray)):
            if s:
                out.append(Send(bytes(s)))
        else:
            raise TypeError(f"unsupported step: {type(s).__name__}")
    return out


class StepError(Exception):
    """单个交互步骤失败；partial 是失败时的完整累积输出。"""

    def __init__(self, msg: str, partial: bytes = b""):
        super().__init__(msg)
        self.partial = partial


class WaitTimeout(StepError):
    def __init__(self, step: Wait, partial: bytes, waited: float):
        tail = partial[-120:]
        super().__init__(
            f"Wait({step.needle!r}) timeout after {waited:.1f}s tail={tail!r}", partial
        )
        self.step = step
        self.waited = waited


class Interaction:
    """把一个 tube 包装成「带游标的累积缓冲 + 步骤执行器」。"""

    def __init__(self, tube, *, silence_timeout: float = 1.0,
                 needle_timeout: float = 2.2):
        self.tube = tube
        self.silence_timeout = silence_timeout
        self.needle_timeout = needle_timeout
        self.buf = b""
        self.pos = 0

    # ------------------------------------------------------------------ 低层
    def read(self, timeout: float) -> bytes:
        """读一次并累积；任何异常都按「没读到」处理（EOF 由 _alive 判断）。"""
        try:
            chunk = self.tube.recvrepeat(timeout) or b""
        except Exception:
            return b""
        if chunk:
            self.buf += chunk
        return chunk

    def _alive(self) -> bool:
        try:
            return bool(self.tube.connected())
        except Exception:
            return False

    def send(self, data: bytes) -> None:
        try:
            self.tube.send(data)
        except Exception as exc:
            raise StepError(f"send failed: {exc}", self.buf) from exc

    def drain(self, timeout: float) -> bytes:
        """旧 `_sync`：出现数据后再静默一次即停；一直没数据则等满 deadline。"""
        got = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self.read(POLL)
            if chunk:
                got += chunk
                continue
            if got:
                break
            if not self._alive():
                break
        return got

    def wait_for(self, needle: bytes, timeout: Optional[float] = None) -> bytes:
        if not needle:
            before = len(self.buf)
            self.drain(self.silence_timeout if timeout is None else timeout)
            # 旧输出视为已消费：防止后续 Wait 匹配到同一个 prompt
            self.pos = len(self.buf)
            return self.buf[before:]

        limit = self.needle_timeout if timeout is None else timeout
        deadline = time.time() + limit
        while True:
            idx = self.buf.find(needle, self.pos)
            if idx >= 0:
                self.pos = idx + len(needle)
                return self.buf[idx:self.pos]
            if time.time() >= deadline:
                raise WaitTimeout(Wait(needle, timeout), self.buf, limit)
            chunk = self.read(POLL)
            if not chunk and not self._alive():
                # 进程已关闭：不要烧满超时
                raise WaitTimeout(Wait(needle, timeout), self.buf, limit)

    # ------------------------------------------------------------------ 步骤
    def run_steps(self, steps: Iterable[Step], *, sync_timeout: float = 1.0,
                  send_gap=None, final_sleep: float = 0.2,
                  final_read: float = 0.04) -> bytes:
        """执行步骤序列，返回完整累积输出。

        send_gap=(sleep, read) 时用固定间隔替代「读到静默」同步（flag 路径的旧行为）；
        下一条是 Wait 时不自动读，由 Wait 独占这个边界。
        """
        steps = list(steps)
        for idx, step in enumerate(steps):
            if isinstance(step, Wait):
                self.wait_for(step.needle, step.timeout)
                continue
            self.send(step.data)
            if idx == len(steps) - 1:
                continue                      # 最后一步的收尾在循环外
            if isinstance(steps[idx + 1], Wait):
                continue
            if send_gap is None:
                self.drain(sync_timeout)
            else:
                time.sleep(send_gap[0])
                self.read(send_gap[1])
        if final_sleep:
            time.sleep(final_sleep)
        if final_read:
            self.read(final_read)
        return self.buf
