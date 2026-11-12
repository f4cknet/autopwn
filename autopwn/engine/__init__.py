"""AutoPwn v6 engine —— 以「本地拿到 shell」为唯一成功判据的离线自动利用引擎.

设计原则（与旧 v4/v5 分层代码解耦，互不 import）:

1. 事实优先：所有决策来自静态事实（符号 / 保护 / gadget / 字符串）与动态反馈，
   不做猜测式「按名字硬编码题目」。
2. 每个策略都是「构造 payload → 交互 → 验证 shell」，验证失败即视为失败，
   绝不因为「没有报错」就判定成功。
3. 偏移量优先静态推导（读函数序言 + 调用点），静态拿不到再用 gdb / 暴力探测兜底。
4. 所有尝试留痕：payload、预置输入、输出片段、耗时，落到 results/*.json，
   便于人工复核与复盘。
"""
from .model import Challenge  # noqa: F401
from .orchestrator import solve  # noqa: F401

__all__ = ["Challenge", "solve"]
