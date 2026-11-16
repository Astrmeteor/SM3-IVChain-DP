# -*- coding: utf-8 -*-
"""实施例六：验证、异常检测与分级处置。

    式22  T_g = med_i‖g_i‖₂ + κ·MAD，MAD = med_i |‖g_i‖₂ − med_j‖g_j‖₂|
    式23  A_i^(t+1) = θ·A_i^(t) + (1 − θ)·1{第t轮核验与审计全部通过}

四通道：(a) 链连续性  (b) 鲁棒范数  (c) 历史一致性  (d) 门限追责审计
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence


def median(xs: Sequence[float]) -> float:
    if not xs:
        raise ValueError("空序列无中位数")
    s = sorted(xs)
    n = len(s)
    m = n // 2
    return s[m] if n % 2 else 0.5 * (s[m - 1] + s[m])


def mad(xs: Sequence[float]) -> float:
    """绝对中位差：MAD = med|x_i − med(x)|，击穿点 50%。"""
    med = median(xs)
    return median([abs(x - med) for x in xs])


def robust_threshold(norms: Sequence[float], kappa: float = 3.0) -> float:
    """式22：鲁棒范数阈值。"""
    return median(norms) + kappa * mad(norms)


def sigma_from_mad(xs: Sequence[float]) -> float:
    """正态近似下的稳健标准差估计 σ̂ ≈ 1.4826·MAD。"""
    return 1.4826 * mad(xs)


def l2(v: Sequence[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """余弦相似度；任一向量为零向量时返回 0。"""
    na, nb = l2(a), l2(b)
    if na == 0 or nb == 0:
        return 0.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


def _z_quantile(p: float) -> float:
    """标准正态分位数 z_p，用 math.erf 二分求解（避免引入第三方依赖）。"""
    if not 0.0 < p < 1.0:
        raise ValueError("p 应在 (0,1)")
    lo, hi = -10.0, 10.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        cdf = 0.5 * (1.0 + math.erf(mid / math.sqrt(2.0)))
        if cdf < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def suggest_theta_cos(dim: int, alpha: float = 0.05) -> float:
    """按零假设分布标定式(c) 通道的余弦阈值 θ_c。

    当模型接近收敛时真实梯度趋零、差分隐私噪声主导，两个独立各向同性
    随机向量夹角余弦近似服从均值 0、方差 1/d 的分布。据此取
        θ_c = z_α / √d      （z_α 为标准正态的 α 分位数，α 为容许误报率）
    可将该通道的误报率控制在 α 附近。若沿用与维度无关的固定阈值
    （如说明书示例值 0.1），在 d = 10 时对应约 38% 的误报率。
    """
    if dim < 1:
        raise ValueError("维度须为正")
    return _z_quantile(alpha) / math.sqrt(dim)


# --------------------------------------------------------------------------
# 式23：链核验信誉因子
# --------------------------------------------------------------------------
@dataclass
class Reputation:
    """由行为链存证的核验/审计结果递推得到的可核验信誉。"""
    theta: float = 0.8
    init: float = 0.5
    A: Dict[str, float] = field(default_factory=dict)

    def get(self, vid: str) -> float:
        return self.A.setdefault(vid, self.init)

    def update(self, vid: str, passed: bool) -> float:
        a = self.get(vid)
        a = self.theta * a + (1.0 - self.theta) * (1.0 if passed else 0.0)
        self.A[vid] = a
        return a


# --------------------------------------------------------------------------
# 检测结果
# --------------------------------------------------------------------------
@dataclass
class DetectResult:
    vid: str
    chain_ok: bool
    chain_errs: List[str]
    norm_flag: bool
    cos_flag: bool
    audit_flag: bool = False
    audit_reason: str = ""
    action: str = "接受"

    @property
    def flagged(self) -> bool:
        return (not self.chain_ok) or self.norm_flag or self.cos_flag or self.audit_flag


class Detector:
    """四通道检测器 + 分级处置。"""

    def __init__(self, kappa: float = 3.0, theta_cos: float = 0.1,
                 hist_len: int = 5):
        self.kappa = kappa
        self.theta_cos = theta_cos
        self.hist_len = hist_len
        self.history: Dict[str, List[List[float]]] = {}
        self.strikes: Dict[str, int] = {}

    def hist_mean(self, vid: str) -> List[float]:
        h = self.history.get(vid, [])
        if not h:
            return []
        d = len(h[0])
        return [sum(v[j] for v in h) / len(h) for j in range(d)]

    def push_history(self, vid: str, g: Sequence[float]):
        h = self.history.setdefault(vid, [])
        h.append(list(g))
        if len(h) > self.hist_len:
            h.pop(0)

    def screen(self, uploads: List[dict], chain_results: Dict[str, tuple],
               scales: Dict[str, float] = None) -> List[DetectResult]:
        """uploads: [{'vid':..,'vec':[..]}]；chain_results: vid -> (ok, errs)。

        scales 为各车上传量的公开尺度因子 s_i（可由链上绑定的 ε_i 与公开轮
        参数导出，无需车辆自报）。当各车分配到的隐私预算不同时，其噪声
        强度合法地不同，直接对原始范数施加式22 会把高噪声车辆误判为异常；
        因此这里对尺度归一化后的统计量
            z_i = ‖g_i‖₂ / s_i,   s_i = √(Δ₂² + d·σ_{v,i}²)
        施加式22 的中位数—MAD 阈值。各车尺度相同时该常数因子在中位数与
        MAD 中同比消去，退化为式22 的原始形式，二者自洽。
        """
        raw = [l2(u['vec']) for u in uploads]
        if scales:
            norms = [raw[i] / max(1e-12, scales.get(uploads[i]['vid'], 1.0))
                     for i in range(len(uploads))]
        else:
            norms = raw
        Tg = robust_threshold(norms, self.kappa) if len(norms) >= 3 else float('inf')

        out = []
        for i, u in enumerate(uploads):
            vid = u['vid']
            ok, errs = chain_results.get(vid, (True, []))
            norm_flag = norms[i] > Tg
            hm = self.hist_mean(vid)
            cos_flag = False
            if hm:
                cos_flag = cosine(u['vec'], hm) < self.theta_cos
            out.append(DetectResult(vid, ok, list(errs), norm_flag, cos_flag))
        return out, Tg

    def grade(self, r: DetectResult) -> str:
        """分级处置：降权 → 临时隔离 → 重新提交证明 → 追责审计 → 上报。"""
        if not r.flagged:
            self.strikes[r.vid] = 0
            r.action = "接受"
            return r.action
        self.strikes[r.vid] = self.strikes.get(r.vid, 0) + 1
        s = self.strikes[r.vid]
        if r.audit_flag:
            r.action = "追责审计判定违规：隔离并上报管理端"
        elif not r.chain_ok:
            r.action = "丢弃并要求重新提交证明"
        elif s == 1:
            r.action = "降权"
        elif s == 2:
            r.action = "临时隔离"
        else:
            r.action = "触发追责审计"
        return r.action
