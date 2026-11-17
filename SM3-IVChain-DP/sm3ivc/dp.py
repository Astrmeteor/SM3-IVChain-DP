# -*- coding: utf-8 -*-
"""链态耦合的可验证差分隐私（核心算法）。

    式8   seed_t   = HMAC-SM3(k_v, h_t^d ∥ ctr_t ∥ 0x01)
    式9   u_{t,j}  = HMAC-SM3(seed_t, j) / 2^256 ∈ (0,1)
    式10  拉普拉斯 n = −b·sgn(u−1/2)·ln(1−2|u−1/2|)，b = Δ₁/ε
    式11  高斯（Box–Muller） n = σ·√(−2·ln u₁)·cos(2π·u₂)
    式12  C_t = SM3(seed_t ∥ r_t)，r_t = HMAC-SM3(k_v, h_t^d ∥ 0x02)
    式13  clip(g) = g·min(1, Δ₂/‖g‖₂)
    式14  σ_g = Δ₂·√(2·ln(1.25/δ)) / ε_g

关键性质：噪声完全由 (k_v, h_t^d, ctr_t) 决定，而 h_t^d 在噪声生成之前
已对本轮数据作出承诺，故车辆无法自适应挑选噪声（定理6）；持有 k_v 的
审计方可确定性重算噪声（定理7）。
"""

from __future__ import annotations

import math
from typing import List, Sequence

from .sm3 import sm3, hmac_sm3
from .codec import cat, u64

TWO256 = float(1 << 256)
# 浮点安全区间：避免 ln(0) 与 u=1 导致的退化（式9 的浮点实现细节）
_U_LO = 1e-15
_U_HI = 1.0 - 1e-15


# --------------------------------------------------------------------------
# 式8 / 式12：种子与承诺
# --------------------------------------------------------------------------
def derive_seed(k_v: bytes, h_d: bytes, ctr: int) -> bytes:
    """式8：由根密钥与当前数据链链头派生噪声种子。"""
    return hmac_sm3(k_v, cat(h_d, u64(ctr), b'\x01'))


def derive_blind(k_v: bytes, h_d: bytes) -> bytes:
    """式12 中的盲化随机数 r_t。"""
    return hmac_sm3(k_v, cat(h_d, b'\x02'))


def commitment(seed: bytes, r: bytes) -> bytes:
    """式12：噪声承诺 C_t = SM3(seed_t ∥ r_t)。"""
    return sm3(cat(seed, r))


def open_commitment(k_v: bytes, h_d: bytes, ctr: int, commit: bytes) -> bool:
    """审计方持 k_v 时对承诺的开示核验。"""
    seed = derive_seed(k_v, h_d, ctr)
    return commitment(seed, derive_blind(k_v, h_d)) == commit


# --------------------------------------------------------------------------
# 式9：伪随机序列
# --------------------------------------------------------------------------
def prf_u(seed: bytes, j: int) -> float:
    """式9：u_{t,j} = HMAC-SM3(seed, j)/2^256，并夹取到开区间 (0,1)。

    夹取是式9 在 IEEE-754 双精度下的确定性实现：由于 2^256 远超双精度
    有效位数，端点邻域需显式规避以保证式10、式11 的良定义；夹取规则
    对审计方与车辆完全一致，故不破坏可复算性。
    """
    x = int.from_bytes(hmac_sm3(seed, u64(j)), 'big') / TWO256
    if x <= _U_LO:
        return _U_LO
    if x >= _U_HI:
        return _U_HI
    return x


def prf_stream(seed: bytes, n: int, offset: int = 1) -> List[float]:
    return [prf_u(seed, offset + i) for i in range(n)]


# --------------------------------------------------------------------------
# 式10 / 式11：逆累积分布变换采样
# --------------------------------------------------------------------------
def laplace_from_u(u: float, b: float) -> float:
    """式10：拉普拉斯逆 CDF 采样，尺度参数 b = Δ₁/ε。"""
    d = u - 0.5
    s = 1.0 if d > 0 else (-1.0 if d < 0 else 0.0)
    arg = 1.0 - 2.0 * abs(d)
    if arg < 1e-300:
        arg = 1e-300
    return -b * s * math.log(arg)


def gauss_from_u(u1: float, u2: float, sigma: float) -> float:
    """式11：Box–Muller 变换生成高斯噪声。"""
    return sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


def laplace_noise(seed: bytes, dim: int, delta1: float, eps: float) -> List[float]:
    """由种子确定性生成 dim 维拉普拉斯噪声（式9 + 式10）。"""
    if eps <= 0:
        raise ValueError("ε 必须为正")
    b = delta1 / eps
    return [laplace_from_u(prf_u(seed, j), b) for j in range(1, dim + 1)]


def gaussian_noise(seed: bytes, dim: int, sigma: float) -> List[float]:
    """由种子确定性生成 dim 维高斯噪声（式9 + 式11）。

    第 j 维消耗 u_{2j−1}、u_{2j} 两个伪随机数，与式11 索引约定一致。
    """
    out = []
    for j in range(1, dim + 1):
        u1 = prf_u(seed, 2 * j - 1)
        u2 = prf_u(seed, 2 * j)
        out.append(gauss_from_u(u1, u2, sigma))
    return out


# --------------------------------------------------------------------------
# 式13 / 式14：裁剪与高斯机制标定
# --------------------------------------------------------------------------
def l2_norm(v: Sequence[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def clip(g: Sequence[float], delta2: float) -> List[float]:
    """式13：L2 范数裁剪，保证单车对聚合和的 L2 敏感度不超过 Δ₂。"""
    n = l2_norm(g)
    if n == 0.0:
        return list(g)
    f = min(1.0, delta2 / n)
    return [x * f for x in g]


def sigma_gauss(delta2: float, eps: float, delta: float) -> float:
    """式14 / 定理4：高斯机制满足 (ε,δ)-DP 所需的噪声标准差。"""
    if not (0 < eps < 1):
        # 经典解析式在 ε∈(0,1) 上成立；越界时给出提示但仍按公式计算
        pass
    if not (0 < delta < 1):
        raise ValueError("δ 应在 (0,1)")
    return delta2 * math.sqrt(2.0 * math.log(1.25 / delta)) / eps


def eps_from_sigma(delta2: float, sigma: float, delta: float) -> float:
    """式14 的反解，用于层间视角的隐私量化（式16 的等价形式）。"""
    return delta2 * math.sqrt(2.0 * math.log(1.25 / delta)) / sigma


def laplace_scale(delta1: float, eps: float) -> float:
    """b = Δ₁/ε。"""
    return delta1 / eps


# --------------------------------------------------------------------------
# 车端一次完整的"链态耦合加噪 + 承诺"操作
# --------------------------------------------------------------------------
class ChainCoupledDP:
    """封装式8→式13→式10/11→式12 的完整流程。"""

    def __init__(self, k_v: bytes):
        self.k_v = k_v

    def perturb(self, g: Sequence[float], h_d: bytes, ctr: int,
                mechanism: str = "gauss", delta2: float = 1.0,
                sigma: float = 0.1, delta1: float = 1.0, eps: float = 1.0):
        """返回 (含噪向量, 承诺, 种子, 噪声向量)。

        注意调用次序：h_d 必须是已对本轮数据作出承诺的链头（式2），
        噪声在其之后派生，从而阻断自适应噪声构造（定理6）。
        """
        gc = clip(g, delta2)
        seed = derive_seed(self.k_v, h_d, ctr)
        if mechanism == "gauss":
            n = gaussian_noise(seed, len(gc), sigma)
        elif mechanism == "laplace":
            n = laplace_noise(seed, len(gc), delta1, eps)
        else:
            raise ValueError("mechanism 应为 'gauss' 或 'laplace'")
        y = [a + b for a, b in zip(gc, n)]
        c = commitment(seed, derive_blind(self.k_v, h_d))
        return y, c, seed, n
