# -*- coding: utf-8 -*-
"""实施例五（5.1–5.3）：分层噪声分解与层间隐私量化。

    式15  σ_v² = ρ_v·σ_g²/K，σ_r² = ρ_r·σ_g²/R，σ_m² = ρ_m·σ_g²，Σρ = 1
    定理8  K·σ_v² + R·σ_r² + σ_m² = σ_g²（独立高斯方差可加）
    式16  ε_RSU = Δ₂·√(2·ln(1.25/δ))/σ_v = ε_g·√(K/ρ_v)
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .dp import sigma_gauss, eps_from_sigma


@dataclass
class LayerSplit:
    sigma_g: float
    sigma_v: float
    sigma_r: float
    sigma_m: float
    rho_v: float
    rho_r: float
    rho_m: float
    K: int
    R: int

    @property
    def var_sum(self) -> float:
        """定理8 左端：K·σ_v² + R·σ_r² + σ_m²。"""
        return self.K * self.sigma_v ** 2 + self.R * self.sigma_r ** 2 + self.sigma_m ** 2

    def theorem8_holds(self, tol: float = 1e-9) -> bool:
        return abs(self.var_sum - self.sigma_g ** 2) <= tol * max(1.0, self.sigma_g ** 2)


def split_variance(delta2: float, eps_g: float, delta: float, K: int, R: int,
                   rho_v: float = 0.5, rho_r: float = 0.3,
                   rho_m: float = 0.2) -> LayerSplit:
    """式14 + 式15：计算全局所需 σ_g 并按比例分解到三层。"""
    tot = rho_v + rho_r + rho_m
    if abs(tot - 1.0) > 1e-9:
        raise ValueError("分解比例须满足 ρ_v + ρ_r + ρ_m = 1，当前和为 %.6f" % tot)
    if min(rho_v, rho_r, rho_m) < 0:
        raise ValueError("分解比例须非负")
    if K < 1 or R < 1:
        raise ValueError("K、R 须为正整数")
    sg = sigma_gauss(delta2, eps_g, delta)
    sv = math.sqrt(rho_v * sg ** 2 / K)
    sr = math.sqrt(rho_r * sg ** 2 / R)
    sm = math.sqrt(rho_m * sg ** 2)
    return LayerSplit(sg, sv, sr, sm, rho_v, rho_r, rho_m, K, R)


def eps_rsu_view(split: LayerSplit, delta2: float, delta: float) -> float:
    """式16：半诚实 RSU 仅观察单车更新时的等效隐私预算。"""
    return eps_from_sigma(delta2, split.sigma_v, delta)


def eps_rsu_closed_form(eps_g: float, K: int, rho_v: float) -> float:
    """式16 的闭式等价形式 ε_g·√(K/ρ_v)，用于交叉校验。"""
    if rho_v <= 0:
        return float('inf')
    return eps_g * math.sqrt(K / rho_v)


# --------------------------------------------------------------------------
# 车辆层总方差在各车之间的异构分摊
# --------------------------------------------------------------------------
def vehicle_variance_shares(eps_list) -> list:
    """按各车分配到的 ε_i 计算车辆层方差份额 w_i，Σw_i = 1。

    单次查询的噪声方差与 ε² 成反比，故预算越紧（ε_i 越小）的车辆应承担
    越大的噪声方差份额：
        w_i = (1/ε_i²) / Σ_j (1/ε_j²)
    当各车 ε 相等时 w_i = 1/K，退化为式15 的均匀分摊，二者自洽。
    """
    inv = [1.0 / (e * e) for e in eps_list]
    s = sum(inv)
    if s <= 0:
        n = len(eps_list)
        return [1.0 / n] * n
    return [x / s for x in inv]


def vehicle_sigmas(split: LayerSplit, eps_list) -> list:
    """将车辆层总方差 ρ_v·σ_g² 按 vehicle_variance_shares 分摊到各车。

    构造上满足 Σ_i σ_{v,i}² = ρ_v·σ_g²，因此定理8 仍以等式成立：
        Σ_i σ_{v,i}² + R·σ_r² + σ_m² = σ_g²
    这样，行为链中声明的 ε_i 与该车实际施加的噪声强度一一对应，
    审计方可由链上 ε_i 与公开轮参数确定性地重算 σ_{v,i}（无需车辆自报）。
    """
    total = split.rho_v * split.sigma_g ** 2
    return [math.sqrt(total * w) for w in vehicle_variance_shares(eps_list)]


def sigma_of_eps(eps_i: float, inv_sum: float, rho_v: float, sigma_g: float) -> float:
    """审计方侧的单车噪声标准差复算：仅用链上绑定的 ε_i 与公开轮参数。"""
    if eps_i <= 0 or inv_sum <= 0:
        return 0.0
    return math.sqrt(rho_v * sigma_g ** 2 * (1.0 / (eps_i * eps_i)) / inv_sum)


def theorem8_holds_hetero(sigmas_v, split: LayerSplit, tol: float = 1e-9) -> bool:
    """异构车辆噪声下的定理8 核验。"""
    lhs = sum(s * s for s in sigmas_v) + split.R * split.sigma_r ** 2 + split.sigma_m ** 2
    return abs(lhs - split.sigma_g ** 2) <= tol * max(1.0, split.sigma_g ** 2)
