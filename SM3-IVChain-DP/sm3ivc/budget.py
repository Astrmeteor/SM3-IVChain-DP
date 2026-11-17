# -*- coding: utf-8 -*-
"""隐私预算的三级管理。

    式17  ε_total(T) = √(2T·ln(1/δ′))·ε₀ + T·ε₀·(e^ε₀ − 1)，δ_total = T·δ₀ + δ′
    式18  min Σ 2·u_i·Δ_i²/ε_i²  s.t. Σ ε_i = ε_total，0 < ε_i ≤ ε̄(S_i)
    式19  KKT：−4·u_i·Δ_i²/ε_i³ + λ = 0 ⇒ ε_i ∝ (u_i·Δ_i²)^(1/3)
    式20  ε_i* = ε_total·(u_i·Δ_i²)^(1/3) / Σ_j (u_j·Δ_j²)^(1/3)
    式21  ε_i^(t+1) = min{ ε̄(S_i), max{ ε_min, ε_i^(t)·(φ_i/φ̄)·e^(−α·S_i) } }
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Sequence


# --------------------------------------------------------------------------
# 式18 目标函数与凸性
# --------------------------------------------------------------------------
def distortion(u: Sequence[float], delta: Sequence[float],
               eps: Sequence[float]) -> float:
    """式18 目标：总失真 Σ 2·u_i·Δ_i²/ε_i²（拉普拉斯噪声方差之和）。"""
    tot = 0.0
    for ui, di, ei in zip(u, delta, eps):
        if ei <= 0:
            return float('inf')
        tot += 2.0 * ui * di * di / (ei * ei)
    return tot


def second_derivative(u_i: float, delta_i: float, eps_i: float) -> float:
    """d²/dε² [2uΔ²/ε²] = 12·u·Δ²/ε⁴ > 0，用于运行期核验严格凸性。"""
    return 12.0 * u_i * delta_i * delta_i / (eps_i ** 4)


# --------------------------------------------------------------------------
# 式20：闭式解 + 截断水填充
# --------------------------------------------------------------------------
@dataclass
class Allocation:
    eps: List[float]
    capped: List[bool]
    iterations: int
    total_used: float
    distortion: float
    feasible: bool
    note: str = ""


def water_filling(u: Sequence[float], delta: Sequence[float], eps_total: float,
                  caps: Optional[Sequence[float]] = None,
                  max_iter: int = 100) -> Allocation:
    """截断水填充：先按式20 闭式解分配，越界者固定于上限后对其余迭代再分配。

    由目标严格凸、约束线性可知 KKT 为最优性充要条件，且每轮至少固定一个
    变量，故算法在有限步内收敛到全局最优。
    """
    n = len(u)
    if n == 0:
        return Allocation([], [], 0, 0.0, 0.0, True, "无参与方")
    if len(delta) != n:
        raise ValueError("u 与 Δ 长度不一致")
    if eps_total <= 0:
        raise ValueError("ε_total 必须为正")
    if caps is None:
        caps = [float('inf')] * n
    if len(caps) != n:
        raise ValueError("caps 长度与参与方数不一致")

    eps = [0.0] * n
    capped = [False] * n
    active = list(range(n))
    remaining = float(eps_total)
    note = ""

    cap_sum = sum(caps)
    if cap_sum < eps_total - 1e-12:
        # 总预算超过所有上限之和：全部封顶，剩余预算不可用（隐私底线优先）
        for i in range(n):
            eps[i] = caps[i]
            capped[i] = True
        return Allocation(eps, capped, 1, cap_sum, distortion(u, delta, eps), True,
                          "ε_total 超过上限之和，全部封顶，剩余 %.4f 未分配" % (eps_total - cap_sum))

    it = 0
    while active and remaining > 1e-15 and it < max_iter:
        it += 1
        w = [(u[i] * delta[i] ** 2) ** (1.0 / 3.0) for i in active]
        sw = sum(w)
        if sw <= 0:
            share = remaining / len(active)
            for i in active:
                eps[i] = share
            break
        viol = []
        for k, i in enumerate(active):
            eps[i] = remaining * w[k] / sw          # 式20
            if eps[i] > caps[i] + 1e-15:
                viol.append(i)
        if not viol:
            break
        for i in viol:
            eps[i] = caps[i]
            capped[i] = True
            remaining -= caps[i]
            active.remove(i)
        if remaining < 0:
            remaining = 0.0

    used = sum(eps)
    return Allocation(eps, capped, it, used, distortion(u, delta, eps), True, note)


def kkt_residual(u: Sequence[float], delta: Sequence[float], eps: Sequence[float],
                 capped: Sequence[bool]) -> float:
    """式19 残差：未封顶变量的 4·u_i·Δ_i²/ε_i³ 应当相等（即 λ 一致）。

    返回最大相对偏差，用于运行期核验最优性。
    """
    vals = [4.0 * u[i] * delta[i] ** 2 / eps[i] ** 3
            for i in range(len(eps)) if not capped[i] and eps[i] > 0]
    if len(vals) < 2:
        return 0.0
    lo, hi = min(vals), max(vals)
    return (hi - lo) / hi if hi > 0 else 0.0


# --------------------------------------------------------------------------
# 式17：高级组合定理
# --------------------------------------------------------------------------
def advanced_composition(eps0: float, delta0: float, T: int,
                         delta_prime: float = 1e-6) -> tuple:
    """式17 / 定理9：返回 (ε_total, δ_total)。"""
    if T < 0:
        raise ValueError("T 须非负")
    if T == 0:
        return 0.0, 0.0
    if not (0 < delta_prime < 1):
        raise ValueError("δ′ 应在 (0,1)")
    e = math.sqrt(2.0 * T * math.log(1.0 / delta_prime)) * eps0 \
        + T * eps0 * (math.exp(eps0) - 1.0)
    d = T * delta0 + delta_prime
    return e, d


def basic_composition(eps0: float, delta0: float, T: int) -> tuple:
    """基本组合 T·ε₀ 作为对照（定理9 中的比较项）。"""
    return T * eps0, T * delta0


def composition_bound(eps0: float, delta0: float, T: int,
                      delta_prime: float = 1e-6) -> tuple:
    """准入用的隐私损耗上界：取高级组合与基本组合中较紧者。

    式17 的高级组合仅在 ε₀ 较小时优于线性损耗；当 ε₀ 偏大时其
    T·ε₀·(e^ε₀ − 1) 项占主导，反而比基本组合 T·ε₀ 更松。二者都是
    对同一累计损耗的合法上界，故取较小者仍是合法上界，且更紧。

    返回 (ε_total, δ_total, 采用的界名)。
    """
    ea, da = advanced_composition(eps0, delta0, T, delta_prime)
    eb, db = basic_composition(eps0, delta0, T)
    if eb <= ea:
        return eb, db, "基本组合"
    return ea, da, "高级组合(式17)"


def max_rounds(eps_budget: float, eps0: float, delta0: float,
               delta_prime: float = 1e-6, cap: int = 100000) -> int:
    """在给定总预算下可训练的最大轮数（按较紧的组合界做准入控制）。"""
    T = 0
    while T + 1 <= cap:
        e, _, _ = composition_bound(eps0, delta0, T + 1, delta_prime)
        if e > eps_budget:
            break
        T += 1
    return T


@dataclass
class BudgetAccountant:
    """中心云预算会计器：按较紧的组合界对后续轮次进行准入控制。"""
    eps_budget: float
    eps0: float
    delta0: float = 1e-6
    delta_prime: float = 1e-6
    rounds: int = 0
    history: List[tuple] = field(default_factory=list)
    bound_name: str = ""

    def spent(self) -> tuple:
        e, d, name = composition_bound(self.eps0, self.delta0, self.rounds,
                                       self.delta_prime)
        self.bound_name = name
        return e, d

    def can_admit(self) -> bool:
        e, _, _ = composition_bound(self.eps0, self.delta0, self.rounds + 1,
                                    self.delta_prime)
        return e <= self.eps_budget

    def admit(self) -> bool:
        if not self.can_admit():
            return False
        self.rounds += 1
        e, d = self.spent()
        self.history.append((self.rounds, e, d))
        return True


# --------------------------------------------------------------------------
# 式21：轮间预算联动
# --------------------------------------------------------------------------
def update_budget(eps_prev: float, phi_i: float, phi_bar: float, S_i: int,
                  cap_i: float, alpha: float = 0.5,
                  eps_min: float = 0.01) -> float:
    """式21：按贡献度与敏感度联动更新单车预算，并夹在 [ε_min, ε̄(S_i)]。"""
    if phi_bar <= 0:
        ratio = 1.0
    else:
        ratio = phi_i / phi_bar
    raw = eps_prev * ratio * math.exp(-alpha * S_i)
    return min(cap_i, max(eps_min, raw))
