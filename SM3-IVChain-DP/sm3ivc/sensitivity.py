# -*- coding: utf-8 -*-
"""实施例二：敏感度量化与隐私预算上限映射。

    式4  S_raw = w_T·φ_T + w_L·φ_L + w_P·φ_P + w_C·φ_C，  S = min(⌊S_raw⌋, 3)
    式5  ε̄(S) = ε₀·e^(−λS)
    式6  λ = (1/3)·ln(ε₀/ε̄₃)
    性质1  ε̄(S+1)/ε̄(S) = e^(−λ) 为与 S 无关的常数（等比收紧）
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# φ_T：数据类型基础敏感分（说明书 2.1 节）
PHI_T_TABLE = {
    "天气": 0, "路况": 0, "公开交通流统计": 0,
    "车速": 1, "车辆状态": 1, "聚合位置": 1,
    "精确GPS轨迹": 2, "驾驶行为": 2, "人脸特征": 2, "声纹特征": 2,
    "受控区域采集数据": 3,
}

LEVEL_NAME = {0: "S0 公开级", 1: "S1 一般敏感级", 2: "S2 高敏感级", 3: "S3 受控级"}


@dataclass
class SensitivityWeights:
    w_T: float = 1.0
    w_L: float = 1.0
    w_P: float = 1.0
    w_C: float = 1.0


def phi_T(data_type: str) -> int:
    """数据类型基础敏感分。未知类型按一般敏感（1）保守取值。"""
    return PHI_T_TABLE.get(data_type, 1)


def sensitivity_score(data_type: str, geofence_hit: bool = False,
                      personal_id: bool = False, special_period: bool = False,
                      w: SensitivityWeights = SensitivityWeights()) -> tuple:
    """式4：返回 (S_raw, S)。"""
    s_raw = (w.w_T * phi_T(data_type)
             + w.w_L * (1 if geofence_hit else 0)
             + w.w_P * (1 if personal_id else 0)
             + w.w_C * (1 if special_period else 0))
    s = min(int(math.floor(s_raw)), 3)
    return s_raw, s


def lam(eps0: float = 2.0, eps3: float = 0.1) -> float:
    """式6：由两端点参数唯一确定衰减系数 λ。"""
    if eps0 <= 0 or eps3 <= 0:
        raise ValueError("ε₀ 与 ε̄₃ 必须为正")
    if eps3 > eps0:
        raise ValueError("ε̄₃ 应不大于 ε₀（预算随敏感度递减）")
    return (1.0 / 3.0) * math.log(eps0 / eps3)


def eps_cap(S: int, eps0: float = 2.0, eps3: float = 0.1) -> float:
    """式5：敏感度等级 S 对应的隐私预算上限 ε̄(S)。"""
    if not 0 <= S <= 3:
        raise ValueError("敏感度等级 S 应在 0..3")
    return eps0 * math.exp(-lam(eps0, eps3) * S)


def cap_table(eps0: float = 2.0, eps3: float = 0.1) -> list:
    """返回 [(S, 等级名, ε̄(S))]，供 UI 展示。"""
    return [(S, LEVEL_NAME[S], eps_cap(S, eps0, eps3)) for S in range(4)]


def ratio_constant(eps0: float = 2.0, eps3: float = 0.1) -> float:
    """性质1：相邻等级的固定收紧倍率 e^(−λ)。"""
    return math.exp(-lam(eps0, eps3))


def verify_property1(eps0: float = 2.0, eps3: float = 0.1, tol: float = 1e-12) -> bool:
    """运行期核验性质1：相邻等级比值为与 S 无关的常数。"""
    r = ratio_constant(eps0, eps3)
    for S in range(3):
        if abs(eps_cap(S + 1, eps0, eps3) / eps_cap(S, eps0, eps3) - r) > tol:
            return False
    # 端点一致性：ε̄(3) 应等于设定的 ε̄₃
    return abs(eps_cap(3, eps0, eps3) - eps3) < 1e-9
