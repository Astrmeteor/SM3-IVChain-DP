# -*- coding: utf-8 -*-
"""资源约束下的最小代价隐私策略选择。

    式7   min J(a) = w₁·γ_cp(a)/C + w₂·γ_cm(a)/N + w₃·γ_e(a)/B
          s.t. P(a) ≥ P_req(S)；γ_cp ≤ θ_c·C，γ_e ≤ θ_b·B，γ_cm ≤ θ_n·N
    命题1  开销与强度同向严格单调时，最优解为最低可行等级策略
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Policy:
    name: str
    level: int          # 保护强度序数 P(a)
    tech: str
    scene: str
    gamma_cp: float     # 计算开销系数
    gamma_cm: float     # 通信开销系数
    gamma_e: float      # 能耗开销系数
    overhead: str       # 配置表中的总开销系数标签


# 分级策略库（分级策略表）。三类开销系数随等级严格单调递增，
# 与总开销系数 0.1x / 0.3x / 0.7x / 1.2x 一致。
POLICY_LIB: Dict[str, Policy] = {
    "L1": Policy("L1", 1, "SM3交织双链＋有界随机扰动", "交通流量统计",
                 0.10, 0.05, 0.08, "0.1x"),
    "L2": Policy("L2", 2, "SM3交织双链＋自适应差分隐私", "驾驶习惯分析",
                 0.30, 0.15, 0.25, "0.3x"),
    "L3": Policy("L3", 3, "SM3交织双链＋门限同态加密（叠加DP）", "个人精确导航数据",
                 0.70, 0.55, 0.65, "0.7x"),
    "L4": Policy("L4", 4, "SM3交织双链＋安全多方计算（叠加DP）", "受控区域车辆数据",
                 1.20, 1.00, 1.10, "1.2x"),
}
ORDER = ["L1", "L2", "L3", "L4"]


@dataclass
class Context:
    """车端归一化上下文：计算能力 C、剩余电量 B、网络质量 N ∈ (0,1]。"""
    C: float = 0.8
    B: float = 0.7
    N: float = 0.8


@dataclass
class CostWeights:
    w1: float = 1.0
    w2: float = 1.0
    w3: float = 1.0


@dataclass
class Thresholds:
    """资源占用率阈值 θ_c、θ_b、θ_n（式7 第二组约束）。

    标定依据：策略库中的开销系数（0.1x/0.3x/0.7x/1.2x）是相对基准的倍率，
    而 C、B、N 是归一化到 (0,1] 的资源量，二者量纲不同，不能直接比较——
    若取 θ=1，则 γ_cp(L4)=1.20 > C 恒成立，L4 将永远不可行，与设计文档 3.3 节
    "S=3 且 C>0.7、B>0.4、N>0.5 时选择 L4" 相矛盾。

    故以 3.3 节的最高等级节点条件反标定，使 L4 的资源可行边界恰为该组阈值：
        θ_c = γ_cp(L4)/0.7 = 1.20/0.7 ≈ 1.714
        θ_b = γ_e (L4)/0.4 = 1.10/0.4 = 2.750
        θ_n = γ_cm(L4)/0.5 = 1.00/0.5 = 2.000
    由此式7 的优化解法与 3.3 节的阈值化实现在 L4 边界上完全一致。
    """
    theta_c: float = 1.714   # 计算资源占用率阈值
    theta_b: float = 2.750   # 电量占用率阈值
    theta_n: float = 2.000   # 网络占用率阈值


def p_req(S: int) -> int:
    """敏感度 S 要求的目标保护强度 P_req(S) = S + 1（式7 第一组约束）。"""
    return S + 1


def p_floor(S: int) -> int:
    """强度底线：设计文档 3.3 节规定 S3 级以 L3 为不可降级底线，
    S2 级资源不足时可降至 L2 但预算封顶于 ε̄(2)。据此
        floor(3) = 3，floor(2) = 2，floor(1) = 2，floor(0) = 1。
    """
    if S >= 2:
        return S
    return S + 1


def cost(a: Policy, ctx: Context, w: CostWeights = CostWeights()) -> float:
    """式7 目标函数 J(a)。"""
    return (w.w1 * a.gamma_cp / ctx.C
            + w.w2 * a.gamma_cm / ctx.N
            + w.w3 * a.gamma_e / ctx.B)


def resource_feasible(a: Policy, ctx: Context, th: Thresholds = Thresholds()) -> bool:
    """式7 第二组约束：资源可行性。"""
    return (a.gamma_cp <= th.theta_c * ctx.C
            and a.gamma_e <= th.theta_b * ctx.B
            and a.gamma_cm <= th.theta_n * ctx.N)


def feasible_set(S: int, ctx: Context, th: Thresholds = Thresholds(),
                 level_min: Optional[int] = None) -> List[Policy]:
    """同时满足隐私强度要求与资源可行性的策略集合。"""
    need = p_req(S) if level_min is None else level_min
    return [POLICY_LIB[k] for k in ORDER
            if POLICY_LIB[k].level >= need and resource_feasible(POLICY_LIB[k], ctx, th)]


@dataclass
class Decision:
    policy: Optional[Policy]
    J: Optional[float]
    feasible: List[str]
    table: List[tuple]          # [(名称, 等级, J, 强度可行, 资源可行)]
    fallback: Optional[str]     # 无可行解时的处置
    prop1_consistent: bool      # 命题1 运行期核验结果
    degraded: bool = False      # 是否由目标强度降至底线强度
    cap_eps: bool = False       # 降级时是否需将预算封顶于 ε̄(S)


def select(S: int, ctx: Context, w: CostWeights = CostWeights(),
           th: Thresholds = Thresholds()) -> Decision:
    """按式7 求解，并在运行期核验命题1（argmin 应为最低可行等级）。

    两级求解：先在目标强度 P_req(S) 上求最小代价可行策略；若可行集为空，
    退至强度底线 p_floor(S)（S3 级底线为 L3，不可再降）并对预算封顶；
    若底线仍不可行，则延迟上传或仅上传承诺值。
    """
    need = p_req(S)
    table = []
    for k in ORDER:
        a = POLICY_LIB[k]
        table.append((a.name, a.level, cost(a, ctx, w),
                      a.level >= need, resource_feasible(a, ctx, th)))

    def _pick(level_min: int):
        F = feasible_set(S, ctx, th, level_min)
        if not F:
            return None, None, [], True
        best = min(F, key=lambda a: cost(a, ctx, w))
        lowest = min(F, key=lambda a: a.level)
        return best, cost(best, ctx, w), [a.name for a in F], best.name == lowest.name

    best, J, names, ok1 = _pick(need)
    if best is not None:
        return Decision(best, J, names, table, None, ok1, False, False)

    floor = p_floor(S)
    if floor < need:
        best, J, names, ok1 = _pick(floor)
        if best is not None:
            return Decision(best, J, names, table, None, ok1, True, True)

    fb = ("延迟上传或仅上传承诺值（S3 底线 L3 不可降级）" if S == 3
          else "延迟上传，等待资源恢复")
    return Decision(None, None, [], table, fb, True, False, False)


def select_by_rule(S: int, ctx: Context) -> str:
    """设计文档 3.3 节阈值化决策规则实例（与命题1 一致的查表实现）。"""
    if S == 3:
        return "L4" if (ctx.C > 0.7 and ctx.B > 0.4 and ctx.N > 0.5) else "L3"
    if S == 2:
        return "L3" if (ctx.C > 0.5 and ctx.N > 0.5) else "L2"
    if S == 1:
        return "L2"
    return "L1"
