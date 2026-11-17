# -*- coding: utf-8 -*-
"""门限重构式噪声追责审计（定理7）。

审计链条（每一步都不依赖被审计车辆的自我声明）：
  1. 车辆向委员会开示原始梯度 m_t；委员会核验 SM3(m_t) 是否等于链上摘要。
     该摘要由式2 绑定并经信标逐层锚定，故车辆无法就 m_t 说谎（归约至定理1）。
  2. 不少于 t 名委员经拉格朗日插值重构 k_v（Shamir 门限，定理7-i）。
  3. 由式8、式12 重算 seed_t、r_t，核验承诺 C_t。
  4. 由式10 / 式11 重算噪声 n_t。
  5. 比对 上传值 与 clip(m_t) + n_t：残差非零即为违规，并区分
     "少加噪 / 虚标 ε" 与 "以加噪为名的定向扰动"。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .sm3 import sm3
from .codec import unpack_vec
from .dp import (derive_seed, derive_blind, commitment, gaussian_noise,
                 laplace_noise, clip, l2_norm)
from .layered import sigma_of_eps


@dataclass
class AuditReport:
    vid: str
    ctr: int
    committee: List[str]
    disclosure_ok: bool        # SM3(m_t) 与链上摘要一致
    commit_ok: bool            # 承诺 C_t 开示一致
    noise_match: bool          # 噪声逐维一致
    residual: float
    claimed_eps: float
    verdict: str
    detail: str = ""

    @property
    def compliant(self) -> bool:
        return self.disclosure_ok and self.commit_ok and self.noise_match


def audit_record(k_v: bytes, rec, disclosed_m: bytes,
                 committee_names: Sequence[str] = (),
                 rel_tol: float = 1e-9,
                 public_params: Optional[dict] = None) -> AuditReport:
    """对单条链记录执行完整审计（步骤 1、3、4、5；k_v 由外层门限重构提供）。

    public_params 为该轮的公开系统参数（由 MEC 发布并随信标锚定），至少包含
    rho_v、sigma_g、inv_sum、delta2。给定该参数后，审计方将**仅**依据
    行为链中已绑定的 ε_i 复算该车应施加的噪声强度 σ_{v,i}，不再采用记录
    meta 中由车辆自行填写的 σ —— 否则"虚标 ε"的车辆可同时篡改自报 σ 而
    使残差归零，定理7 的确定性检出将被架空。
    未提供 public_params 时退回读取 meta，仅用于离线单条演示。
    """
    names = list(committee_names)
    eps_claim = rec.beta.epsilon

    # 步骤 1：链绑定开示核验
    disclosure_ok = (sm3(disclosed_m) == rec.msg_digest)
    if not disclosure_ok:
        return AuditReport(rec.vehicle_id, rec.ctr, names, False, False, False,
                           float('nan'), eps_claim, "开示不符",
                           "开示的 m_t 与链上摘要不一致，已归约至定理1 的抗第二原像性")

    meta = rec.meta or {}
    pp = public_params or {}
    g_raw = unpack_vec(disclosed_m)
    delta2 = pp.get('delta2', meta.get('delta2', 1.0))     # 系统参数，非车辆自选
    g_clip = clip(g_raw, delta2)                            # 式13，由审计方独立复算
    dim = len(g_clip)

    # 步骤 3：承诺开示（式8、式12）
    seed = derive_seed(k_v, rec.h_d, rec.ctr)
    r = derive_blind(k_v, rec.h_d)
    commit_ok = (commitment(seed, r) == rec.beta.commit)

    # 步骤 4：噪声重算（式10 / 式11）。σ 由链上 ε_i 与公开轮参数导出。
    mech = pp.get('mechanism', meta.get('mechanism', 'gauss'))
    if pp:
        sigma = sigma_of_eps(eps_claim, pp['inv_sum'], pp['rho_v'], pp['sigma_g'])
        sigma_src = "由链上 ε=%.4f 与公开轮参数复算" % eps_claim
    else:
        sigma = meta.get('sigma', 0.0)
        sigma_src = "取自记录元数据（离线演示模式）"
    if mech == 'gauss':
        n = gaussian_noise(seed, dim, sigma)
    else:
        n = laplace_noise(seed, dim, pp.get('delta1', meta.get('delta1', 1.0)), eps_claim)

    # 步骤 5：残差比对
    y = list(rec.payload or [])
    if len(y) != dim:
        return AuditReport(rec.vehicle_id, rec.ctr, names, True, commit_ok, False,
                           float('nan'), eps_claim, "维度不符", "上传维度与开示梯度维度不一致")
    resid = l2_norm([y[j] - (g_clip[j] + n[j]) for j in range(dim)])
    scale = max(1.0, l2_norm(y))
    noise_match = (resid / scale) <= rel_tol

    if commit_ok and noise_match:
        verdict = "合规"
        detail = ("承诺开示一致，噪声与重算结果逐维一致（残差 %.3g；σ %s）"
                  % (resid, sigma_src))
    elif not commit_ok:
        verdict = "承诺不符"
        detail = "C_t 与由 k_v 重算的 SM3(seed_t ∥ r_t) 不一致"
    else:
        added = [y[j] - g_clip[j] for j in range(dim)]
        na, nn = l2_norm(added), l2_norm(n)
        ratio = na / max(1e-12, nn)
        if ratio < 0.8:
            verdict = "违规：少加噪 / 虚标 ε"
            detail = ("实加噪声范数为规范噪声的 %.1f%%，等效 ε 被放大约 %.2f 倍（σ %s）"
                      % (100 * ratio, (1.0 / max(ratio, 1e-9)), sigma_src))
        else:
            verdict = "违规：以加噪为名的定向扰动"
            detail = ("噪声范数相当（%.1f%%）但方向与重算结果不一致，残差 %.4g"
                      % (100 * ratio, resid))
    return AuditReport(rec.vehicle_id, rec.ctr, names, True, commit_ok,
                       noise_match, resid, eps_claim, verdict, detail)


def run_threshold_audit(committee, member_idx: Sequence[int], rec,
                        disclosed_m: bytes, rel_tol: float = 1e-9,
                        public_params: Optional[dict] = None) -> AuditReport:
    """步骤 2 + 完整审计。参与成员不足门限时抛 PermissionError（定理7-ii）。"""
    k_v = committee.reconstruct(member_idx)
    names = [committee.members[i] for i in sorted(set(member_idx))[:committee.t]]
    return audit_record(k_v, rec, disclosed_m, names, rel_tol, public_params)
