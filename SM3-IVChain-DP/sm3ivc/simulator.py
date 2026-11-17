# -*- coding: utf-8 -*-
"""车—路—边—云端到端仿真引擎。

单轮闭环：
  信标推进(式1) → 预算水填充(式20) → 车端敏感度分级(式4-6) → 策略选择(式7)
  → 裁剪(式13) → 链态派生噪声(式8-11) → 承诺(式12) → 双链上链(式2,3)
  → RSU 验证(定理1,2) + 四通道检测(式22) + 信誉加权聚合(式23) + 层级加噪(式15)
  → MEC 加噪与锚定 → 中心云全局聚合 + 组合会计(式17)
  → 对标记车辆触发门限追责审计(定理7)

协同学习任务采用线性回归：y = ⟨w*, x⟩ + ξ，各车执行一步梯度并上传。
隐私核算按定理8 对"求和"模型进行；模型更新使用的信誉加权平均是同一批
含噪上传的后处理，由差分隐私的后处理不变性，隐私保证不受影响。
"""

from __future__ import annotations

import math
import os
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .sm3 import sm3
from .codec import pack_vec
from .chain import (BeaconChain, MEC, InterwovenChain, ChainVerifier, Behavior)
from .sensitivity import sensitivity_score, eps_cap, LEVEL_NAME
from .policy import Context, select, POLICY_LIB
from .dp import (ChainCoupledDP, clip, l2_norm, derive_seed, gaussian_noise,
                 gauss_from_u, prf_u, sigma_gauss)
from .layered import (split_variance, eps_rsu_view, eps_rsu_closed_form,
                      vehicle_sigmas, sigma_of_eps, theorem8_holds_hetero)
from .budget import (water_filling, advanced_composition, BudgetAccountant,
                     update_budget, kkt_residual)
from .detect import (Detector, Reputation, l2, cosine, robust_threshold,
                     suggest_theta_cos)
from .shamir import AuditCommittee
from .audit import run_threshold_audit

DATA_TYPES = ["天气", "路况", "车速", "车辆状态", "聚合位置",
              "精确GPS轨迹", "驾驶行为", "受控区域采集数据"]

ATTACKS = {
    "none": "诚实车辆",
    "tamper": "篡改链上记录",
    "replay": "重放历史记录",
    "undernoise": "少加噪声(虚标ε)",
    "disguise": "以加噪为名的定向投毒",
    "norm": "超大范数梯度投毒",
}


# --------------------------------------------------------------------------
@dataclass
class SimConfig:
    n_vehicles: int = 20
    n_rsu: int = 2
    dim: int = 10
    rounds: int = 30
    local_samples: int = 40
    lr: float = 0.25
    delta2: float = 1.0            # 裁剪阈值 Δ₂
    eps_g: float = 2.0             # 全局单轮隐私预算 ε_g
    delta: float = 1e-5            # (ε,δ)-DP 中的 δ
    rho_v: float = 0.5
    rho_r: float = 0.3
    rho_m: float = 0.2
    eps0: float = 2.0              # 式5 端点
    eps3: float = 0.1
    eps_total_round: float = 10.0  # 单轮可分配给全体车辆的预算总量（式18）
    eps_budget: float = 100.0      # 全程隐私预算（按较紧的组合界准入）
    kappa: float = 3.0             # 式22 鲁棒系数
    theta_cos: float = 0.0         # 余弦阈值；0 表示按维度自动标定(见 suggest_theta_cos)
    cos_alpha: float = 0.05        # 自动标定时容许的误报率 α
    theta_rep: float = 0.8         # 式23 记忆系数
    alpha: float = 0.5             # 式21 敏感度调节系数
    audit_rate: float = 0.20       # 通道(d) 抽检审计比例（高敏感数据优先）
    shamir_t: int = 3
    shamir_n: int = 5
    seed: int = 20260826
    attack_plan: Dict[int, str] = field(default_factory=dict)  # 车辆下标 -> 攻击类型


@dataclass
class Vehicle:
    vid: str
    idx: int
    rsu: int
    ctx: Context
    chain: InterwovenChain
    k_v: bytes
    committee: AuditCommittee
    X: List[List[float]]
    y: List[float]
    attack: str = "none"
    eps_cur: float = 1.0
    phi: float = 1.0               # 贡献度
    last_record: object = None
    last_m: bytes = b''


# --------------------------------------------------------------------------
class Simulator:
    def __init__(self, cfg: SimConfig, log=None):
        self.cfg = cfg
        self.log = log or (lambda s: None)
        self.rng = random.Random(cfg.seed)
        self.reset()

    # ---------------------------------------------------------------- setup
    def reset(self):
        cfg = self.cfg
        self.rng = random.Random(cfg.seed)
        d = cfg.dim
        self.w_star = [self.rng.gauss(0, 1) for _ in range(d)]
        self.w = [0.0] * d
        self.round = 0

        self.mec = MEC()
        self.rsus = [BeaconChain("RSU-%d" % (i + 1)) for i in range(cfg.n_rsu)]
        self.verifiers = [ChainVerifier(bc) for bc in self.rsus]

        self.vehicles: List[Vehicle] = []
        for i in range(cfg.n_vehicles):
            k_v = os.urandom(32)
            ch = InterwovenChain("V-%02d" % (i + 1), reg_ts=1700000000 + i)
            ctx = Context(C=round(self.rng.uniform(0.35, 0.98), 2),
                          B=round(self.rng.uniform(0.30, 0.95), 2),
                          N=round(self.rng.uniform(0.35, 0.98), 2))
            X = [[self.rng.gauss(0, 1) for _ in range(d)]
                 for _ in range(cfg.local_samples)]
            y = [sum(a * b for a, b in zip(x, self.w_star)) + self.rng.gauss(0, 0.1)
                 for x in X]
            v = Vehicle("V-%02d" % (i + 1), i, i % cfg.n_rsu, ctx, ch, k_v,
                        AuditCommittee(k_v, cfg.shamir_t, cfg.shamir_n),
                        X, y, cfg.attack_plan.get(i, "none"),
                        eps_cap(1, cfg.eps0, cfg.eps3))
            self.vehicles.append(v)
            self.verifiers[v.rsu].register(v.vid, ch.h_d, ch.h_b)

        th_cos = (cfg.theta_cos if cfg.theta_cos else
                  suggest_theta_cos(cfg.dim, cfg.cos_alpha))
        self.theta_cos_used = th_cos
        self.detector = Detector(cfg.kappa, th_cos)
        self.rep = Reputation(cfg.theta_rep)
        self.accountant = BudgetAccountant(cfg.eps_budget, cfg.eps_g, cfg.delta)
        self.split = split_variance(cfg.delta2, cfg.eps_g, cfg.delta,
                                    max(1, cfg.n_vehicles // max(1, cfg.n_rsu)),
                                    cfg.n_rsu, cfg.rho_v, cfg.rho_r, cfg.rho_m)
        self.history: List[dict] = []
        self.audit_reports: List = []
        self.all_records: List = []

    # ------------------------------------------------------------- gradient
    def local_gradient(self, v: Vehicle) -> List[float]:
        d = self.cfg.dim
        g = [0.0] * d
        n = len(v.X)
        for x, yy in zip(v.X, v.y):
            e = sum(a * b for a, b in zip(x, self.w)) - yy
            for j in range(d):
                g[j] += e * x[j]
        return [gg / n for gg in g]

    def model_error(self) -> float:
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(self.w, self.w_star)))

    # ----------------------------------------------------------------- step
    def step(self) -> dict:
        cfg = self.cfg
        if not self.accountant.can_admit():
            self.log("【预算会计】累计损耗已达总预算上限（准入界：%s），停止参训。"
                     % (self.accountant.bound_name or "组合界"))
            return {}
        self.accountant.admit()
        self.round += 1
        r = self.round

        # 1) 各 RSU 推进纪元信标并向 MEC 锚定（式1）
        beacons = []
        for i, bc in enumerate(self.rsus):
            b = bc.next_epoch()
            bc.anchor_to_mec(self.mec)
            beacons.append(b)

        # 2) 车端：敏感度 → 上限 → 预算水填充（式4-6、式18-20）
        sens, caps, us, deltas = [], [], [], []
        for v in self.vehicles:
            dt = DATA_TYPES[self.rng.randrange(len(DATA_TYPES))]
            s_raw, S = sensitivity_score(
                dt, geofence_hit=(self.rng.random() < 0.15),
                personal_id=(self.rng.random() < 0.15),
                special_period=(self.rng.random() < 0.10))
            cap = eps_cap(S, cfg.eps0, cfg.eps3)
            sens.append((dt, s_raw, S))
            caps.append(cap)
            us.append(max(0.05, self.rep.get(v.vid) * v.phi))
            deltas.append(cfg.delta2)
        alloc = water_filling(us, deltas, cfg.eps_total_round, caps)
        kkt = kkt_residual(us, deltas, alloc.eps, alloc.capped)

        # 车辆层总方差 ρ_v·σ_g² 按各车分配到的 ε_i 异构分摊，使行为链中
        # 声明的 ε_i 与该车实际噪声强度严格对应（定理8 仍以等式成立）。
        sig_v = vehicle_sigmas(self.split, alloc.eps)
        inv_sum = sum(1.0 / (e * e) for e in alloc.eps)
        # 本轮公开参数：由 MEC 发布并随信标锚定，审计方据此复算 σ，
        # 不采信车辆自报的任何数值。
        pub = dict(rho_v=cfg.rho_v, sigma_g=self.split.sigma_g,
                   inv_sum=inv_sum, delta2=cfg.delta2, mechanism="gauss")
        self.round_public = pub
        self.round_sigmas = dict()

        # 3) 车端本地训练 + 链态耦合加噪 + 上链
        uploads, chain_results, meta_all = [], {}, {}
        n_degraded = n_delayed = 0
        for k, v in enumerate(self.vehicles):
            dt, s_raw, S = sens[k]
            v.eps_cur = alloc.eps[k]
            dec = select(S, v.ctx)
            policy = dec.policy.name if dec.policy else "延迟上传"
            if dec.policy is None:
                # 强度底线仍不可行：延迟上传或仅上传承诺值（设计文档 3.3 节）
                n_delayed += 1
                chain_results[v.vid] = (True, [])
                continue
            if dec.degraded:
                # 已由目标强度退至底线强度，预算按 ε̄(S) 封顶
                n_degraded += 1
                v.eps_cur = min(v.eps_cur, caps[k])

            g = self.local_gradient(v)
            g_clip = clip(g, cfg.delta2)
            m_bytes = pack_vec(g)                       # 链上消息 m_t
            bc = self.rsus[v.rsu]
            ctr, h_d = v.chain.begin_record(m_bytes, ts=1700000000 + r, beacon=bc.current())

            sigma_v = sig_v[k]
            self.round_sigmas[v.vid] = sigma_v
            seed = derive_seed(v.k_v, h_d, ctr)
            noise = gaussian_noise(seed, cfg.dim, sigma_v)

            # ---- 攻击注入 ----
            atk = v.attack
            if atk == "undernoise":
                noise = [x / 6.0 for x in noise]        # 少加噪，虚标 ε
            elif atk == "disguise":
                nn = l2_norm(noise)
                gn = max(1e-12, l2_norm(g_clip))
                noise = [-1.0 * x / gn * nn for x in g_clip]   # 同范数定向扰动
            payload = [a + b for a, b in zip(g_clip, noise)]
            if atk == "norm":
                payload = [x * 12.0 for x in payload]

            from .dp import derive_blind, commitment
            commit = commitment(seed, derive_blind(v.k_v, h_d))
            beta = Behavior(policy=policy, epsilon=v.eps_cur, commit=commit,
                            proof_id=sm3(pack_vec(payload))[:8])
            rec = v.chain.commit_record(beta, payload=payload, meta=dict(
                mechanism="gauss", sigma=sigma_v, delta2=cfg.delta2,
                S=S, data_type=dt, attack=atk, degraded=dec.degraded))

            if atk == "tamper":
                rec.msg_digest = sm3(pack_vec([x * 1.5 for x in g]))   # 篡改链上摘要
            if atk == "replay" and v.last_record is not None:
                old = v.last_record
                rec.ctr, rec.epoch, rec.beacon = old.ctr, old.epoch, old.beacon

            v.last_record, v.last_m = rec, m_bytes
            self.all_records.append((v, rec, m_bytes))
            ok, errs = self.verifiers[v.rsu].verify(rec)
            chain_results[v.vid] = (ok, errs)
            uploads.append(dict(vid=v.vid, vec=payload, rec=rec, vehicle=v))
            meta_all[v.vid] = dict(S=S, policy=policy, eps=v.eps_cur, dt=dt)

        # 4) RSU 四通道检测 + 分级处置（式22、式23）
        # 尺度因子 s_i = √(Δ₂² + d·σ_{v,i}²)：由链上 ε_i 与公开轮参数导出
        scales = {vid: math.sqrt(cfg.delta2 ** 2 + cfg.dim * sg * sg)
                  for vid, sg in self.round_sigmas.items()}
        results, Tg = self.detector.screen(uploads, chain_results, scales)
        accepted, flagged = [], []
        for res, up in zip(results, uploads):
            v = up['vehicle']
            S_up = meta_all.get(res.vid, {}).get('S', 0)
            # 通道(d)：链/统计告警触发审计；此外对高敏感数据按 audit_rate 抽检。
            # 抽检是"少加噪"与"伪装投毒"能被检出的关键——这两类攻击
            # 在通道(a)(b)(c) 上均无异常表现（见设计文档 6.2(d) 与定理6、7）。
            spot = (self.rng.random() < cfg.audit_rate * (2.0 if S_up >= 2 else 1.0))
            if res.flagged or spot:
                try:
                    rep = run_threshold_audit(v.committee, list(range(cfg.shamir_t)),
                                              up['rec'], v.last_m,
                                              public_params=pub)
                    if not rep.compliant:
                        res.audit_flag, res.audit_reason = True, rep.verdict
                    self.audit_reports.append((r, rep))
                except PermissionError as e:
                    self.audit_reports.append((r, str(e)))
            self.detector.grade(res)
            self.rep.update(v.vid, not res.flagged)
            # 历史序列只要求链校验与审计通过即可更新，避免统计通道的
            # 偶发误报导致历史陈旧、进而引发误报级联。
            if res.chain_ok and not res.audit_flag:
                self.detector.push_history(v.vid, up['vec'])
            if res.flagged:
                flagged.append(res)
            else:
                accepted.append(up)

        # 5) 分层聚合：RSU 加噪 → MEC 加噪 → 云端更新（式15、定理8）
        d = cfg.dim
        agg = [0.0] * d
        wsum = 0.0
        for up in accepted:
            wv = self.rep.get(up['vid'])
            wsum += wv
            for j in range(d):
                agg[j] += wv * up['vec'][j]
        if wsum > 0:
            agg = [x / wsum for x in agg]

        rsu_noise = [self.rng.gauss(0, self.split.sigma_r) / max(1, len(accepted))
                     for _ in range(d)]
        mec_noise = [self.rng.gauss(0, self.split.sigma_m) / max(1, len(accepted))
                     for _ in range(d)]
        ghat = [agg[j] + rsu_noise[j] + mec_noise[j] for j in range(d)]

        self.w = [self.w[j] - cfg.lr * ghat[j] for j in range(d)]

        # 6) 轮间预算联动（式21）
        phis = [max(0.05, self.rep.get(v.vid)) for v in self.vehicles]
        phibar = sum(phis) / len(phis)
        for k, v in enumerate(self.vehicles):
            v.phi = phis[k]
            v.eps_cur = update_budget(v.eps_cur, v.phi, phibar, sens[k][2],
                                      caps[k], cfg.alpha)

        e_tot, d_tot = self.accountant.spent()
        rec_row = dict(
            round=r, err=self.model_error(), accepted=len(accepted),
            flagged=len(flagged), Tg=Tg, eps_total=e_tot, delta_total=d_tot,
            degraded=n_degraded, delayed=n_delayed,
            bound=self.accountant.bound_name,
            alloc=list(alloc.eps), caps=list(caps), kkt=kkt,
            sigma_v=list(sig_v), sigma_r=self.split.sigma_r,
            sigma_m=self.split.sigma_m,
            th8=theorem8_holds_hetero(sig_v, self.split),
            var_lhs=(sum(x * x for x in sig_v)
                     + self.split.R * self.split.sigma_r ** 2
                     + self.split.sigma_m ** 2),
            detail=[(res.vid, meta_all.get(res.vid, {}).get('S'),
                     meta_all.get(res.vid, {}).get('policy'),
                     res.chain_ok, res.norm_flag, res.cos_flag,
                     res.audit_flag, res.action) for res in results])
        self.history.append(rec_row)
        return rec_row

    def run(self, rounds: Optional[int] = None) -> List[dict]:
        for _ in range(rounds or self.cfg.rounds):
            row = self.step()
            if not row:
                break
        return self.history

    # ------------------------------------------------------------- metrics
    def detection_stats(self) -> dict:
        """按车辆统计检出情况：恶意车辆是否被标记，诚实车辆是否被误报。"""
        tp = fp = fn = tn = 0
        for row in self.history:
            for (vid, S, pol, chain_ok, nf, cf, af, action) in row['detail']:
                v = next(x for x in self.vehicles if x.vid == vid)
                malicious = (v.attack != "none")
                flagged = (not chain_ok) or nf or cf or af
                if malicious and flagged:
                    tp += 1
                elif malicious and not flagged:
                    fn += 1
                elif (not malicious) and flagged:
                    fp += 1
                else:
                    tn += 1
        tot = tp + fp + fn + tn
        return dict(TP=tp, FP=fp, FN=fn, TN=tn,
                    recall=(tp / (tp + fn) if tp + fn else float('nan')),
                    fpr=(fp / (fp + tn) if fp + tn else float('nan')),
                    total=tot)

    def channel_attribution(self) -> List[tuple]:
        """按攻击类型统计各通道的检出次数，用于论证通道(d) 的不可替代性。

        返回 [(攻击类型, 出现次数, a链, b范数, c余弦, d审计, 综合检出)]。
        """
        agg: Dict[str, List[int]] = {}
        for row in self.history:
            for (vid, S, pol, chain_ok, nf, cf, af, action) in row['detail']:
                v = next(x for x in self.vehicles if x.vid == vid)
                a = agg.setdefault(v.attack, [0, 0, 0, 0, 0, 0])
                a[0] += 1
                a[1] += 0 if chain_ok else 1
                a[2] += 1 if nf else 0
                a[3] += 1 if cf else 0
                a[4] += 1 if af else 0
                a[5] += 1 if ((not chain_ok) or nf or cf or af) else 0
        out = []
        for k in ["none"] + [x for x in ATTACKS if x != "none"]:
            if k in agg:
                a = agg[k]
                out.append((k, ATTACKS[k], a[0], a[1], a[2], a[3], a[4], a[5]))
        return out

    def audit_stats(self) -> dict:
        """审计通道的条件检出率：一旦对违规车辆执行审计，按定理7 检出概率应为 1。"""
        n_audit = n_bad = n_caught = 0
        bad_vids = {v.vid for v in self.vehicles if v.attack in
                    ("undernoise", "disguise", "tamper")}
        for _, rep in self.audit_reports:
            if isinstance(rep, str):
                continue
            n_audit += 1
            if rep.vid in bad_vids:
                n_bad += 1
                if not rep.compliant:
                    n_caught += 1
        return dict(audits=n_audit, on_malicious=n_bad, caught=n_caught,
                    conditional_recall=(n_caught / n_bad if n_bad else float('nan')))

    def theorem8_report(self) -> dict:
        """定理8 运行期核验：Σσ_{v,i}² + R·σ_r² + σ_m² 是否等于 σ_g²。

        车辆层采用按 ε_i 的异构分摊，等 ε 时退化为式15 的均匀分摊。
        """
        sp = self.split
        last = self.history[-1] if self.history else None
        if last:
            sv = last['sigma_v']
            lhs, holds = last['var_lhs'], last['th8']
            sv_min, sv_max = min(sv), max(sv)
            sv_rep = sum(sv) / len(sv)
        else:
            lhs, holds = sp.var_sum, sp.theorem8_holds()
            sv_min = sv_max = sv_rep = sp.sigma_v
        return dict(sigma_g=sp.sigma_g, sigma_v=sv_rep, sigma_v_min=sv_min,
                    sigma_v_max=sv_max, sigma_r=sp.sigma_r, sigma_m=sp.sigma_m,
                    lhs=lhs, rhs=sp.sigma_g ** 2, holds=holds,
                    eps_rsu=eps_rsu_view(sp, self.cfg.delta2, self.cfg.delta),
                    eps_rsu_cf=eps_rsu_closed_form(self.cfg.eps_g, sp.K, sp.rho_v))
