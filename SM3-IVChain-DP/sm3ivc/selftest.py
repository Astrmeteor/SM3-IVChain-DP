# -*- coding: utf-8 -*-
"""自检套件：对密码学实现、公式与定理逐条做运行期验证。

每项返回 (名称, 是否通过, 说明)。UI 的"自检"页与 `python run.py --selftest`
均调用 run_all()。
"""

from __future__ import annotations

import math
import os
import random

from .sm3 import sm3_hex, sm3, hmac_sm3, _sm3_pure, BACKEND
from .codec import cat, pack_vec, unpack_vec
from .chain import BeaconChain, InterwovenChain, ChainVerifier, Behavior, MEC
from .sensitivity import (sensitivity_score, eps_cap, lam, verify_property1,
                          ratio_constant)
from .policy import Context, select, POLICY_LIB, cost, p_req, p_floor
from .dp import (derive_seed, derive_blind, commitment, prf_u, laplace_noise,
                 gaussian_noise, clip, l2_norm, sigma_gauss, laplace_from_u)
from .layered import (split_variance, eps_rsu_view, eps_rsu_closed_form,
                      vehicle_sigmas, sigma_of_eps, theorem8_holds_hetero,
                      vehicle_variance_shares)
from .budget import (water_filling, kkt_residual, distortion, second_derivative,
                     advanced_composition, basic_composition, update_budget,
                     composition_bound, BudgetAccountant, max_rounds)
from .shamir import AuditCommittee, split_secret, reconstruct
from .detect import (median, mad, robust_threshold, cosine, Reputation,
                     suggest_theta_cos, Detector)
from .audit import audit_record, run_threshold_audit


def _t(name, ok, msg=""):
    return (name, bool(ok), msg)


# --------------------------------------------------------------------------
def test_sm3_vectors():
    a = sm3_hex(b"abc")
    b = sm3_hex(b"abcd" * 16)
    ea = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    eb = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    return _t("SM3 国标测试向量 (GB/T 32905-2016)", a == ea and b == eb,
              "SM3(\"abc\") = %s…" % a[:16])


def test_sm3_backend_consistency():
    """双后端一致性：OpenSSL 的 C 实现与纯 Python 保底实现须逐字节相同。"""
    ok = True
    for n in (0, 1, 55, 56, 63, 64, 65, 119, 120, 200, 1000):
        if _sm3_pure(os.urandom(n) if n else b"") != sm3(b"") and n == 0:
            ok = False
            break
    for n in (1, 55, 56, 63, 64, 65, 119, 120, 200, 1000):
        d = os.urandom(n)
        if _sm3_pure(d) != sm3(d):
            ok = False
            break
    return _t("SM3 双后端一致性（当前：%s）" % BACKEND, ok,
              "纯 Python 与加速后端在 11 种消息长度上逐字节一致")


def test_hmac_determinism():
    k = os.urandom(32)
    m = b"chain-state"
    ok = hmac_sm3(k, m) == hmac_sm3(k, m) and hmac_sm3(k, m) != hmac_sm3(os.urandom(32), m)
    # RFC2104 长密钥折叠
    ok = ok and len(hmac_sm3(os.urandom(100), m)) == 32
    return _t("HMAC-SM3 确定性与长密钥折叠", ok, "同输入恒等、异密钥相异")


def test_codec_injective():
    ok = cat(b"ab", b"c") != cat(b"a", b"bc")
    return _t("拼接编码 ∥ 的单射性", ok, "消除 SM3 输入歧义，支撑定理1 归约")


def test_eq1_beacon():
    bc = BeaconChain("RSU-T")
    for _ in range(5):
        bc.next_epoch()
    ok = bc.verify_chain()
    b3 = bc.beacons[3].value
    ok = ok and bc.is_valid(3, b3) is (bc.epoch - bc.window <= 3 <= bc.epoch)
    ok = ok and not bc.is_valid(3, sm3(b"forged"))
    return _t("式1 信标链连续性与窗口校验", ok, "共 %d 个纪元逐一复算通过" % bc.epoch)


def test_eq2_eq3_interweave():
    """式2、式3：交织性 —— 改动行为链链头必然改变后续数据链链头。"""
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000, seed_v=b"\x01" * 16)
    ch.begin_record(b"m1", 1, bc.current())
    r1 = ch.commit_record(Behavior("L2", 1.0, sm3(b"c1")))
    h_d_true = InterwovenChain.data_head(r1.h_d, sm3(b"m2"), 2, 2, "V-T",
                                         bc.current().value, r1.h_b)
    h_d_alt = InterwovenChain.data_head(r1.h_d, sm3(b"m2"), 2, 2, "V-T",
                                        bc.current().value, sm3(b"other"))
    return _t("式2/式3 双链交织耦合", h_d_true != h_d_alt,
              "替换上一行为链链头即改变数据链链头，二链不可分割")


def test_theorem1_tamper():
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    mec = MEC(); bc.anchor_to_mec(mec)
    ch = InterwovenChain("V-T", 1700000000)
    v = ChainVerifier(bc); v.register("V-T", ch.h_d, ch.h_b)
    ch.begin_record(b"payload", 1, bc.current())
    rec = ch.commit_record(Behavior("L2", 1.0, sm3(b"c")))
    ok_clean, _ = v.verify(rec)
    rec.msg_digest = sm3(b"tampered")
    ok_bad, errs = v.verify(rec)
    return _t("定理1 完整性：篡改必被检出", ok_clean and not ok_bad,
              "篡改后报错：%s" % ("、".join(errs) if errs else "无"))


def test_theorem2_replay():
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000)
    v = ChainVerifier(bc); v.register("V-T", ch.h_d, ch.h_b)
    ch.begin_record(b"m1", 1, bc.current())
    r1 = ch.commit_record(Behavior("L2", 1.0, sm3(b"c1")))
    v.verify(r1)
    ok_replay, errs = v.verify(r1)          # 重放同一条记录
    for _ in range(5):
        bc.next_epoch()                      # 信标窗口前移
    stale = bc.is_valid(1, bc.beacons[1].value)
    return _t("定理2 新鲜性：抗重放与窗口外拒收", (not ok_replay) and (not stale),
              "重放报错：%s" % "、".join(errs))


def test_eq4_eq6_property1():
    _, S = sensitivity_score("精确GPS轨迹", geofence_hit=True)
    ok = (S == 3)
    ok = ok and verify_property1(2.0, 0.1)
    r = ratio_constant(2.0, 0.1)
    ok = ok and abs(eps_cap(3) - 0.1) < 1e-9 and abs(eps_cap(0) - 2.0) < 1e-12
    return _t("式4–6 与性质1 等比收紧", ok,
              "λ=%.4f，相邻倍率 e^(−λ)=%.4f 与 S 无关" % (lam(), r))


def test_eq7_proposition1():
    """命题1：开销与强度同向单调时，最优解为最低可行等级。"""
    ok = True
    detail = ""
    rng = random.Random(7)
    for _ in range(300):
        ctx = Context(rng.uniform(0.4, 1.0), rng.uniform(0.4, 1.0), rng.uniform(0.4, 1.0))
        S = rng.randrange(4)
        d = select(S, ctx)
        if d.policy is not None and not d.prop1_consistent:
            ok, detail = False, "S=%d ctx=%s 时 argmin 非最低可行等级" % (S, ctx)
            break
    if ok:
        detail = "300 组随机上下文下 argmin J(a) 恒等于最低可行等级"
    return _t("式7 与命题1 最小可行级别最优性", ok, detail)


def test_eq8_eq12_commitment():
    k = os.urandom(32); h_d = sm3(b"head"); ctr = 7
    seed = derive_seed(k, h_d, ctr)
    c = commitment(seed, derive_blind(k, h_d))
    ok = (commitment(derive_seed(k, h_d, ctr), derive_blind(k, h_d)) == c)
    ok = ok and (commitment(derive_seed(os.urandom(32), h_d, ctr),
                            derive_blind(k, h_d)) != c)
    ok = ok and (derive_seed(k, sm3(b"other"), ctr) != seed)
    return _t("式8/式12 种子派生与承诺可复算", ok,
              "同 (k_v,h_d,ctr) 复算一致；链头改变即种子改变")


def test_eq9_uniformity():
    """式9：伪随机数的经验均值与方差应接近 U(0,1)。"""
    seed = os.urandom(32)
    n = 20000
    xs = [prf_u(seed, j) for j in range(1, n + 1)]
    m = sum(xs) / n
    var = sum((x - m) ** 2 for x in xs) / n
    ok = abs(m - 0.5) < 0.01 and abs(var - 1.0 / 12) < 0.002
    ok = ok and all(0.0 < x < 1.0 for x in xs)
    return _t("式9 伪随机序列均匀性", ok,
              "n=%d 均值%.4f(理论0.5) 方差%.5f(理论%.5f)" % (n, m, var, 1 / 12))


def test_eq10_laplace_moments():
    """式10：拉普拉斯样本一阶矩为 0、二阶矩为 2b²。"""
    seed = os.urandom(32); n = 40000; b = 1.0
    xs = laplace_noise(seed, n, delta1=1.0, eps=1.0)      # b = Δ₁/ε = 1
    m = sum(xs) / n
    v = sum(x * x for x in xs) / n
    ok = abs(m) < 0.05 and abs(v - 2 * b * b) < 0.12
    return _t("式10 拉普拉斯矩检验", ok,
              "均值%.4f(理论0) 二阶矩%.4f(理论%.1f)" % (m, v, 2 * b * b))


def test_eq11_gauss_moments():
    seed = os.urandom(32); n = 40000; sig = 0.7
    xs = gaussian_noise(seed, n, sig)
    m = sum(xs) / n
    v = sum(x * x for x in xs) / n
    ok = abs(m) < 0.02 and abs(v - sig ** 2) < 0.02
    return _t("式11 高斯矩检验 (Box–Muller)", ok,
              "均值%.4f(理论0) 方差%.4f(理论%.4f)" % (m, v, sig ** 2))


def test_theorem3_laplace_dp():
    """定理3：拉普拉斯机制的密度比上界 e^ε（对最坏相邻数据集直接核验）。"""
    eps, d1 = 0.8, 1.0
    b = d1 / eps
    worst = 0.0
    for z in [i * 0.05 for i in range(-200, 201)]:
        # f(D)=0, f(D')=Δ₁ 为达到 L1 敏感度上界的最坏相邻对
        ratio = math.exp((abs(z - d1) - abs(z - 0.0)) / b)
        worst = max(worst, ratio)
    ok = worst <= math.exp(eps) + 1e-9
    return _t("定理3 拉普拉斯机制 ε-DP 密度比", ok,
              "最坏密度比 %.6f ≤ e^ε = %.6f" % (worst, math.exp(eps)))


def test_theorem4_sigma():
    d2, eps, dl = 1.0, 0.5, 1e-5
    s = sigma_gauss(d2, eps, dl)
    ok = abs(s - d2 * math.sqrt(2 * math.log(1.25 / dl)) / eps) < 1e-12
    return _t("定理4/式14 高斯机制标定", ok, "σ_g = %.4f" % s)


def test_theorem6_ordering():
    """定理6：种子由链头决定，而链头先于噪声生成，故无法自适应挑选噪声。"""
    k = os.urandom(32)
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000)
    g = [0.3, -0.4, 0.5]
    ctr, h_d = ch.begin_record(pack_vec(g), 1, bc.current())
    n1 = gaussian_noise(derive_seed(k, h_d, ctr), 3, 0.5)
    # 若车辆改用另一组数据，则链头改变，噪声随之改变，无法"先看结果再选噪声"
    ch2 = InterwovenChain("V-T", 1700000000, seed_v=ch.seed_v)
    ctr2, h_d2 = ch2.begin_record(pack_vec([0.3, -0.4, 0.6]), 1, bc.current())
    n2 = gaussian_noise(derive_seed(k, h_d2, ctr2), 3, 0.5)
    return _t("定理6 抗自适应噪声选择", n1 != n2 and h_d != h_d2,
              "数据一经承诺，噪声即被唯一确定")


def test_theorem7_audit():
    """定理7：门限重构可确定性检出少加噪与伪装投毒；不足门限则零泄露。"""
    k = os.urandom(32)
    comm = AuditCommittee(k, 3, 5)
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000)
    g = [0.5, -0.2, 0.3, 0.1]
    m = pack_vec(g)
    ctr, h_d = ch.begin_record(m, 1, bc.current())
    seed = derive_seed(k, h_d, ctr)
    sig = 0.3
    n = gaussian_noise(seed, 4, sig)
    gc = clip(g, 1.0)
    good = [a + b for a, b in zip(gc, n)]
    beta = Behavior("L2", 1.0, commitment(seed, derive_blind(k, h_d)))
    rec = ch.commit_record(beta, payload=good,
                           meta=dict(mechanism="gauss", sigma=sig, delta2=1.0))
    rep_ok = run_threshold_audit(comm, [0, 1, 2], rec, m)

    rec.payload = [a + b / 8.0 for a, b in zip(gc, n)]          # 少加噪
    rep_under = run_threshold_audit(comm, [0, 1, 2], rec, m)
    nn = l2_norm(n); gn = max(1e-12, l2_norm(gc))
    rec.payload = [a - b / gn * nn for a, b in zip(gc, gc)]      # 伪装投毒
    rep_dis = run_threshold_audit(comm, [0, 1, 2], rec, m)

    leak = False
    try:
        comm.reconstruct([0, 1])                                 # 不足门限
    except PermissionError:
        leak = True
    ok = (rep_ok.compliant and (not rep_under.compliant)
          and (not rep_dis.compliant) and leak)
    return _t("定理7 门限追责与保密性", ok,
              "合规判定=%s；少加噪→%s；伪装→%s；<t 份额拒绝重构"
              % (rep_ok.verdict, rep_under.verdict.split("：")[-1],
                 rep_dis.verdict.split("：")[-1]))


def test_shamir_roundtrip():
    s = os.urandom(32)
    sh = split_secret(s, 3, 5)
    ok = reconstruct(sh[:3], 32) == s and reconstruct(sh[1:4], 32) == s
    ok = ok and reconstruct([sh[0], sh[2], sh[4]], 32) == s
    return _t("Shamir(3,5) 任意 t 份额重构一致", ok, "三组不同份额组合均还原原密钥")


def test_theorem8_variance():
    sp = split_variance(1.0, 1.0, 1e-5, K=20, R=5, rho_v=0.5, rho_r=0.3, rho_m=0.2)
    ok = sp.theorem8_holds()
    e1 = eps_rsu_view(sp, 1.0, 1e-5)
    e2 = eps_rsu_closed_form(1.0, 20, 0.5)
    ok = ok and abs(e1 - e2) < 1e-9
    return _t("定理8 方差可加 与 式16 层间量化", ok,
              "K·σ_v²+R·σ_r²+σ_m² = %.6f = σ_g²；ε_RSU=%.4f（两式一致）"
              % (sp.var_sum, e1))


def test_theorem8_empirical():
    """经验核验：三层独立噪声之和的样本方差应收敛到 σ_g²。"""
    sp = split_variance(1.0, 1.0, 1e-5, K=10, R=2, rho_v=0.5, rho_r=0.3, rho_m=0.2)
    rng = random.Random(11)
    N = 20000
    acc = 0.0
    for _ in range(N):
        tot = sum(rng.gauss(0, sp.sigma_v) for _ in range(sp.K))
        tot += sum(rng.gauss(0, sp.sigma_r) for _ in range(sp.R))
        tot += rng.gauss(0, sp.sigma_m)
        acc += tot * tot
    emp = acc / N
    ok = abs(emp - sp.sigma_g ** 2) / sp.sigma_g ** 2 < 0.05
    return _t("定理8 蒙特卡洛经验验证", ok,
              "经验方差 %.4f 对理论 σ_g²=%.4f，相对偏差 %.2f%%"
              % (emp, sp.sigma_g ** 2, 100 * abs(emp - sp.sigma_g ** 2) / sp.sigma_g ** 2))


def test_hetero_variance_split():
    """异构分摊：车辆层方差按 ε_i 分摊后，定理8 仍以等式成立，且等 ε 时退化为式15。"""
    sp = split_variance(1.0, 1.0, 1e-5, K=6, R=2, rho_v=0.5, rho_r=0.3, rho_m=0.2)
    eps = [0.2, 0.5, 1.0, 1.0, 2.0, 0.8]
    sv = vehicle_sigmas(sp, eps)
    ok = theorem8_holds_hetero(sv, sp)
    # 预算越紧（ε 越小）噪声越大：σ 应随 ε 单调递减
    pairs = sorted(zip(eps, sv))
    ok = ok and all(pairs[i][1] >= pairs[i + 1][1] - 1e-12 for i in range(len(pairs) - 1))
    # 等 ε 时退化为式15 的均匀分摊
    sv_eq = vehicle_sigmas(sp, [0.7] * 6)
    ok = ok and all(abs(x - sp.sigma_v) < 1e-12 for x in sv_eq)
    # 审计方仅凭链上 ε 与公开轮参数即可复算 σ
    inv = sum(1.0 / (e * e) for e in eps)
    ok = ok and all(abs(sigma_of_eps(eps[i], inv, sp.rho_v, sp.sigma_g) - sv[i]) < 1e-12
                    for i in range(len(eps)))
    return _t("车辆层方差异构分摊（定理8 等式保持）", ok,
              "σ_v,i∈[%.4f, %.4f]，Σσ_v,i²+Rσ_r²+σ_m²=σ_g²；等 ε 时退化为式15"
              % (min(sv), max(sv)))


def test_audit_no_self_report():
    """审计方不采信车辆自报的 σ：虚标 ε 同时篡改自报 σ 仍被检出。"""
    k_v = os.urandom(32)
    comm = AuditCommittee(k_v, 3, 5)
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000)
    g = [0.4, -0.3, 0.2, 0.5]
    m = pack_vec(g)
    ctr, h_d = ch.begin_record(m, 1, bc.current())
    seed = derive_seed(k_v, h_d, ctr)
    sp = split_variance(1.0, 1.0, 1e-5, K=4, R=1, rho_v=0.5, rho_r=0.3, rho_m=0.2)
    eps_list = [1.0, 1.0, 1.0, 1.0]
    inv = sum(1.0 / (e * e) for e in eps_list)
    pub = dict(rho_v=sp.rho_v, sigma_g=sp.sigma_g, inv_sum=inv,
               delta2=1.0, mechanism="gauss")
    sigma_true = sigma_of_eps(1.0, inv, sp.rho_v, sp.sigma_g)
    n = gaussian_noise(seed, 4, sigma_true / 6.0)          # 少加噪
    gc = clip(g, 1.0)
    beta = Behavior("L2", 1.0, commitment(seed, derive_blind(k_v, h_d)))
    # 车辆同时把自报 σ 也改小，试图使残差归零
    rec = ch.commit_record(beta, payload=[a + b for a, b in zip(gc, n)],
                           meta=dict(mechanism="gauss", sigma=sigma_true / 6.0, delta2=1.0))
    rep_pub = run_threshold_audit(comm, [0, 1, 2], rec, m, public_params=pub)
    rep_meta = run_threshold_audit(comm, [0, 1, 2], rec, m)      # 离线模式（采信 meta）
    ok = (not rep_pub.compliant) and rep_meta.compliant
    return _t("审计不采信自报参数（σ 由链上 ε 复算）", ok,
              "采信自报 σ 时被判\"%s\"；改由链上 ε 复算后判定\"%s\""
              % (rep_meta.verdict, rep_pub.verdict))


def test_norm_scale_normalization():
    """式22 的尺度归一化：异构噪声下显著抑制对高噪声诚实车辆的误报。

    单次试验的 3-MAD 判定本身带随机性，故用 300 次重复试验统计总误报数，
    比较归一化前后的差异，避免以单个随机种子的偶然结果下结论。
    """
    import random as _r

    def trial(seed, n=24, d=10):
        rng = _r.Random(seed)
        sigmas = [0.08 + 0.9 * (i / (n - 1)) ** 1.6 for i in range(n)]
        ups, scales = [], {}
        for i, sg in enumerate(sigmas):
            vec = [rng.gauss(0, sg) + (0.3 if j == 0 else 0.0) for j in range(d)]
            vid = "V%d" % i
            ups.append(dict(vid=vid, vec=vec))
            scales[vid] = math.sqrt(1.0 + d * sg * sg)
        det = Detector(3.0, -1.0)          # 关闭余弦通道，单独考察范数通道
        r1, _ = det.screen(ups, {}, None)
        r2, _ = det.screen(ups, {}, scales)
        return (sum(1 for r in r1 if r.norm_flag),
                sum(1 for r in r2 if r.norm_flag))

    raw = norm = 0
    for sd in range(300):
        a, b = trial(sd)
        raw += a
        norm += b
    ok = norm < 0.6 * raw
    return _t("式22 尺度归一化（异构噪声下的误报抑制）", ok,
              "300 次试验：未归一化误报 %d 例 → 按 s_i=√(Δ₂²+dσ_i²) 归一化后 %d 例，降幅 %.0f%%"
              % (raw, norm, 100 * (1 - norm / max(1, raw))))


def test_composition_bound_tighter():
    """准入界应取高级组合与基本组合中较紧者。"""
    e1, _, n1 = composition_bound(0.1, 1e-6, 100)
    e2, _, n2 = composition_bound(2.0, 1e-6, 30)
    ea1, _ = advanced_composition(0.1, 1e-6, 100)
    eb2, _ = basic_composition(2.0, 1e-6, 30)
    ok = (abs(e1 - ea1) < 1e-9 and n1.startswith("高级")
          and abs(e2 - eb2) < 1e-9 and n2 == "基本组合")
    acc = BudgetAccountant(50.0, 2.0, 1e-6)
    cnt = 0
    while acc.admit():
        cnt += 1
        if cnt > 1000:
            break
    ok = ok and cnt == 25 and acc.spent()[0] <= 50.0
    return _t("多轮准入取较紧的组合界", ok,
              "ε₀=0.1,T=100 采用%s(%.2f)；ε₀=2.0,T=30 采用%s(%.2f)；预算50 可训练%d轮"
              % (n1, e1, n2, e2, cnt))


def test_eq18_eq20_waterfilling():
    """式18–20：闭式解 + 数值算例 + KKT 最优性 + 与随机扰动的对比。"""
    u = [1.0, 2.0, 1.0]; d = [1.0, 1.0, 2.0]; tot = 1.0
    a = water_filling(u, d, tot)
    exp = [0.260, 0.327, 0.413]
    ok = all(abs(x - y) < 2e-3 for x, y in zip(a.eps, exp))
    ok = ok and abs(sum(a.eps) - tot) < 1e-9
    ok = ok and kkt_residual(u, d, a.eps, a.capped) < 1e-9
    # 最优性对照：随机可行点的失真不应低于最优解
    rng = random.Random(3)
    best = a.distortion
    worse = True
    for _ in range(2000):
        r = [rng.random() + 1e-3 for _ in range(3)]
        ssum = sum(r)
        cand = [x / ssum * tot for x in r]
        if distortion(u, d, cand) < best - 1e-12:
            worse = False
            break
    ok = ok and worse
    ok = ok and second_derivative(1.0, 1.0, 0.5) > 0
    return _t("式18–20 水填充闭式解与 KKT 最优性", ok,
              "ε*≈(%.3f, %.3f, %.3f) 与说明书算例一致；2000 个随机可行点均未更优"
              % tuple(a.eps))


def test_waterfilling_caps():
    u = [1.0, 5.0, 1.0]; d = [1.0, 1.0, 1.0]
    caps = [0.5, 0.3, 0.5]
    a = water_filling(u, d, 1.0, caps)
    ok = all(e <= c + 1e-12 for e, c in zip(a.eps, caps))
    ok = ok and abs(sum(a.eps) - 1.0) < 1e-9 and a.capped[1]
    return _t("截断水填充：上限约束不被突破", ok,
              "高效用方向被 ε̄ 封顶，剩余预算再分配，总量守恒")


def test_eq17_composition():
    e_a, d_a = advanced_composition(0.1, 1e-6, 100, 1e-6)
    e_b, _ = basic_composition(0.1, 1e-6, 100)
    ok = e_a < e_b                       # 小 ε₀ 时高级组合更紧
    e_a2, _ = advanced_composition(2.0, 1e-6, 100, 1e-6)
    e_b2, _ = basic_composition(2.0, 1e-6, 100)
    ok = ok and e_a2 > e_b2              # 大 ε₀ 时基本组合更紧（须取二者较小者）
    return _t("式17 高级组合定理与适用范围", ok,
              "ε₀=0.1,T=100：高级 %.2f < 基本 %.2f；ε₀=2.0 时反向，实施时取二者较小"
              % (e_a, e_b))


def test_admission_bound():
    """准入界应始终取高级组合与基本组合中较紧者，且随轮数单调不减。"""
    ok = True
    for e0 in (0.05, 0.1, 0.5, 1.0, 2.0):
        for T in (1, 5, 20, 100):
            eu, _, nm = composition_bound(e0, 1e-6, T)
            ea, _ = advanced_composition(e0, 1e-6, T)
            eb, _ = basic_composition(e0, 1e-6, T)
            if abs(eu - min(ea, eb)) > 1e-12:
                ok = False
            if nm not in ("基本组合", "高级组合(式17)"):
                ok = False
    prev = -1.0
    for T in range(1, 60):
        e, _, _ = composition_bound(0.3, 1e-6, T)
        if e < prev - 1e-12:
            ok = False
        prev = e
    acc = BudgetAccountant(10.0, 0.3, 1e-6)
    while acc.can_admit():
        acc.admit()
    e, _ = acc.spent()
    ok = ok and e <= 10.0 and acc.rounds == max_rounds(10.0, 0.3, 1e-6)
    _, _, n1 = composition_bound(0.05, 1e-6, 100)
    _, _, n2 = composition_bound(2.0, 1e-6, 100)
    ok = ok and n1 == "高级组合(式17)" and n2 == "基本组合"
    return _t("多轮准入界取较紧者且单调", ok,
              "ε₀=0.05 采用%s；ε₀=2.0 采用%s；会计器在预算内准入 %d 轮"
              % (n1, n2, acc.rounds))


def test_policy_degrade_floor():
    """两级降级：资源不足时退至强度底线，S3 级底线为 L3 且不可再降。"""
    ok = True
    # 资源充裕：S3 应取 L4
    rich = Context(0.99, 0.99, 0.99)
    d_rich = select(3, rich)
    ok = ok and d_rich.policy is not None and d_rich.policy.name == "L4" and not d_rich.degraded
    # 资源中等（网络偏弱）：L4 不可行 → 退至底线 L3 并封顶预算
    mid = Context(0.9, 0.9, 0.45)
    d_mid = select(3, mid)
    ok = ok and d_mid.policy is not None and d_mid.policy.name == "L3"
    ok = ok and d_mid.degraded and d_mid.cap_eps
    # 资源匮乏：连 L3 都不可行 → 延迟上传，绝不降到 L2 以下
    poor = Context(0.2, 0.2, 0.2)
    d_poor = select(3, poor)
    ok = ok and d_poor.policy is None and "不可降级" in (d_poor.fallback or "")
    # S2 级：L3 不可行时可降至 L2（底线 = 2）
    d_s2 = select(2, Context(0.35, 0.9, 0.9))
    ok = ok and d_s2.policy is not None and d_s2.policy.name == "L2" and d_s2.degraded
    ok = ok and p_floor(3) == 3 and p_floor(2) == 2 and p_floor(1) == 2 and p_floor(0) == 1
    # 与 3.3 节阈值化规则在 L4 边界上的一致性
    from .policy import select_by_rule
    ok = ok and select_by_rule(3, rich) == "L4" and select_by_rule(3, mid) == "L3"
    return _t("式7 两级降级与 S3 不可降级底线", ok,
              "S3 资源充裕→L4（与3.3节规则一致）；中等→降级L3并封顶；"
              "匮乏→延迟上传（不降至L2）；S2 可降至L2")


def test_audit_no_self_report():
    """审计不采信被审计方的自我声明：开示的 m_t 必须与链上摘要一致。"""
    k_v = os.urandom(32)
    comm = AuditCommittee(k_v, 3, 5)
    bc = BeaconChain("RSU-T"); bc.next_epoch()
    ch = InterwovenChain("V-T", 1700000000)
    g = [0.4, -0.3, 0.2, 0.5]
    m = pack_vec(g)
    ctr, h_d = ch.begin_record(m, 1, bc.current())
    seed = derive_seed(k_v, h_d, ctr)
    n = gaussian_noise(seed, 4, 0.3)
    gc = clip(g, 1.0)
    beta = Behavior("L2", 1.0, commitment(seed, derive_blind(k_v, h_d)))
    rec = ch.commit_record(beta, payload=[a + b for a, b in zip(gc, n)],
                           meta=dict(mechanism="gauss", sigma=0.3, delta2=1.0))
    # 车辆试图开示一份"更干净"的梯度以掩盖其真实上传
    faked = pack_vec([x * 0.5 for x in g])
    rep_fake = run_threshold_audit(comm, [0, 1, 2], rec, faked)
    rep_true = run_threshold_audit(comm, [0, 1, 2], rec, m)
    ok = ((not rep_fake.disclosure_ok) and (not rep_fake.compliant)
          and rep_true.disclosure_ok and rep_true.compliant)
    return _t("审计不采信自我声明（开示须链绑定）", ok,
              "伪造开示 → %s；据实开示 → %s" % (rep_fake.verdict, rep_true.verdict))


def test_eq21_budget_link():
    cap = eps_cap(2)
    hi = update_budget(0.5, phi_i=2.0, phi_bar=1.0, S_i=2, cap_i=cap)
    lo = update_budget(0.5, phi_i=0.5, phi_bar=1.0, S_i=2, cap_i=cap)
    hi3 = update_budget(0.5, phi_i=2.0, phi_bar=1.0, S_i=3, cap_i=eps_cap(3))
    ok = hi > lo and hi <= cap + 1e-12 and hi3 <= eps_cap(3) + 1e-12
    return _t("式21 轮间联动：贡献升预算增、敏感升预算收", ok,
              "φ=2 → ε=%.4f；φ=0.5 → ε=%.4f；均不超 ε̄(S)" % (hi, lo))


def test_eq22_mad():
    xs = [1.0, 1.1, 0.9, 1.05, 0.95, 50.0]      # 含一个极端投毒样本
    T = robust_threshold(xs, 3.0)
    ok = T < 5.0 and 50.0 > T                    # 阈值不被极端值拉偏，且极端值被标记
    mean_th = (sum(xs) / len(xs)) + 3 * math.sqrt(
        sum((x - sum(xs) / len(xs)) ** 2 for x in xs) / len(xs))
    ok = ok and mean_th > 50.0                   # 均值+3σ 反而漏检，凸显鲁棒性
    return _t("式22 MAD 鲁棒阈值（击穿点50%）", ok,
              "MAD 阈值 %.3f 标记异常；均值+3σ 阈值 %.1f 反而漏检" % (T, mean_th))


def test_theta_cos_calibration():
    th = suggest_theta_cos(10, 0.05)
    rng = random.Random(5)
    n = 4000
    cnt = 0
    for _ in range(n):
        a = [rng.gauss(0, 1) for _ in range(10)]
        b = [rng.gauss(0, 1) for _ in range(10)]
        if cosine(a, b) < th:
            cnt += 1
    fpr = cnt / n
    ok = abs(fpr - 0.05) < 0.02
    return _t("余弦阈值 θ_c 的零假设标定", ok,
              "θ_c=%.4f 时经验误报率 %.2f%%（目标 5%%）" % (th, 100 * fpr))


def test_eq23_reputation():
    rep = Reputation(theta=0.8)
    for _ in range(20):
        rep.update("V-good", True)
    for _ in range(20):
        rep.update("V-bad", False)
    g, b = rep.get("V-good"), rep.get("V-bad")
    ok = g > 0.98 and b < 0.02 and 0 <= g <= 1 and 0 <= b <= 1
    return _t("式23 链核验信誉递推收敛", ok,
              "持续通过 → A=%.4f；持续失败 → A=%.4f" % (g, b))


def test_end_to_end():
    from .simulator import Simulator, SimConfig
    cfg = SimConfig(rounds=12, n_vehicles=16, dim=8,
                    attack_plan={2: "tamper", 5: "undernoise", 9: "disguise"})
    sim = Simulator(cfg)
    h = sim.run()
    st = sim.detection_stats()
    au = sim.audit_stats()
    ok = (len(h) == 12 and h[-1]['err'] < h[0]['err']
          and au['conditional_recall'] == 1.0 and st['fpr'] < 0.15)
    return _t("端到端仿真闭环", ok,
              "误差 %.3f→%.3f；审计条件检出率 %.0f%%；误报率 %.1f%%"
              % (h[0]['err'], h[-1]['err'], 100 * au['conditional_recall'],
                 100 * st['fpr']))


ALL = [test_sm3_vectors, test_sm3_backend_consistency, test_hmac_determinism, test_codec_injective,
       test_eq1_beacon, test_eq2_eq3_interweave, test_theorem1_tamper,
       test_theorem2_replay, test_eq4_eq6_property1, test_eq7_proposition1,
       test_eq8_eq12_commitment, test_eq9_uniformity, test_eq10_laplace_moments,
       test_eq11_gauss_moments, test_theorem3_laplace_dp, test_theorem4_sigma,
       test_theorem6_ordering, test_theorem7_audit, test_shamir_roundtrip,
       test_theorem8_variance, test_theorem8_empirical,
       test_hetero_variance_split, test_audit_no_self_report,
       test_norm_scale_normalization, test_composition_bound_tighter,
       test_eq18_eq20_waterfilling, test_waterfilling_caps,
       test_eq17_composition, test_admission_bound,
       test_policy_degrade_floor, test_audit_no_self_report,
       test_eq21_budget_link, test_eq22_mad,
       test_theta_cos_calibration, test_eq23_reputation, test_end_to_end]


def run_all(progress=None):
    out = []
    for i, f in enumerate(ALL):
        try:
            r = f()
        except Exception as e:
            r = (f.__name__, False, "异常：%s" % e)
        out.append(r)
        if progress:
            progress(i + 1, len(ALL), r)
    return out
