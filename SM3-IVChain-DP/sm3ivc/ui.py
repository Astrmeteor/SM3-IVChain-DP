# -*- coding: utf-8 -*-
"""图形界面（Tkinter，标准库，无第三方依赖）。

六个页签：
  ① 协同仿真   ② 交织双链   ③ 隐私预算   ④ 策略选择   ⑤ 追责审计   ⑥ 自检
"""

from __future__ import annotations

import math
import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, font as tkfont

from .sm3 import sm3, sm3_hex
from .codec import pack_vec
from .chain import BeaconChain, InterwovenChain, ChainVerifier, Behavior, MEC
from .sensitivity import sensitivity_score, eps_cap, lam, cap_table, PHI_T_TABLE, LEVEL_NAME
from .policy import Context, select, POLICY_LIB, ORDER
from .dp import (derive_seed, derive_blind, commitment, gaussian_noise, clip,
                 l2_norm, sigma_gauss)
from .layered import (split_variance, eps_rsu_view, eps_rsu_closed_form,
                      sigma_of_eps)
from .budget import (water_filling, advanced_composition, basic_composition,
                     composition_bound, kkt_residual, max_rounds)
from .shamir import AuditCommittee
from .audit import run_threshold_audit
from .detect import suggest_theta_cos
from .simulator import Simulator, SimConfig, ATTACKS, DATA_TYPES
from .selftest import run_all

BG = "#f4f6f9"
CARD = "#ffffff"
ACC = "#1f4e79"
OK = "#1a7f37"
BAD = "#b42318"
WARN = "#b54708"
GRID = "#d6dbe3"


def pick_font(root):
    """选择系统中可用的中文字体。"""
    fams = set(tkfont.families(root))
    for f in ("Noto Sans CJK SC", "Microsoft YaHei", "PingFang SC",
              "WenQuanYi Zen Hei", "SimHei", "Source Han Sans SC",
              "Noto Sans CJK JP", "DejaVu Sans"):
        if f in fams:
            return f
    return "TkDefaultFont"


# --------------------------------------------------------------------------
# 简易图表（Canvas 自绘，避免引入 matplotlib）
# --------------------------------------------------------------------------
class Chart(tk.Canvas):
    def __init__(self, master, w=520, h=240, **kw):
        super().__init__(master, width=w, height=h, bg=CARD,
                         highlightthickness=1, highlightbackground=GRID, **kw)
        self.W, self.H = w, h
        self.pad = (52, 16, 14, 34)     # 左 上 右 下

    def _frame(self, title, xlab, ylab, font):
        self.delete("all")
        l, t, r, b = self.pad
        self.create_rectangle(l, t, self.W - r, self.H - b, outline=GRID)
        if title:
            self.create_text(self.W / 2, 8, text=title, anchor="n",
                             font=(font, 9, "bold"), fill=ACC)
        if xlab:
            self.create_text(self.W / 2, self.H - 8, text=xlab, font=(font, 8))
        if ylab:
            self.create_text(10, t + 4, text=ylab, anchor="nw", font=(font, 8))

    def line_chart(self, xs, series, title="", xlab="", ylab="", font="TkDefaultFont",
                   colors=(ACC, BAD, OK, WARN)):
        self._frame(title, xlab, ylab, font)
        if not xs or not series:
            return
        l, t, r, b = self.pad
        pw, ph = self.W - l - r, self.H - t - b
        allv = [v for _, ys in series for v in ys if v is not None]
        if not allv:
            return
        lo, hi = min(allv), max(allv)
        if hi - lo < 1e-12:
            hi, lo = hi + 1, lo - 1
        pad = (hi - lo) * 0.1
        lo, hi = lo - pad, hi + pad
        x0, x1 = min(xs), max(xs)
        if x1 == x0:
            x1 = x0 + 1

        for k in range(5):
            yy = t + ph * k / 4
            self.create_line(l, yy, self.W - r, yy, fill=GRID, dash=(2, 3))
            self.create_text(l - 5, yy, text="%.3g" % (hi - (hi - lo) * k / 4),
                             anchor="e", font=(font, 7))
        for k in range(5):
            xx = l + pw * k / 4
            self.create_text(xx, self.H - b + 12,
                             text="%.0f" % (x0 + (x1 - x0) * k / 4), font=(font, 7))

        def P(x, y):
            return (l + pw * (x - x0) / (x1 - x0), t + ph * (hi - y) / (hi - lo))

        for i, (name, ys) in enumerate(series):
            c = colors[i % len(colors)]
            pts = []
            for x, y in zip(xs, ys):
                if y is None:
                    continue
                pts.extend(P(x, y))
            if len(pts) >= 4:
                self.create_line(*pts, fill=c, width=2, smooth=False)
            self.create_text(self.W - r - 6, t + 10 + 13 * i, text="— " + name,
                             anchor="e", fill=c, font=(font, 8, "bold"))

    def bar_chart(self, labels, values, title="", ylab="", font="TkDefaultFont",
                  caps=None, color=ACC):
        self._frame(title, "", ylab, font)
        if not values:
            return
        l, t, r, b = self.pad
        pw, ph = self.W - l - r, self.H - t - b
        hi = max(list(values) + ([max(caps)] if caps else []))
        hi = hi if hi > 0 else 1.0
        hi *= 1.15
        n = len(values)
        bw = pw / max(1, n)
        for k in range(5):
            yy = t + ph * k / 4
            self.create_line(l, yy, self.W - r, yy, fill=GRID, dash=(2, 3))
            self.create_text(l - 5, yy, text="%.2f" % (hi - hi * k / 4),
                             anchor="e", font=(font, 7))
        for i, v in enumerate(values):
            x = l + i * bw
            y = t + ph * (1 - v / hi)
            self.create_rectangle(x + bw * 0.18, y, x + bw * 0.82, t + ph,
                                  fill=color, outline="")
            if caps and i < len(caps) and caps[i] < float('inf'):
                yc = t + ph * (1 - caps[i] / hi)
                self.create_line(x + bw * 0.10, yc, x + bw * 0.90, yc,
                                 fill=BAD, width=2, dash=(4, 2))
            if n <= 26:
                self.create_text(x + bw / 2, t + ph + 10, text=str(labels[i]),
                                 font=(font, 7))
        if caps:
            self.create_text(self.W - r - 6, t + 10, text="- - 上限 ε̄(S)",
                             anchor="e", fill=BAD, font=(font, 8, "bold"))


# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("智能网联汽车SM3双链协同安全系统")
        self.geometry("1180x760")
        self.configure(bg=BG)
        self.FONT = pick_font(self)
        self._style()
        self.sim = None
        self.q = queue.Queue()

        head = tk.Frame(self, bg=ACC)
        head.pack(fill="x")
        tk.Label(head, text="智能网联汽车SM3双链协同安全系统",
                 bg=ACC, fg="white", font=(self.FONT, 14, "bold")).pack(side="left", padx=14, pady=8)
        tk.Label(head, text="SM3(GB/T 32905-2016) · 链态耦合可验证差分隐私 · 门限追责审计",
                 bg=ACC, fg="#c9dcf0", font=(self.FONT, 9)).pack(side="left", padx=6)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=8)
        self.nb = nb
        for name, build in (("① 协同仿真", self.tab_sim), ("② 交织双链", self.tab_chain),
                            ("③ 隐私预算", self.tab_budget), ("④ 策略选择", self.tab_policy),
                            ("⑤ 追责审计", self.tab_audit), ("⑥ 自检", self.tab_test)):
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=name)
            build(f)

        self.status = tk.Label(self, text="就绪", bg="#e8ecf2", anchor="w",
                               font=(self.FONT, 9))
        self.status.pack(fill="x", side="bottom")
        self.after(120, self._pump)

    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", font=(self.FONT, 10), padding=(14, 6))
        s.configure("Treeview", font=(self.FONT, 9), rowheight=22,
                    fieldbackground=CARD)
        s.configure("Treeview.Heading", font=(self.FONT, 9, "bold"))
        s.configure("TButton", font=(self.FONT, 9))
        s.configure("TLabelframe", background=BG)
        s.configure("TLabelframe.Label", font=(self.FONT, 10, "bold"),
                    background=BG, foreground=ACC)

    # -------------------------------------------------------------- helpers
    def card(self, parent, text, **kw):
        f = ttk.Labelframe(parent, text=text, **kw)
        return f

    def field(self, parent, label, default, width=8, row=0, col=0):
        tk.Label(parent, text=label, bg=BG, font=(self.FONT, 9),
                 anchor="e").grid(row=row, column=col * 2, sticky="e", padx=(8, 3), pady=3)
        v = tk.StringVar(value=str(default))
        e = tk.Entry(parent, textvariable=v, width=width, font=(self.FONT, 9),
                     relief="solid", bd=1)
        e.grid(row=row, column=col * 2 + 1, sticky="w", pady=3)
        return v

    def tree(self, parent, cols, widths, height=10):
        t = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c, w in zip(cols, widths):
            t.heading(c, text=c)
            t.column(c, width=w, anchor="center")
        sb = ttk.Scrollbar(parent, orient="vertical", command=t.yview)
        t.configure(yscroll=sb.set)
        return t, sb

    # ==================================================== ① 协同仿真
    def tab_sim(self, f):
        left = tk.Frame(f, bg=BG)
        left.pack(side="left", fill="y", padx=(0, 8))

        p = self.card(left, "仿真参数")
        p.pack(fill="x", pady=(0, 6))
        g = tk.Frame(p, bg=BG); g.pack(padx=4, pady=4)
        self.v_nv = self.field(g, "车辆数 K·R", 20, row=0, col=0)
        self.v_nr = self.field(g, "RSU 数 R", 2, row=0, col=1)
        self.v_dim = self.field(g, "模型维度 d", 10, row=1, col=0)
        self.v_rounds = self.field(g, "训练轮数 T", 30, row=1, col=1)
        self.v_epsg = self.field(g, "全局预算 ε_g", 2.0, row=2, col=0)
        self.v_delta = self.field(g, "δ", "1e-5", row=2, col=1)
        self.v_d2 = self.field(g, "裁剪 Δ₂", 1.0, row=3, col=0)
        self.v_lr = self.field(g, "学习率 η", 0.25, row=3, col=1)
        self.v_rv = self.field(g, "ρ_v", 0.5, row=4, col=0)
        self.v_rr = self.field(g, "ρ_r", 0.3, row=4, col=1)
        self.v_rm = self.field(g, "ρ_m", 0.2, row=5, col=0)
        self.v_kappa = self.field(g, "κ (式22)", 3.0, row=5, col=1)
        self.v_epstot = self.field(g, "单轮 ε_total", 10.0, row=6, col=0)
        self.v_audit = self.field(g, "抽检率", 0.20, row=6, col=1)
        self.v_thcos = self.field(g, "θ_c (0=自动)", 0.0, row=7, col=0)
        self.v_budget = self.field(g, "总预算 ε", 100.0, row=7, col=1)
        tk.Label(g, text="θ_c 填 0 按 z_α/√d 自动标定（α=5%）；填 0.1 复现说明书固定阈值",
                 bg=BG, fg="#666", font=(self.FONT, 8), wraplength=300,
                 justify="left").grid(row=8, column=0, columnspan=4,
                                      sticky="w", padx=8, pady=(2, 4))

        a = self.card(left, "攻击注入（车辆下标 : 类型）")
        a.pack(fill="x", pady=(0, 6))
        self.v_atk = tk.StringVar(value="3:tamper, 7:undernoise, 11:disguise, 15:norm, 17:replay")
        tk.Entry(a, textvariable=self.v_atk, font=(self.FONT, 8), width=40,
                 relief="solid", bd=1).pack(padx=6, pady=4)
        tk.Label(a, text="类型：" + " / ".join(ATTACKS.keys()), bg=BG,
                 font=(self.FONT, 8), fg="#555").pack(padx=6, pady=(0, 4))

        b = tk.Frame(left, bg=BG); b.pack(fill="x", pady=4)
        ttk.Button(b, text="▶ 运行仿真", command=self.run_sim).pack(side="left", padx=4)
        ttk.Button(b, text="■ 复位", command=self.reset_sim).pack(side="left")

        m = self.card(left, "隐私核算 / 检测指标")
        m.pack(fill="both", expand=True, pady=(6, 0))
        self.sim_metrics = tk.Text(m, height=16, width=44, font=(self.FONT, 9),
                                   relief="flat", bg=CARD, wrap="word")
        self.sim_metrics.pack(fill="both", expand=True, padx=4, pady=4)

        right = tk.Frame(f, bg=BG); right.pack(side="left", fill="both", expand=True)
        self.ch_err = Chart(right, 640, 210); self.ch_err.pack(pady=(0, 6))
        self.ch_det = Chart(right, 640, 190); self.ch_det.pack(pady=(0, 6))
        tv = self.card(right, "分通道检出归属（攻击类型 × 检测通道）")
        tv.pack(fill="both", expand=True)
        cols = ("攻击类型", "样本", "(a)链", "(b)范数", "(c)余弦", "(d)审计", "综合检出")
        self.tr_chan, sb = self.tree(tv, cols, (150, 55, 55, 60, 60, 60, 70), height=7)
        self.tr_chan.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb.pack(side="right", fill="y")

    def _parse_attacks(self):
        plan = {}
        for item in self.v_atk.get().split(","):
            item = item.strip()
            if not item or ":" not in item:
                continue
            i, t = item.split(":")
            t = t.strip()
            if t in ATTACKS:
                plan[int(i.strip())] = t
        return plan

    def run_sim(self):
        try:
            cfg = SimConfig(
                n_vehicles=int(self.v_nv.get()), n_rsu=int(self.v_nr.get()),
                dim=int(self.v_dim.get()), rounds=int(self.v_rounds.get()),
                lr=float(self.v_lr.get()), delta2=float(self.v_d2.get()),
                eps_g=float(self.v_epsg.get()), delta=float(self.v_delta.get()),
                rho_v=float(self.v_rv.get()), rho_r=float(self.v_rr.get()),
                rho_m=float(self.v_rm.get()), kappa=float(self.v_kappa.get()),
                eps_total_round=float(self.v_epstot.get()),
                audit_rate=float(self.v_audit.get()),
                theta_cos=float(self.v_thcos.get()),
                eps_budget=float(self.v_budget.get()),
                attack_plan=self._parse_attacks())
        except Exception as e:
            self.status.config(text="参数错误：%s" % e, fg=BAD)
            return
        self.status.config(text="仿真运行中…", fg=ACC)

        def work():
            try:
                sim = Simulator(cfg)
                sim.run()
                self.q.put(("sim", sim))
            except Exception as e:
                self.q.put(("err", str(e)))
        threading.Thread(target=work, daemon=True).start()

    def reset_sim(self):
        self.sim = None
        self.ch_err.delete("all"); self.ch_det.delete("all")
        self.sim_metrics.delete("1.0", "end")
        for i in self.tr_chan.get_children():
            self.tr_chan.delete(i)
        self.status.config(text="已复位", fg="black")

    def _show_sim(self, sim):
        self.sim = sim
        h = sim.history
        xs = [r['round'] for r in h]
        self.ch_err.line_chart(xs, [("模型误差 ‖w−w*‖₂", [r['err'] for r in h])],
                               "协同训练收敛曲线（含分层DP噪声）", "训练轮次 t",
                               "误差", self.FONT)
        self.ch_det.line_chart(
            xs, [("累计 ε_total", [r['eps_total'] for r in h]),
                 ("被标记车辆数", [r['flagged'] for r in h])],
            "隐私损耗核算 与 异常标记", "训练轮次 t", "", self.FONT)

        st = sim.detection_stats(); au = sim.audit_stats(); t8 = sim.theorem8_report()
        sp = sim.split
        eb, _ = basic_composition(sim.cfg.eps_g, sim.cfg.delta, len(h))
        ea, da = advanced_composition(sim.cfg.eps_g, sim.cfg.delta, len(h))
        used = h[-1].get('bound', '')
        deg = sum(r.get('degraded', 0) for r in h)
        dly = sum(r.get('delayed', 0) for r in h)
        txt = self.sim_metrics
        txt.delete("1.0", "end")
        L = txt.insert
        L("end", "【模型效用】\n")
        L("end", "  初始误差 %.4f → 终末误差 %.4f\n" % (h[0]['err'], h[-1]['err']))
        L("end", "  完成轮数 %d / %d\n" % (len(h), sim.cfg.rounds))
        L("end", "  策略降级 %d 次，延迟上传 %d 次（S3 底线不降级）\n\n"
                 % (sum(r.get('degraded', 0) for r in h),
                    sum(r.get('delayed', 0) for r in h)))
        L("end", "【分层噪声（式14/15，定理8）】\n")
        L("end", "  σ_g=%.4f  σ_r=%.4f  σ_m=%.4f\n"
                 % (t8['sigma_g'], t8['sigma_r'], t8['sigma_m']))
        L("end", "  σ_v,i 按各车 ε_i 异构分摊：[%.4f, %.4f]\n"
                 % (t8['sigma_v_min'], t8['sigma_v_max']))
        L("end", "  Σσ_v,i²+R·σ_r²+σ_m² = %.6f\n  σ_g²                = %.6f  → %s\n"
                 % (t8['lhs'], t8['rhs'], "成立" if t8['holds'] else "不成立"))
        L("end", "  层间视角 ε_RSU = %.4f（两式一致：%.4f）\n\n"
                 % (t8['eps_rsu'], t8['eps_rsu_cf']))
        L("end", "【多轮组合与准入】\n")
        L("end", "  高级组合 ε_total=%.2f\n" % ea)
        L("end", "  基本组合 T·ε₀ =%.2f\n" % eb)
        L("end", "  准入采用较紧者：%s，ε_total=%.2f，δ_total=%.2e\n\n"
                 % (used, h[-1]['eps_total'], h[-1]['delta_total']))
        L("end", "【策略两级降级】\n")
        L("end", "  降至强度底线并按 ε̄(S) 封顶：%d 车次\n" % deg)
        L("end", "  底线仍不可行、延迟上传：%d 车次\n\n" % dly)
        L("end", "【检测与审计】\n")
        L("end", "  θ_c 自动标定 = %.4f（目标误报率 5%%）\n" % sim.theta_cos_used)
        L("end", "  综合检出率 %.1f%%    误报率 %.1f%%\n"
                 % (100 * st['recall'], 100 * st['fpr']))
        L("end", "  审计次数 %d，其中对违规车辆 %d 次\n" % (au['audits'], au['on_malicious']))
        L("end", "  审计条件检出率 %.1f%%  ← 定理7 的确定性检出\n"
                 % (100 * au['conditional_recall']))

        for i in self.tr_chan.get_children():
            self.tr_chan.delete(i)
        for (k, name, n, ca, cb, cc, cd, tot) in sim.channel_attribution():
            self.tr_chan.insert("", "end", values=(name, n, ca, cb, cc, cd, tot))
        self.status.config(text="仿真完成：%d 轮" % len(h), fg=OK)

    # ==================================================== ② 交织双链
    def tab_chain(self, f):
        top = tk.Frame(f, bg=BG); top.pack(fill="x")
        c = self.card(top, "链上记录"); c.pack(fill="x")
        b = tk.Frame(c, bg=BG); b.pack(fill="x", padx=4, pady=4)
        ttk.Button(b, text="① 初始化车辆与RSU", command=self.chain_init).pack(side="left", padx=3)
        ttk.Button(b, text="② 追加一条记录", command=self.chain_append).pack(side="left", padx=3)
        ttk.Button(b, text="③ 篡改选中记录", command=self.chain_tamper).pack(side="left", padx=3)
        ttk.Button(b, text="④ 重放选中记录", command=self.chain_replay).pack(side="left", padx=3)
        ttk.Button(b, text="⑤ 全链验证", command=self.chain_verify).pack(side="left", padx=3)

        cols = ("ctr", "纪元τ", "R_τ(前8字节)", "SM3(m_t)", "h_t^d", "h_t^b", "策略", "ε", "状态")
        self.tr_chain, sb = self.tree(f, cols, (45, 50, 130, 130, 130, 130, 55, 55, 150), height=13)
        self.tr_chain.pack(side="top", fill="both", expand=True, padx=4, pady=4)
        self.tr_chain.tag_configure("bad", foreground=BAD)
        self.tr_chain.tag_configure("ok", foreground=OK)

        self.chain_log = tk.Text(f, height=9, font=(self.FONT, 9), bg=CARD,
                                 relief="solid", bd=1, wrap="word")
        self.chain_log.pack(fill="x", padx=4, pady=(0, 4))

    def chain_init(self):
        self.bc = BeaconChain("RSU-1")
        self.mec = MEC()
        self.bc.next_epoch(); self.bc.anchor_to_mec(self.mec)
        self.k_v = os.urandom(32)
        self.vchain = InterwovenChain("V-01", 1700000000)
        self.verifier = ChainVerifier(self.bc)
        self.verifier.register("V-01", self.vchain.h_d, self.vchain.h_b)
        self.committee = AuditCommittee(self.k_v, 3, 5)
        self.rec_msgs = {}
        for i in self.tr_chain.get_children():
            self.tr_chain.delete(i)
        self.chain_log.delete("1.0", "end")
        self._clog("已初始化：RSU-1 广播纪元信标 R_1 = %s…" % self.bc.current().value.hex()[:16])
        self._clog("车辆 V-01 注册：h_0^d = %s…，h_0^b = %s…"
                   % (self.vchain.h_d.hex()[:16], self.vchain.h_b.hex()[:16]))
        self._clog("k_v 已经 Shamir(3,5) 分发至审计委员会：%s" % "、".join(self.committee.members))

    def _clog(self, s):
        self.chain_log.insert("end", s + "\n")
        self.chain_log.see("end")

    def chain_append(self):
        if not hasattr(self, "vchain"):
            self.chain_init()
        import random as _r
        self.bc.next_epoch(); self.bc.anchor_to_mec(self.mec)
        g = [_r.gauss(0, 1) for _ in range(6)]
        m = pack_vec(g)
        ctr, h_d = self.vchain.begin_record(m, 1700000000 + self.vchain.ctr,
                                            self.bc.current())
        seed = derive_seed(self.k_v, h_d, ctr)
        sig = 0.3
        n = gaussian_noise(seed, 6, sig)
        gc = clip(g, 1.0)
        payload = [a + b for a, b in zip(gc, n)]
        cmt = commitment(seed, derive_blind(self.k_v, h_d))
        beta = Behavior("L2", 1.0, cmt)
        rec = self.vchain.commit_record(beta, payload=payload,
                                        meta=dict(mechanism="gauss", sigma=sig, delta2=1.0))
        self.rec_msgs[rec.ctr] = m
        ok, errs = self.verifier.verify(rec)
        self._insert_rec(rec, ok, errs)
        self._clog("追加第 %d 条：种子由链头派生，承诺 C_t=%s… 写入行为链"
                   % (rec.ctr, cmt.hex()[:16]))

    def _insert_rec(self, rec, ok, errs):
        self.tr_chain.insert("", "end", iid=str(rec.ctr), values=(
            rec.ctr, rec.epoch, rec.beacon.hex()[:16], rec.msg_digest.hex()[:16],
            rec.h_d.hex()[:16], rec.h_b.hex()[:16], rec.beta.policy,
            "%.2f" % rec.beta.epsilon,
            "验证通过" if ok else "；".join(errs)), tags=("ok" if ok else "bad",))

    def _selected_rec(self):
        sel = self.tr_chain.selection()
        if not sel:
            self._clog("请先在表中选中一条记录。")
            return None
        ctr = int(sel[0])
        for r in self.vchain.records:
            if r.ctr == ctr:
                return r
        return None

    def chain_tamper(self):
        r = self._selected_rec()
        if not r:
            return
        r.msg_digest = sm3(b"TAMPERED-" + os.urandom(4))
        ok, errs = self.verifier.verify(r)
        self.tr_chain.item(str(r.ctr), values=(
            r.ctr, r.epoch, r.beacon.hex()[:16], r.msg_digest.hex()[:16],
            r.h_d.hex()[:16], r.h_b.hex()[:16], r.beta.policy,
            "%.2f" % r.beta.epsilon, "；".join(errs) if errs else "验证通过"),
            tags=("bad" if not ok else "ok",))
        self._clog("【篡改试验】改写第 %d 条的 SM3(m_t) → 复算失败：%s"
                   % (r.ctr, "；".join(errs)))

    def chain_replay(self):
        r = self._selected_rec()
        if not r:
            return
        ok, errs = self.verifier.verify(r)
        self._clog("【重放试验】再次提交第 %d 条 → %s（ctr 非单调 / 信标越窗）"
                   % (r.ctr, "被拒绝：" + "；".join(errs) if not ok else "被接受"))

    def chain_verify(self):
        if not hasattr(self, "vchain"):
            return
        okb = self.bc.verify_chain()
        self._clog("信标链自校验：%s，共 %d 个纪元；MEC 锚定链头 %s…"
                   % ("通过" if okb else "失败", self.bc.epoch, self.mec.head.hex()[:16]))
        good = bad = 0
        for r in self.vchain.records:
            hd = InterwovenChain.data_head(r.prev_d, r.msg_digest, r.ctr, r.ts,
                                           r.vehicle_id, r.beacon, r.prev_b)
            hb = InterwovenChain.behavior_head(r.prev_b, r.beta, r.ctr, r.h_d)
            if hd == r.h_d and hb == r.h_b:
                good += 1
            else:
                bad += 1
        self._clog("双链逐条复算：通过 %d 条，失败 %d 条。" % (good, bad))

    # ==================================================== ③ 隐私预算
    def tab_budget(self, f):
        left = tk.Frame(f, bg=BG); left.pack(side="left", fill="y", padx=(0, 8))
        c = self.card(left, "水填充分配"); c.pack(fill="x")
        g = tk.Frame(c, bg=BG); g.pack(padx=4, pady=4)
        self.b_u = self.field(g, "效用 u_i", "1, 2, 1", width=22, row=0)
        self.b_d = self.field(g, "敏感度 Δ_i", "1, 1, 2", width=22, row=1)
        self.b_S = self.field(g, "等级 S_i", "1, 1, 1", width=22, row=2)
        self.b_tot = self.field(g, "ε_total", "1.0", width=22, row=3)
        self.b_cap = tk.IntVar(value=0)
        tk.Checkbutton(g, text="启用上限 ε̄(S_i) 截断", variable=self.b_cap, bg=BG,
                       font=(self.FONT, 9)).grid(row=4, column=0, columnspan=2, pady=3)
        ttk.Button(c, text="计算最优分配", command=self.calc_budget).pack(pady=(0, 6))

        c2 = self.card(left, "多轮组合核算"); c2.pack(fill="x", pady=(8, 0))
        g2 = tk.Frame(c2, bg=BG); g2.pack(padx=4, pady=4)
        self.c_eps0 = self.field(g2, "单轮 ε₀", "0.5", row=0)
        self.c_d0 = self.field(g2, "单轮 δ₀", "1e-6", row=1)
        self.c_T = self.field(g2, "轮数 T", "60", row=2)
        self.c_budget = self.field(g2, "总预算", "20", row=3)
        ttk.Button(c2, text="核算并绘制", command=self.calc_comp).pack(pady=(0, 6))

        self.b_out = tk.Text(left, height=13, width=44, font=(self.FONT, 9),
                             bg=CARD, relief="solid", bd=1, wrap="word")
        self.b_out.pack(fill="both", expand=True, pady=(8, 0))

        right = tk.Frame(f, bg=BG); right.pack(side="left", fill="both", expand=True)
        self.ch_alloc = Chart(right, 640, 250); self.ch_alloc.pack(pady=(0, 8))
        self.ch_comp = Chart(right, 640, 250); self.ch_comp.pack()

    def calc_budget(self):
        try:
            u = [float(x) for x in self.b_u.get().replace("，", ",").split(",")]
            d = [float(x) for x in self.b_d.get().replace("，", ",").split(",")]
            S = [int(x) for x in self.b_S.get().replace("，", ",").split(",")]
            tot = float(self.b_tot.get())
            caps = [eps_cap(s) for s in S] if self.b_cap.get() else None
            a = water_filling(u, d, tot, caps)
        except Exception as e:
            self.status.config(text="输入错误：%s" % e, fg=BAD); return
        res = kkt_residual(u, d, a.eps, a.capped)
        self.ch_alloc.bar_chart(["V%d" % (i + 1) for i in range(len(u))], a.eps,
                                "闭式最优分配 ε_i*", "ε_i", self.FONT,
                                caps=caps)
        o = self.b_out; o.delete("1.0", "end")
        o.insert("end", "【闭式解】ε_i* = ε_total·(u_iΔ_i²)^(1/3) / Σ(u_jΔ_j²)^(1/3)\n\n")
        for i, e in enumerate(a.eps):
            o.insert("end", "  车辆%d: ε=%.4f%s\n"
                     % (i + 1, e, "（已封顶于 ε̄(S)=%.3f）" % caps[i] if a.capped[i] else ""))
        o.insert("end", "\n  Σε_i = %.6f（约束 ε_total=%.4f）\n" % (a.total_used, tot))
        o.insert("end", "  总失真 Σ2u_iΔ_i²/ε_i² = %.6f\n" % a.distortion)
        o.insert("end", "  KKT 残差 = %.3e → %s\n"
                 % (res, "满足最优性" if res < 1e-6 else "存在封顶约束，互补松弛成立"))
        o.insert("end", "  迭代 %d 次收敛\n" % a.iterations)
        if a.note:
            o.insert("end", "  注：%s\n" % a.note)

    def calc_comp(self):
        try:
            e0 = float(self.c_eps0.get()); d0 = float(self.c_d0.get())
            T = int(self.c_T.get()); bud = float(self.c_budget.get())
        except Exception as e:
            self.status.config(text="输入错误：%s" % e, fg=BAD); return
        xs = list(range(1, T + 1))
        ya = [advanced_composition(e0, d0, t)[0] for t in xs]
        yb = [basic_composition(e0, d0, t)[0] for t in xs]
        yu = [composition_bound(e0, d0, t)[0] for t in xs]
        self.ch_comp.line_chart(xs, [("准入界=较紧者", yu), ("高级组合", ya),
                                     ("基本组合 T·ε₀", yb),
                                     ("总预算上限", [bud] * len(xs))],
                                "多轮隐私损耗核算与准入", "训练轮数 T", "ε_total",
                                self.FONT, colors=(OK, ACC, "#7a5195", BAD))
        n = max_rounds(bud, e0, d0)
        o = self.b_out; o.delete("1.0", "end")
        o.insert("end", "【高级组合定理】\n")
        o.insert("end", "  ε_total(T) = √(2T·ln(1/δ′))·ε₀ + T·ε₀·(e^ε₀ − 1)\n\n")
        eu, du, nm = composition_bound(e0, d0, T)
        o.insert("end", "  T=%d 时：高级 %.3f，基本 %.3f\n" % (T, ya[-1], yb[-1]))
        o.insert("end", "  准入采用较紧者：%s，ε_total=%.3f，δ_total=%.2e\n" % (nm, eu, du))
        o.insert("end", "  在总预算 %.2f 下可训练 %d 轮\n\n" % (bud, n))
        if ya[-1] > yb[-1]:
            o.insert("end", "  说明：当前 ε₀=%.2f 偏大，高级组合的 T·ε₀(e^ε₀−1) 项占主导，\n"
                            "  反而比线性损耗更松。二者均为合法上界，程序默认取较紧者，\n"
                            "  故此时准入依据自动切换为基本组合。\n" % e0)
        else:
            o.insert("end", "  说明：当前 ε₀ 较小，高级组合的 √T 主导项显著优于线性损耗。\n")

    # ==================================================== ④ 策略选择
    def tab_policy(self, f):
        left = tk.Frame(f, bg=BG); left.pack(side="left", fill="y", padx=(0, 8))
        c = self.card(left, "敏感度评分"); c.pack(fill="x")
        g = tk.Frame(c, bg=BG); g.pack(padx=6, pady=4)
        tk.Label(g, text="数据类型", bg=BG, font=(self.FONT, 9)).grid(row=0, column=0, sticky="e")
        self.p_dt = ttk.Combobox(g, values=list(PHI_T_TABLE.keys()), width=18,
                                 font=(self.FONT, 9), state="readonly")
        self.p_dt.set("精确GPS轨迹"); self.p_dt.grid(row=0, column=1, pady=3)
        self.p_L = tk.IntVar(); self.p_P = tk.IntVar(); self.p_C = tk.IntVar()
        for i, (t, v) in enumerate((("命中敏感地理围栏 φ_L", self.p_L),
                                    ("含个体标识特征 φ_P", self.p_P),
                                    ("处于特殊时段 φ_C", self.p_C))):
            tk.Checkbutton(g, text=t, variable=v, bg=BG, font=(self.FONT, 9),
                           command=self.calc_policy).grid(row=1 + i, column=0,
                                                          columnspan=2, sticky="w")
        self.p_dt.bind("<<ComboboxSelected>>", lambda e: self.calc_policy())

        c2 = self.card(left, "车端资源上下文"); c2.pack(fill="x", pady=(8, 0))
        self.p_C_ = tk.DoubleVar(value=0.8); self.p_B_ = tk.DoubleVar(value=0.7)
        self.p_N_ = tk.DoubleVar(value=0.8)
        for t, v in (("计算能力 C", self.p_C_), ("剩余电量 B", self.p_B_),
                     ("网络质量 N", self.p_N_)):
            r = tk.Frame(c2, bg=BG); r.pack(fill="x", padx=6, pady=2)
            tk.Label(r, text=t, bg=BG, font=(self.FONT, 9), width=11,
                     anchor="w").pack(side="left")
            tk.Scale(r, from_=0.05, to=1.0, resolution=0.01, orient="horizontal",
                     variable=v, bg=BG, length=190, font=(self.FONT, 8),
                     command=lambda e: self.calc_policy()).pack(side="left")

        self.p_out = tk.Text(left, height=14, width=44, font=(self.FONT, 9),
                             bg=CARD, relief="solid", bd=1, wrap="word")
        self.p_out.pack(fill="both", expand=True, pady=(8, 0))

        right = tk.Frame(f, bg=BG); right.pack(side="left", fill="both", expand=True)
        c3 = self.card(right, "策略库与代价函数 J(a)"); c3.pack(fill="x")
        cols = ("策略", "强度P(a)", "技术组合", "开销", "J(a)", "强度可行", "资源可行")
        self.tr_pol, sb = self.tree(c3, cols, (55, 65, 300, 55, 75, 70, 70), height=5)
        self.tr_pol.pack(fill="x", padx=4, pady=4)
        self.tr_pol.tag_configure("sel", background="#dff0e0")
        self.ch_cap = Chart(right, 640, 240); self.ch_cap.pack(pady=8)
        self.after(400, self.calc_policy)

    def calc_policy(self, *a):
        s_raw, S = sensitivity_score(self.p_dt.get(), bool(self.p_L.get()),
                                     bool(self.p_P.get()), bool(self.p_C.get()))
        ctx = Context(self.p_C_.get(), self.p_B_.get(), self.p_N_.get())
        d = select(S, ctx)
        for i in self.tr_pol.get_children():
            self.tr_pol.delete(i)
        for (name, lvl, J, sf, rf) in d.table:
            p = POLICY_LIB[name]
            tag = ("sel",) if (d.policy and d.policy.name == name) else ()
            self.tr_pol.insert("", "end", values=(
                name, lvl, p.tech, p.overhead, "%.3f" % J,
                "满足" if sf else "不足", "可行" if rf else "超限"), tags=tag)
        caps = [eps_cap(s) for s in range(4)]
        self.ch_cap.bar_chart(["S0", "S1", "S2", "S3"], caps,
                              "预算上限映射 ε̄(S)=ε₀·e^(−λS)，λ=%.4f" % lam(),
                              "ε̄(S)", self.FONT)
        o = self.p_out; o.delete("1.0", "end")
        o.insert("end", "S_raw = %.2f → S = %d（%s）\n" % (s_raw, S, LEVEL_NAME[S]))
        o.insert("end", "ε̄(S) = %.4f\n" % eps_cap(S))
        o.insert("end", "目标强度 P_req = %d\n\n" % (S + 1))
        if d.policy:
            o.insert("end", "→ 选定策略：%s（J = %.4f）\n" % (d.policy.name, d.J))
            o.insert("end", "   %s\n" % d.policy.tech)
            o.insert("end", "   可行集合：%s\n" % "、".join(d.feasible))
            if d.degraded:
                o.insert("end", "\n⚠ 资源不足，已降至强度底线；\n   预算封顶于 ε̄(%d)=%.3f\n"
                         % (S, eps_cap(S)))
            o.insert("end", "\n核验：%s\n"
                     % ("argmin J 即最低可行等级 ✓" if d.prop1_consistent else "不一致 ✗"))
        else:
            o.insert("end", "→ 无可行策略：%s\n" % d.fallback)

    # ==================================================== ⑤ 追责审计
    def tab_audit(self, f):
        top = self.card(f, "门限追责审计：重构 k_v → 重算噪声 → 比对残差")
        top.pack(fill="x")
        b = tk.Frame(top, bg=BG); b.pack(fill="x", padx=6, pady=6)
        tk.Label(b, text="被审计车辆行为：", bg=BG, font=(self.FONT, 9)).pack(side="left")
        self.a_kind = ttk.Combobox(b, width=26, state="readonly", font=(self.FONT, 9),
                                   values=["诚实（按规范加噪）", "少加噪声（虚标 ε）",
                                           "以加噪为名的定向投毒", "篡改开示的 m_t"])
        self.a_kind.set("少加噪声（虚标 ε）"); self.a_kind.pack(side="left", padx=6)
        tk.Label(b, text="参与审计委员数：", bg=BG, font=(self.FONT, 9)).pack(side="left", padx=(14, 0))
        self.a_n = tk.IntVar(value=3)
        tk.Spinbox(b, from_=1, to=5, textvariable=self.a_n, width=4,
                   font=(self.FONT, 9)).pack(side="left", padx=4)
        tk.Label(b, text="（门限 t=3，不足则零泄露）", bg=BG, fg="#666",
                 font=(self.FONT, 8)).pack(side="left")
        ttk.Button(b, text="▶ 执行审计", command=self.do_audit).pack(side="left", padx=12)

        self.a_out = tk.Text(f, font=(self.FONT, 10), bg=CARD, relief="solid",
                             bd=1, wrap="word")
        self.a_out.pack(fill="both", expand=True, padx=4, pady=6)
        self.a_out.tag_configure("ok", foreground=OK, font=(self.FONT, 10, "bold"))
        self.a_out.tag_configure("bad", foreground=BAD, font=(self.FONT, 10, "bold"))
        self.a_out.tag_configure("h", foreground=ACC, font=(self.FONT, 10, "bold"))

    def do_audit(self):
        import random as _r
        k_v = os.urandom(32)
        comm = AuditCommittee(k_v, 3, 5)
        bc = BeaconChain("RSU-A"); bc.next_epoch()
        ch = InterwovenChain("V-A", 1700000000)
        g = [_r.gauss(0, 1) for _ in range(8)]
        m = pack_vec(g)
        ctr, h_d = ch.begin_record(m, 1700000001, bc.current())
        seed = derive_seed(k_v, h_d, ctr)
        # 公开轮参数（由 MEC 发布并随信标锚定）；σ 由链上 ε 复算，不采信车辆自报
        sp = split_variance(1.0, 1.0, 1e-5, K=4, R=1, rho_v=0.5, rho_r=0.3, rho_m=0.2)
        eps_i = 1.0
        inv_sum = 4.0 / (eps_i * eps_i)
        pub = dict(rho_v=sp.rho_v, sigma_g=sp.sigma_g, inv_sum=inv_sum,
                   delta2=1.0, mechanism="gauss")
        sig = sigma_of_eps(eps_i, inv_sum, sp.rho_v, sp.sigma_g)
        n = gaussian_noise(seed, 8, sig)
        gc = clip(g, 1.0)
        kind = self.a_kind.get()
        if kind.startswith("诚实"):
            payload = [a + b for a, b in zip(gc, n)]
        elif kind.startswith("少加噪"):
            payload = [a + b / 8.0 for a, b in zip(gc, n)]
        elif kind.startswith("以加噪"):
            nn, gn = l2_norm(n), max(1e-12, l2_norm(gc))
            payload = [a - a / gn * nn for a in gc]
        else:
            payload = [a + b for a, b in zip(gc, n)]
        cmt = commitment(seed, derive_blind(k_v, h_d))
        rec = ch.commit_record(Behavior("L2", eps_i, cmt), payload=payload,
                               meta=dict(mechanism="gauss", sigma=sig, delta2=1.0))
        disclosed = pack_vec([x * 1.3 for x in g]) if kind.startswith("篡改") else m

        o = self.a_out; o.delete("1.0", "end")
        o.insert("end", "审计对象：车辆 V-A 第 %d 条记录\n" % ctr, "h")
        o.insert("end", "链上数据摘要 SM3(m_t) = %s\n" % rec.msg_digest.hex())
        o.insert("end", "数据链链头 h_t^d   = %s\n" % rec.h_d.hex())
        o.insert("end", "噪声承诺   C_t     = %s\n" % cmt.hex())
        o.insert("end", "链上声明   ε       = %.4f  → 审计方据此复算 σ = %.4f\n\n"
                 % (eps_i, sig))
        try:
            rep = run_threshold_audit(comm, list(range(self.a_n.get())), rec,
                                      disclosed, public_params=pub)
        except PermissionError as e:
            o.insert("end", "【步骤2 门限重构】失败\n", "h")
            o.insert("end", "  %s\n" % e, "bad")
            o.insert("end", "\n→ 保密性：少于 t 个份额对 k_v 信息论零泄露，\n"
                            "   噪声对其保持伪随机，隐私保证不受影响。\n")
            return
        o.insert("end", "【步骤1 链绑定开示】%s\n"
                 % ("SM3(开示 m_t) 与链上摘要一致 ✓" if rep.disclosure_ok
                    else "开示内容与链上摘要不符 ✗"),
                 "ok" if rep.disclosure_ok else "bad")
        o.insert("end", "【步骤2 门限重构】%s 名委员（%s）经拉格朗日插值重构 k_v ✓\n"
                 % (len(rep.committee), "、".join(rep.committee)), "ok")
        if rep.disclosure_ok:
            o.insert("end", "【步骤3 承诺核验】%s\n"
                     % ("SM3(seed_t ∥ r_t) 与 C_t 一致 ✓" if rep.commit_ok else "承诺不一致 ✗"),
                     "ok" if rep.commit_ok else "bad")
            o.insert("end", "【步骤4 噪声重算】逐维重算完成\n")
            o.insert("end", "【步骤5 残差比对】‖上传 − (clip(m_t)+n_t)‖₂ = %.6g\n\n" % rep.residual)
        o.insert("end", "审计结论：%s\n" % rep.verdict, "ok" if rep.compliant else "bad")
        o.insert("end", "%s\n\n" % rep.detail)
        if not rep.compliant:
            o.insert("end", "→ 该行为在通道(a)链校验与通道(b)(c)统计检测下均无异常表现，\n"
                            "   仅由通道(d) 门限追责审计确定性检出。\n"
                            "   处置：隔离该车辆、更新链核验信誉 A_i、上报管理端。\n")
        else:
            o.insert("end", "→ 噪声与链态重算结果逐维一致，隐私声明属实，信誉 A_i 上调。\n")

    # ==================================================== ⑥ 自检
    def tab_test(self, f):
        b = tk.Frame(f, bg=BG); b.pack(fill="x", pady=4)
        ttk.Button(b, text="▶ 运行全部自检",
                   command=self.run_tests).pack(side="left", padx=6)
        self.t_sum = tk.Label(b, text="", bg=BG, font=(self.FONT, 10, "bold"))
        self.t_sum.pack(side="left", padx=10)
        cols = ("项目", "结果", "说明")
        self.tr_test, sb = self.tree(f, cols, (330, 60, 620), height=22)
        self.tr_test.column("项目", anchor="w"); self.tr_test.column("说明", anchor="w")
        self.tr_test.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb.pack(side="right", fill="y")
        self.tr_test.tag_configure("ok", foreground=OK)
        self.tr_test.tag_configure("bad", foreground=BAD)

    def run_tests(self):
        for i in self.tr_test.get_children():
            self.tr_test.delete(i)
        self.t_sum.config(text="运行中…", fg=ACC)
        self.status.config(text="自检运行中…", fg=ACC)

        def work():
            rs = run_all()
            self.q.put(("test", rs))
        threading.Thread(target=work, daemon=True).start()

    def _show_tests(self, rs):
        p = 0
        for name, ok, msg in rs:
            p += 1 if ok else 0
            self.tr_test.insert("", "end", values=(name, "通过" if ok else "失败", msg),
                                tags=("ok" if ok else "bad",))
        self.t_sum.config(text="%d / %d 项通过" % (p, len(rs)),
                          fg=OK if p == len(rs) else BAD)
        self.status.config(text="自检完成：%d/%d" % (p, len(rs)),
                           fg=OK if p == len(rs) else BAD)

    # ------------------------------------------------------------ 事件泵
    def _pump(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "sim":
                    self._show_sim(data)
                elif kind == "test":
                    self._show_tests(data)
                elif kind == "err":
                    self.status.config(text="错误：%s" % data, fg=BAD)
        except queue.Empty:
            pass
        self.after(120, self._pump)


def main():
    App().mainloop()
