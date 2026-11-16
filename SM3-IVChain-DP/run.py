#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基于SM3交织哈希链与链态耦合自适应差分隐私的智能网联汽车协同安全系统
—— 工程化参考实现，程序入口。

用法：
    python run.py                启动图形界面（默认）
    python run.py --selftest     命令行运行全部公式/定理自检
    python run.py --cli          命令行运行一次端到端协同仿真
    python run.py --cli -r 50 -n 30 -e 1.0    指定轮数/车辆数/ε_g

依赖：仅 Python 3.8+ 标准库（图形界面需 tkinter，随官方 Python 一同安装）。
"""

from __future__ import annotations

import argparse
import sys


def cli_selftest() -> int:
    from sm3ivc.selftest import run_all
    print("=" * 78)
    print("公式与定理自检")
    print("=" * 78)
    rs = run_all()
    for name, ok, msg in rs:
        print("[%s] %-38s %s" % ("通过" if ok else "失败", name, msg))
    p = sum(1 for _, ok, _ in rs if ok)
    print("-" * 78)
    print("合计：%d / %d 项通过" % (p, len(rs)))
    return 0 if p == len(rs) else 1


def cli_sim(args) -> int:
    from sm3ivc.simulator import Simulator, SimConfig, ATTACKS
    plan = {}
    for item in (args.attacks or "").split(","):
        item = item.strip()
        if ":" in item:
            i, t = item.split(":")
            if t.strip() in ATTACKS:
                plan[int(i)] = t.strip()
    cfg = SimConfig(rounds=args.rounds, n_vehicles=args.vehicles, dim=args.dim,
                    eps_g=args.eps_g, attack_plan=plan)
    sim = Simulator(cfg, log=print)
    print("=" * 78)
    print("车—路—边—云协同仿真：车辆 %d，RSU %d，维度 %d，ε_g=%.2f，δ=%.0e"
          % (cfg.n_vehicles, cfg.n_rsu, cfg.dim, cfg.eps_g, cfg.delta))
    print("攻击注入：%s" % (plan if plan else "无"))
    print("=" * 78)
    h = sim.run()
    print("%-6s %-12s %-8s %-8s %-12s" % ("轮次", "模型误差", "接受", "标记", "ε_total"))
    for r in h:
        print("%-6d %-12.4f %-8d %-8d %-12.3f"
              % (r['round'], r['err'], r['accepted'], r['flagged'], r['eps_total']))
    t8 = sim.theorem8_report()
    st = sim.detection_stats()
    au = sim.audit_stats()
    print("-" * 78)
    print("定理8 核验：K·σ_v²+R·σ_r²+σ_m² = %.6f，σ_g² = %.6f → %s"
          % (t8['lhs'], t8['rhs'], "成立" if t8['holds'] else "不成立"))
    print("式16 层间视角：ε_RSU = %.4f（闭式 %.4f）" % (t8['eps_rsu'], t8['eps_rsu_cf']))
    print("检测：综合检出率 %.1f%%，误报率 %.1f%%（θ_c 自动标定 %.4f）"
          % (100 * st['recall'], 100 * st['fpr'], sim.theta_cos_used))
    print("审计：共 %d 次，对违规车辆 %d 次，条件检出率 %.1f%%（定理7）"
          % (au['audits'], au['on_malicious'], 100 * au['conditional_recall']))
    print("-" * 78)
    print("%-24s %-6s %-6s %-6s %-6s %-6s %-8s"
          % ("攻击类型", "样本", "(a)链", "(b)范数", "(c)余弦", "(d)审计", "综合检出"))
    for (k, name, n, ca, cb, cc, cd, tot) in sim.channel_attribution():
        print("%-24s %-6d %-6d %-8d %-8d %-8d %-8d" % (name, n, ca, cb, cc, cd, tot))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SM3交织哈希链与链态耦合自适应差分隐私系统")
    ap.add_argument("--selftest", action="store_true", help="运行公式与定理自检")
    ap.add_argument("--cli", action="store_true", help="命令行模式运行端到端仿真")
    ap.add_argument("-r", "--rounds", type=int, default=30, help="训练轮数 T")
    ap.add_argument("-n", "--vehicles", type=int, default=20, help="车辆数")
    ap.add_argument("-d", "--dim", type=int, default=10, help="模型维度")
    ap.add_argument("-e", "--eps-g", type=float, default=2.0, help="全局单轮隐私预算 ε_g")
    ap.add_argument("-a", "--attacks", type=str,
                    default="3:tamper,7:undernoise,11:disguise,15:norm,17:replay",
                    help="攻击注入，如 3:tamper,7:undernoise")
    args = ap.parse_args()

    if args.selftest:
        return cli_selftest()
    if args.cli:
        return cli_sim(args)

    try:
        from sm3ivc.ui import main as ui_main
    except ImportError as e:
        print("未能加载图形界面（%s）。" % e)
        print("多数系统的官方 Python 已自带 tkinter；若缺失可安装：")
        print("  Ubuntu/Debian:  sudo apt install python3-tk")
        print("  Fedora:         sudo dnf install python3-tkinter")
        print("现改用命令行模式运行。\n")
        return cli_sim(args)
    ui_main()
    return 0


if __name__ == "__main__":

    sys.exit(main())
