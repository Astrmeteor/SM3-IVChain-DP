# 基于 SM3 交织哈希链与链态耦合自适应差分隐私的智能网联汽车协同安全系统

# Secure Connected-Vehicle Collaboration via SM3 Interwoven Hash Chains and Chain-State-Coupled Adaptive Differential Privacy

> 技术方案的工程化参考实现 · v1.0
>
> Engineering reference implementation of the technical scheme · v1.0

本程序把设计文档中的 23 个公式、9 条定理、1 条性质与 1 条命题全部落为可执行代码，并提供图形界面与端到端仿真，可用于方案验证、实验数据采集与答辩演示。全部公式与定理配有 36 项运行期自检，`python run.py --selftest` 可一键复现，当前 **36/36 通过**。

This program implements all 23 formulas, 9 theorems, 1 property and 1 proposition from the design document as executable code, and provides a graphical interface plus end-to-end simulation for scheme validation, experiment data collection and defense demos. All formulas and theorems are covered by 36 runtime self-tests, reproducible with `python run.py --selftest` — currently **36/36 pass**.

---

## 一、快速开始 / Quick Start

```bash
python run.py
```

只需 **Python 3.8 或更高版本**，无需 `pip install` 任何东西，下载解压后直接运行即可。**Requires only Python 3.8+** — no `pip install` needed; run it right after download.

其他运行方式 / Other modes:

```bash
python run.py --selftest     # 命令行逐条验证全部公式与定理 / run all formula & theorem self-tests
python run.py --cli          # 命令行运行一次端到端协同仿真 / run one end-to-end simulation
python run.py --cli -r 50 -n 30 -e 1.0 -a "3:tamper,8:disguise"   # 自定义轮数/车辆数/ε_g/攻击注入
```

**依赖说明 / Dependencies**：整个项目只用 Python 标准库。图形界面使用 `tkinter`（Windows / macOS 官方安装包自带）。若 Linux 提示缺少 tkinter，执行 `sudo apt install python3-tk`（或 `sudo dnf install python3-tkinter`）即可；即便不装，`run.py` 也会自动降级到命令行模式，功能不受影响。
The entire project uses only the Python standard library. The GUI uses `tkinter` (bundled with official Windows/macOS Python). On Linux, install it via `sudo apt install python3-tk` (or `sudo dnf install python3-tkinter`); if absent, `run.py` automatically falls back to CLI mode with no loss of functionality.

**关于 SM3 后端 / SM3 backend**：程序优先调用本机 OpenSSL 的 SM3 实现以提升速度，启用前会用 GB/T 32905-2016 的两组标准向量以及与内置纯 Python 实现的逐字节交叉比对进行校验；任何一项不符或本机不支持，则自动回落到纯 Python 实现。两条路径结果完全一致，仅性能不同（实测约 170 倍差距）。
The program prefers the machine's OpenSSL SM3 implementation for speed. Before enabling it, it validates against the two standard vectors of GB/T 32905-2016 and a byte-for-byte cross-check with the built-in pure-Python implementation; if anything mismatches or is unsupported, it falls back to pure Python automatically. Both paths produce identical results — only performance differs (~170×).

---

## 二、图形界面功能 / GUI Features

| 页签 / Tab | 功能 / Function |
|---|---|
| ① 协同仿真 / Collaboration Simulation | 配置车辆数 / RSU 数 / ε_g / 裁剪阈值 / θ_c / 总预算等，注入六类攻击，运行车—路—边—云闭环；输出收敛曲线、隐私损耗曲线、分通道检出归属表 |
| ② 交织双链 / Interwoven Dual Chains | 逐条构建链记录，可视化 R_τ、SM3(m_t)、h_t^d、h_t^b；一键做**篡改试验**与**重放试验**，实时展示定理 1、定理 2 的拒收 |
| ③ 隐私预算 / Privacy Budget | 水填充闭式解（式20）分配柱状图与 KKT 残差；高级组合与基本组合的多轮损耗对比曲线 |
| ④ 策略选择 / Policy Selection | 拖动 C / B / N 滑杆并选择数据类型，实时显示 S_raw→S→ε̄(S)→J(a) 全过程与命题 1 核验 |
| ⑤ 追责审计 / Accountability Audit | 选择被审计车辆的行为（诚实 / 少加噪 / 伪装投毒 / 篡改开示），执行门限重构式审计，逐步展示定理 7 的五步判定 |
| ⑥ 自检 / Self-Test | 一键运行 36 项公式与定理验证 |

---

## 三、公式与定理的代码对照 / Formula–Theorem Code Mapping

| 公式编号 / Ref | 内容 / Content | 代码位置 / Code Location |
|---|---|---|
| 式1 | 信标 R_τ = SM3(R_{τ−1}∥τ∥ID_RSU∥nonce_τ) | `chain.BeaconChain.next_epoch` |
| 式2 | 数据链 h_t^d | `chain.InterwovenChain.data_head` |
| 式3 | 行为链 h_t^b | `chain.InterwovenChain.behavior_head` |
| 式4 | 敏感度评分 S_raw、S | `sensitivity.sensitivity_score` |
| 式5、式6 | ε̄(S)=ε₀e^(−λS)、λ | `sensitivity.eps_cap` / `sensitivity.lam` |
| 式7 | 最小代价目标 J(a) 与约束 | `policy.cost` / `policy.select` |
| 式8 | 种子 seed_t = HMAC-SM3(k_v, h_t^d∥ctr∥0x01) | `dp.derive_seed` |
| 式9 | u_{t,j} = HMAC-SM3(seed,j)/2²⁵⁶ | `dp.prf_u` |
| 式10 | 拉普拉斯逆 CDF 采样 | `dp.laplace_from_u` |
| 式11 | 高斯 Box–Muller 采样 | `dp.gauss_from_u` |
| 式12 | 承诺 C_t = SM3(seed_t∥r_t) | `dp.commitment` |
| 式13 | 裁剪 clip(g) | `dp.clip` |
| 式14 | σ_g 标定 | `dp.sigma_gauss` |
| 式15 | 三层方差分解 | `layered.split_variance` |
| 式16 | 层间视角 ε_RSU | `layered.eps_rsu_view` |
| 式17 | 高级组合定理 | `budget.advanced_composition` |
| 式18–20 | 水填充目标、KKT、闭式解 | `budget.water_filling` |
| 式21 | 轮间预算联动 | `budget.update_budget` |
| 式22 | MAD 鲁棒阈值 | `detect.robust_threshold` |
| 式23 | 链核验信誉递推 | `detect.Reputation.update` |
| 定理1、2 / Thm 1–2 | 完整性、新鲜性 / Integrity, freshness | `chain.ChainVerifier.verify` |
| 定理3、4 / Thm 3–4 | 拉普拉斯 / 高斯机制 DP | `selftest.test_theorem3_laplace_dp` etc. |
| 定理5、6 / Thm 5–6 | 计算性 DP、抗自适应噪声选择 | `dp` 模块的次序约束 + `selftest` |
| 定理7 / Thm 7 | 门限追责与保密性 | `audit.run_threshold_audit` + `shamir` |
| 定理8、9 / Thm 8–9 | 方差可加、多轮核算 | `layered.LayerSplit.theorem8_holds` / `budget` |
| 性质1、命题1 / Prop. 1, Proposition 1 | 等比收紧、最小可行级别最优 | `sensitivity.verify_property1` / `policy.select` |

---

## 四、目录结构 / Repository Structure

```
SM3-IVChain-DP/  (仓库根目录 / repo root)
├── README.md                双语说明（本文件）/ bilingual README (this file)
├── 参考实现_使用说明.md       完整使用说明（中文）/ full usage notes (Chinese)
├── SM3交织哈希链协同安全系统_参考实现_v1.0.zip
├── .gitignore
└── SM3-IVChain-DP/
    ├── run.py               程序入口（UI / --cli / --selftest）/ entry point (GUI / --cli / --selftest)
    ├── README.md
    └── sm3ivc/
        ├── sm3.py             SM3(GB/T 32905-2016) 与 HMAC-SM3，双后端 / dual-backend SM3 & HMAC-SM3
        ├── codec.py           ∥ 的单射编码、向量打包 / injective ∥ encoding, vector packing
        ├── chain.py           信标链、交织双链、验证方、MEC 锚定 / beacon chain, interwoven dual chains, verifier, MEC anchoring
        ├── sensitivity.py     式4–6，性质1 / Eqs. 4–6, Property 1
        ├── policy.py          式7，命题1，3.3 决策规则 / Eq. 7, Proposition 1, §3.3 decision rules
        ├── dp.py              式8–14（核心算法）/ Eqs. 8–14 (core invention)
        ├── layered.py         式15–16，定理8 / Eqs. 15–16, Thm 8
        ├── budget.py          式17–21，水填充与预算会计 / Eqs. 17–21, water-filling & budget accounting
        ├── shamir.py          Shamir(t,n) 门限秘密分享 / threshold secret sharing
        ├── audit.py           门限追责审计，定理7 / threshold accountability audit, Thm 7
        ├── detect.py          四通道检测，式22–23 / four-channel detection, Eqs. 22–23
        ├── simulator.py       车—路—边—云端到端仿真 / vehicle–road–edge–cloud simulation
        ├── selftest.py        36 项公式与定理验证 / 36 formula & theorem self-tests
        └── ui.py              Tkinter 图形界面 / Tkinter GUI
```

---

## 五、实现说明 / Implementation Notes

工程实现中有几处必须把设计文档的文字表述精确化，这些选择均已在代码注释中标注，并各有对应自检项可复现。Several points in the design document required precise engineering decisions; these are annotated in code comments and each has a reproducible self-test:

1. **拼接运算符 ∥ 的实现 / Injective ∥ encoding.** 直接字节串拼接存在歧义（`"ab"∥"c"` 与 `"a"∥"bc"` 相同），会削弱定理 1 的抗碰撞归约。`codec.cat` 为每个分量加 4 字节长度前缀，使编码单射。Plain concatenation is ambiguous (`"ab"∥"c"` equals `"a"∥"bc"`), weakening the collision-resistance reduction of Theorem 1. `codec.cat` prefixes each component with its 4-byte length, making the encoding injective.

2. **式9 的浮点实现 / Floating-point Eq. 9.** `HMAC/2²⁵⁶` 在 IEEE-754 双精度下端点邻域会退化为 0 或 1，导致式10、式11 中的 `ln` 未定义。`dp.prf_u` 以固定规则夹取到开区间；该规则对车辆与审计方完全一致，不影响可复算性。`HMAC/2²⁵⁶` degrades to 0 or 1 near the endpoints in IEEE-754 double precision, making `ln` in Eqs. 10–11 undefined. `dp.prf_u` clamps into the open interval by a fixed rule, identical for vehicles and auditors, preserving reproducibility.

3. **审计全程不采信被审计方的任何自我声明 / Auditing trusts no self-reports.**
   - *开示层 / disclosure layer*：委员会强制车辆开示原始 `m_t`，并先核验 `SM3(m_t)` 是否等于链上摘要——该摘要由式2 绑定且经信标逐层锚定，故车辆无法就 `m_t` 说谎（归约至定理 1）。The committee requires disclosure of the original `m_t` and first checks `SM3(m_t)` against the on-chain digest, which is bound by Eq. 2 and anchored by the beacon — so vehicles cannot lie about `m_t` (reduces to Theorem 1).
   - *参数层 / parameter layer*：审计方**不读取记录中由车辆填写的 σ**，而是依据行为链中已绑定的 `ε_i` 与 MEC 发布并锚定的公开轮参数（ρ_v、σ_g、Σ1/ε_j²、Δ₂）复算 `σ_{v,i}`。否则"虚标 ε"的车辆只需同步改小自报 σ 即可使残差归零。Auditors **ignore the vehicle-reported σ** and recompute `σ_{v,i}` from the chain-bound `ε_i` plus MEC-published, anchored public round parameters (ρ_v, σ_g, Σ1/ε_j², Δ₂). Otherwise a vehicle understating ε could zero its residual by shrinking its self-reported σ.

4. **车辆层方差按 ε_i 异构分摊 / Heterogeneous variance allocation.** 式15 给出的是车辆层的**总**方差 ρ_v·σ_g²；当式18–20 为各车分配了不同的 ε_i 后，若仍按均匀加噪，则声明的 ε_i 与该车实际噪声强度无关。实现按 `w_i = (1/ε_i²)/Σ(1/ε_j²)` 分摊：预算越紧的车辆承担越大的噪声方差份额，且构造上 `Σσ_{v,i}² = ρ_vσ_g²`，**定理 8 仍以等式成立**；各车 ε 相等时 `w_i = 1/K`，严格退化为式15。Eq. 15 gives the vehicle layer's **total** variance ρ_v·σ_g². Once Eqs. 18–20 assign different ε_i per vehicle, uniform noise would make the declared ε_i unrelated to actual noise strength. The implementation allocates `w_i = (1/ε_i²)/Σ(1/ε_j²)`: vehicles with tighter budgets bear a larger noise-variance share, and by construction `Σσ_{v,i}² = ρ_vσ_g²`, so **Theorem 8 still holds as an equality**; with equal ε_i, `w_i = 1/K` and it reduces strictly to Eq. 15.

5. **式22 的尺度归一化 / Scale normalization of Eq. 22.** 各车噪声强度合法地不同，直接对原始范数施加中位数—MAD 阈值会把高噪声（高隐私要求）的诚实车辆判为异常。实现改为对 `z_i = ‖g_i‖₂ / s_i`（`s_i = √(Δ₂² + d·σ_{v,i}²)`，可由公开参数导出）施加式22；各车尺度相同时常数因子在中位数与 MAD 中同比消去，退化为式22 原式。300 次重复试验显示该通道的误报下降约 63%。Noise strength legitimately varies across vehicles; applying a median–MAD threshold to raw norms would flag high-noise (high-privacy) honest vehicles as anomalies. The implementation applies Eq. 22 to `z_i = ‖g_i‖₂ / s_i` (`s_i = √(Δ₂² + d·σ_{v,i}²)`, derivable from public parameters); with equal scales the constant cancels in both median and MAD, reducing to Eq. 22. 300 repeated trials show a ~63% false-positive reduction for this channel.

6. **策略降级路径 / Policy degradation path.** `policy.select` 采用两级求解：先求目标强度上的最小代价可行解，不可行时退至强度底线 `p_floor(S)` 并对预算封顶，仍不可行才延迟上传。S3 级以 L3 为硬底线，任何情况下不会降至 L2。`policy.select` uses two-level solving: first find the minimum-cost feasible solution at target strength; if infeasible, fall back to the strength floor `p_floor(S)` with a budget cap; only if still infeasible is upload delayed. S3 never degrades below L3.

7. **余弦阈值 θ_c 的标定 / Cosine threshold calibration.** 固定阈值 0.1 与维度无关，模型收敛时两独立向量的余弦近似服从均值 0、方差 1/d 的分布，d=10 时误报率约 38%。`detect.suggest_theta_cos` 按零假设给出 `θ_c = z_α/√d`，实测误报率与设定 α 吻合（5.05% vs 5%）。界面中 θ_c 填 0 即自动标定（默认）。The fixed 0.1 is dimension-independent; near convergence, cosines of two independent vectors follow mean 0, variance 1/d, giving ~38% false positives at d=10. `detect.suggest_theta_cos` computes `θ_c = z_α/√d` under the null hypothesis; measured FPR matches the target (5.05% vs 5%). Setting θ_c to 0 in the GUI enables auto-calibration (default).

8. **多轮准入取较紧的组合界 / Tighter composition bound for admission.** 两者都是对同一累计损耗的合法上界，`budget.composition_bound` 取二者较小者作为准入依据（仍是合法上界且更紧）。例如 ε₀=2.0、T=30 时采用基本组合得 ε_total=60，而非高级组合的 485。Both bounds are valid upper bounds on the same cumulative loss; `budget.composition_bound` takes the smaller one (still valid, but tighter). E.g. at ε₀=2.0, T=30, the basic composition gives ε_total=60 instead of the advanced bound's 485.

9. **信誉加权与隐私核算的关系 / Reputation weighting and privacy accounting.** 定理 8 的核算针对"求和"模型；模型更新使用的信誉加权平均是同一批含噪上传的后处理，由差分隐私的后处理不变性，隐私保证不受影响。Theorem 8 accounts for the "sum" model; the reputation-weighted average used for model updates is post-processing of the same noisy uploads, so the DP guarantee is unaffected by post-processing invariance.

---

## 六、典型运行结果 / Typical Results

默认参数（20 车 / 2 RSU / d=10 / ε_g=2.0 / 30 轮）下 / With defaults (20 vehicles / 2 RSUs / d=10 / ε_g=2.0 / 30 rounds):

- 模型误差：2.76 → 0.26（含三层 DP 噪声）/ Model error: 2.76 → 0.26 (with three-layer DP noise)
- 定理 8 核验：`Σσ_{v,i}² + R·σ_r² + σ_m² = σ_g² = 5.868035`，异构分摊下等式仍成立 / Theorem 8 holds as an equality even under heterogeneous allocation
- 式16 层间视角：`ε_RSU` 与闭式 `ε_g√(K/ρ_v)` 完全一致 / Eq. 16 view matches the closed form exactly
- 综合检出率约 81%，误报率约 5%（θ_c 自动标定，与设定 α=5% 吻合）/ Overall detection ~81%, FPR ~5% (auto-calibrated θ_c matches α=5%)
- **审计条件检出率 100%**：一旦对违规车辆执行审计，检出概率为 1（定理 7）/ **100% conditional audit detection**: once a violating vehicle is audited, detection probability is 1 (Theorem 7)

分通道检出归属（典型一次运行）/ Per-channel detection attribution (typical run):

| 攻击类型 / Attack | 样本 / N | (a)链 / chain | (b)范数 / norm | (c)余弦 / cosine | (d)审计 / audit |
|---|---|---|---|---|---|
| 篡改链上记录 / Tamper on-chain record | 30 | **30** | 3 | 0 | 30 |
| 重放历史记录 / Replay historical record | 30 | **29** | 1 | 0 | 29 |
| 超大范数投毒 / Huge-norm poisoning | 30 | 0 | **30** | 0 | 30 |
| 少加噪声(虚标ε) / Noise under-injection (fake ε) | 30 | 0 | 0 | 0 | **13** |
| 以加噪为名的定向投毒 / Directed poisoning disguised as noise | 30 | 0 | 1 | 10 | **15** |

该表是核心结论的实证：**"少加噪"与"伪装投毒"在链通道上完全无异常表现，只有链态耦合带来的门限追责审计能够稳定检出**；其整体检出率等于抽检率，而条件检出率恒为 1（`python run.py --cli` 可复现）。
This table empirically supports the core claim: **noise under-injection and disguised poisoning show no anomaly on the chain channel at all — only the threshold accountability audit enabled by chain-state coupling can reliably detect them**; overall detection equals the audit sampling rate, while conditional detection is always 1 (reproducible with `python run.py --cli`).

---

## 七、免责说明 / Disclaimer

本程序为技术方案的可运行原型，用于验证公式自洽性与机制可行性。其中门限同态加密、安全多方计算与零知识证明部分按设计文档 4.4 节以承诺—开示流程做了简化占位；若要用于实车部署，需替换为经认证的国密算法库与密码硬件，并按 GB/T 38635—2020 等标准完成合规性测评。

This program is a runnable prototype of a technical scheme, intended to validate formula consistency and mechanism feasibility. Threshold homomorphic encryption, secure multi-party computation and zero-knowledge proofs are simplified as commitment–disclosure placeholders per §4.4 of the design document. For real vehicle deployment, they must be replaced with certified national-cryptography libraries and cryptographic hardware, with compliance testing per GB/T 38635—2020 and related standards.

---

## 八、许可 / License

本仓库未指定许可证。No license is specified in this repository.
