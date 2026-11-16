# -*- coding: utf-8 -*-
"""实施例一：信标锚定的 SM3 交织双链。

实现公式：
    式1  R_τ   = SM3(R_{τ−1} ∥ τ ∥ ID_RSU ∥ nonce_τ)
    式2  h_t^d = SM3(h_{t−1}^d ∥ SM3(m_t) ∥ ctr_t ∥ ts_t ∥ ID_v ∥ R_{τ(t)} ∥ h_{t−1}^b)
    式3  h_t^b = SM3(h_{t−1}^b ∥ β_t ∥ ctr_t ∥ h_t^d)
以及定理 1（完整性）、定理 2（新鲜性 / 抗重放 / 抗预计算）对应的验证逻辑。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .sm3 import sm3
from .codec import cat, u64, f64


# --------------------------------------------------------------------------
# 信标链（RSU 侧）
# --------------------------------------------------------------------------
@dataclass
class Beacon:
    epoch: int
    rsu_id: str
    value: bytes
    nonce: bytes


class BeaconChain:
    """RSU 逐纪元生成并广播的不可预测信标链（式1）。

    nonce_τ 取自操作系统真随机源 os.urandom，因此 R_τ 在纪元 τ 开始前
    对任何攻击者不可预测 —— 这是定理 2 抗离线预计算部分的前提。
    """

    def __init__(self, rsu_id: str, window: int = 2, genesis: Optional[bytes] = None):
        self.rsu_id = rsu_id
        self.window = int(window)          # 接受窗口：当前纪元向前容忍的纪元数
        self.epoch = 0
        seed = genesis if genesis is not None else sm3(cat(b'BEACON-GENESIS', rsu_id))
        self.head = seed
        self.beacons: Dict[int, Beacon] = {0: Beacon(0, rsu_id, seed, b'')}
        self.anchors: List[tuple] = []     # 向 MEC 锚定的 (epoch, head) 记录

    def next_epoch(self) -> Beacon:
        """推进一个纪元并广播新的信标值（式1）。"""
        self.epoch += 1
        nonce = os.urandom(16)
        value = sm3(cat(self.head, u64(self.epoch), self.rsu_id, nonce))
        b = Beacon(self.epoch, self.rsu_id, value, nonce)
        self.beacons[self.epoch] = b
        self.head = value
        return b

    def current(self) -> Beacon:
        return self.beacons[self.epoch]

    def is_valid(self, epoch: int, value: bytes) -> bool:
        """校验信标值是否为窗口内的合法信标（定理 2 条件 ii）。"""
        if epoch not in self.beacons:
            return False
        if not (self.epoch - self.window <= epoch <= self.epoch):
            return False
        return self.beacons[epoch].value == value

    def anchor_to_mec(self, mec) -> bytes:
        """将信标链链头逐层锚定至 MEC（说明书 1.1 节）。"""
        self.anchors.append((self.epoch, self.head))
        return mec.anchor(self.rsu_id, self.epoch, self.head)

    def verify_chain(self) -> bool:
        """自校验信标链连续性。"""
        prev = self.beacons[0].value
        for e in range(1, self.epoch + 1):
            b = self.beacons[e]
            if sm3(cat(prev, u64(e), b.rsu_id, b.nonce)) != b.value:
                return False
            prev = b.value
        return True


# --------------------------------------------------------------------------
# 行为摘要 β_t
# --------------------------------------------------------------------------
@dataclass
class Behavior:
    """行为摘要 β_t：至少包含策略编号、消耗预算、噪声承诺与证明标识。"""
    policy: str
    epsilon: float
    commit: bytes
    proof_id: bytes = b''

    def encode(self) -> bytes:
        return cat(self.policy, f64(self.epsilon), self.commit, self.proof_id)


# --------------------------------------------------------------------------
# 交织双链（车载端）
# --------------------------------------------------------------------------
@dataclass
class ChainRecord:
    """一条上链记录，携带验证方复算所需的全部公开量。"""
    ctr: int
    ts: int
    vehicle_id: str
    msg_digest: bytes          # SM3(m_t)
    epoch: int
    beacon: bytes              # R_{τ(t)}
    prev_d: bytes
    prev_b: bytes
    h_d: bytes
    h_b: bytes
    beta: Behavior
    payload: object = None     # 上传的（含噪）梯度或统计量，用于审计
    meta: dict = field(default_factory=dict)


class InterwovenChain:
    """数据链与行为链构成的 SM3 交织双链（式2、式3）。

    交织的密码学含义：数据链吸收上一行为链链头，行为链吸收当前数据链链头，
    二链更新函数互为输入，故篡改任一环将同时破坏两条链的后续全部校验关系。
    """

    def __init__(self, vehicle_id: str, reg_ts: int, seed_v: Optional[bytes] = None):
        self.vehicle_id = vehicle_id
        seed_v = seed_v if seed_v is not None else os.urandom(16)
        self.seed_v = seed_v
        # 注册初始化：h_0^d = SM3(ID_v ∥ reg_ts ∥ seed_v)，h_0^b 追加 0x01 域分隔
        self.h_d = sm3(cat(vehicle_id, u64(reg_ts), seed_v))
        self.h_b = sm3(cat(vehicle_id, u64(reg_ts), seed_v, b'\x01'))
        self.ctr = 0
        self.records: List[ChainRecord] = []

    # -- 式2 ---------------------------------------------------------------
    @staticmethod
    def data_head(prev_d: bytes, msg_digest: bytes, ctr: int, ts: int,
                  vid: str, beacon: bytes, prev_b: bytes) -> bytes:
        return sm3(cat(prev_d, msg_digest, u64(ctr), u64(ts), vid, beacon, prev_b))

    # -- 式3 ---------------------------------------------------------------
    @staticmethod
    def behavior_head(prev_b: bytes, beta: Behavior, ctr: int, h_d: bytes) -> bytes:
        return sm3(cat(prev_b, beta.encode(), u64(ctr), h_d))

    def begin_record(self, message: bytes, ts: int, beacon: Beacon):
        """第一步：产生数据链链头 h_t^d（此时噪声尚未生成）。

        返回 (ctr, h_d)。噪声种子随后由 h_d 派生（式8），这一先后次序
        正是定理 6（抗自适应噪声选择）成立的结构性原因。
        """
        self.ctr += 1
        md = sm3(message)
        h_d = self.data_head(self.h_d, md, self.ctr, ts, self.vehicle_id,
                             beacon.value, self.h_b)
        self._pending = dict(ctr=self.ctr, ts=ts, md=md, beacon=beacon,
                             prev_d=self.h_d, prev_b=self.h_b, h_d=h_d)
        return self.ctr, h_d

    def commit_record(self, beta: Behavior, payload=None, meta=None) -> ChainRecord:
        """第二步：写入行为摘要，产生行为链链头 h_t^b，完成本轮上链。"""
        p = self._pending
        h_b = self.behavior_head(p['prev_b'], beta, p['ctr'], p['h_d'])
        rec = ChainRecord(ctr=p['ctr'], ts=p['ts'], vehicle_id=self.vehicle_id,
                          msg_digest=p['md'], epoch=p['beacon'].epoch,
                          beacon=p['beacon'].value, prev_d=p['prev_d'],
                          prev_b=p['prev_b'], h_d=p['h_d'], h_b=h_b,
                          beta=beta, payload=payload, meta=meta or {})
        self.h_d, self.h_b = p['h_d'], h_b
        self.records.append(rec)
        self._pending = None
        return rec


# --------------------------------------------------------------------------
# 验证方（RSU）侧的双链与新鲜性校验
# --------------------------------------------------------------------------
class ChainVerifier:
    """对上传记录执行定理 1（完整性）与定理 2（新鲜性）所要求的校验。"""

    def __init__(self, beacon_chain: BeaconChain):
        self.bc = beacon_chain
        self.last_ctr: Dict[str, int] = {}
        self.expected: Dict[str, tuple] = {}   # vid -> (h_d, h_b) 上一次接受的链头

    def register(self, vid: str, h_d0: bytes, h_b0: bytes):
        self.expected[vid] = (h_d0, h_b0)
        self.last_ctr[vid] = 0

    def verify(self, rec: ChainRecord) -> tuple:
        """返回 (是否通过, 失败原因列表)。"""
        errs = []
        vid = rec.vehicle_id

        # (i) 计数器严格单调递增 —— 定理 2 条件 i，抗重放
        if vid in self.last_ctr and rec.ctr <= self.last_ctr[vid]:
            errs.append("计数器非单调(重放)")

        # (ii) 信标属于当前接受窗口 —— 定理 2 条件 ii，抗跨时段/跨域移植与预计算
        if not self.bc.is_valid(rec.epoch, rec.beacon):
            errs.append("信标不在接受窗口(重放/跨域/预计算)")

        # 链接续性：上一链头须与验证方记录一致
        if vid in self.expected:
            e_d, e_b = self.expected[vid]
            if rec.prev_d != e_d or rec.prev_b != e_b:
                errs.append("链头断裂")

        # (iii) 双链复算 —— 定理 1
        h_d = InterwovenChain.data_head(rec.prev_d, rec.msg_digest, rec.ctr,
                                        rec.ts, vid, rec.beacon, rec.prev_b)
        if h_d != rec.h_d:
            errs.append("数据链复算不符(篡改)")
        h_b = InterwovenChain.behavior_head(rec.prev_b, rec.beta, rec.ctr, rec.h_d)
        if h_b != rec.h_b:
            errs.append("行为链复算不符(篡改)")

        # 噪声承诺存在性
        if not rec.beta.commit:
            errs.append("缺少噪声承诺")

        ok = not errs
        if ok:
            self.last_ctr[vid] = rec.ctr
            self.expected[vid] = (rec.h_d, rec.h_b)
        return ok, errs


class MEC:
    """区域边缘云：接收 RSU 的信标链锚定与聚合结果存证。"""

    def __init__(self, mec_id: str = "MEC-1"):
        self.mec_id = mec_id
        self.anchor_log: List[tuple] = []
        self.head = sm3(cat(b'MEC-GENESIS', mec_id))

    def anchor(self, rsu_id: str, epoch: int, rsu_head: bytes) -> bytes:
        self.head = sm3(cat(self.head, rsu_id, u64(epoch), rsu_head))
        self.anchor_log.append((rsu_id, epoch, rsu_head, self.head))
        return self.head
