# -*- coding: utf-8 -*-
"""Shamir (t, n) 门限秘密分享，用于车辆根密钥 k_v 的审计委员会托管。

对应定理7：
  (i) 追责：不少于 t 个成员可经拉格朗日插值重构 k_v；
  (ii) 保密：任意少于 t 个份额对 k_v 信息论上零泄露。

有限域取梅森素数 p = 2^521 − 1 > 2^256，可完整容纳 256 比特根密钥。
"""

from __future__ import annotations

import os
from typing import List, Sequence, Tuple

PRIME = (1 << 521) - 1     # 第 13 个梅森素数


def _eval_poly(coeffs: Sequence[int], x: int, p: int = PRIME) -> int:
    """Horner 法求多项式在 x 处的值（模 p）。"""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def split_secret(secret: bytes, t: int, n: int, p: int = PRIME) -> List[Tuple[int, int]]:
    """将 secret 分为 n 份，任意 t 份可重构。返回 [(x_i, y_i)]。"""
    if not 2 <= t <= n:
        raise ValueError("须满足 2 ≤ t ≤ n")
    s = int.from_bytes(secret, 'big')
    if s >= p:
        raise ValueError("秘密过大，超出有限域")
    # a_0 = s，其余系数取自真随机源
    coeffs = [s] + [int.from_bytes(os.urandom(66), 'big') % p for _ in range(t - 1)]
    return [(i, _eval_poly(coeffs, i, p)) for i in range(1, n + 1)]


def reconstruct(shares: Sequence[Tuple[int, int]], length: int = 32,
                p: int = PRIME) -> bytes:
    """拉格朗日插值在 x=0 处重构秘密（定理7-i）。"""
    if not shares:
        raise ValueError("份额为空")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("份额横坐标重复")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % p
            den = (den * (xi - xj)) % p
        term = yi * num * pow(den, p - 2, p)      # 费马小定理求逆元
        secret = (secret + term) % p
    return secret.to_bytes(length, 'big')


class AuditCommittee:
    """审计委员会：持有 k_v 的 (t, n) 份额，达到门限方可重构。"""

    def __init__(self, k_v: bytes, t: int = 3, n: int = 5,
                 members: Sequence[str] = ()):
        self.t, self.n = t, n
        self.members = list(members) if members else [
            "监管机构", "MEC运营方", "整车企业", "第三方审计", "保险机构"][:n]
        self._shares = split_secret(k_v, t, n)

    def share_of(self, idx: int) -> Tuple[int, int]:
        return self._shares[idx]

    def reconstruct(self, member_idx: Sequence[int], length: int = 32) -> bytes:
        """由指定成员集合尝试重构；不足门限时抛出异常（定理7-ii）。"""
        if len(set(member_idx)) < self.t:
            raise PermissionError(
                "参与成员 %d 名，未达门限 t=%d，对 k_v 零泄露" % (len(set(member_idx)), self.t))
        picked = [self._shares[i] for i in sorted(set(member_idx))[:self.t]]
        return reconstruct(picked, length)
