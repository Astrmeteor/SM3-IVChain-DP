# -*- coding: utf-8 -*-
"""规范化序列化：为专利公式中的拼接运算符 ∥ 提供无歧义（prefix-free）实现。

专利式 1、2、3、8、12 中大量使用 A ∥ B ∥ C。直接字节串拼接存在歧义
（("ab","c") 与 ("a","bc") 拼接结果相同），会削弱定理 1 的抗碰撞归约。
本模块对每个分量附加 4 字节大端长度前缀，使编码单射，从而
    SM3(enc(A, B, C))
在密码学意义上严格对应 SM3(A ∥ B ∥ C) 的抗碰撞性论证。
"""

from __future__ import annotations


def u64(n: int) -> bytes:
    """无符号 64 位大端整数编码（用于 ctr、ts、τ 等计数量）。"""
    if n < 0:
        raise ValueError("u64 只接受非负整数")
    return int(n).to_bytes(8, 'big')


def f64(x: float) -> bytes:
    """IEEE-754 双精度大端编码（用于 ε 等实数量，保证可复算）。"""
    import struct
    return struct.pack('>d', float(x))


def _b(x) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, str):
        return x.encode('utf-8')
    if isinstance(x, bool):
        return b'\x01' if x else b'\x00'
    if isinstance(x, int):
        return u64(x)
    if isinstance(x, float):
        return f64(x)
    raise TypeError("不支持的拼接类型: %r" % type(x))


def cat(*parts) -> bytes:
    """规范化拼接 ∥：每个分量以 4 字节大端长度前缀，保证编码单射。"""
    out = bytearray()
    for p in parts:
        bp = _b(p)
        out += len(bp).to_bytes(4, 'big')
        out += bp
    return bytes(out)


def pack_vec(v) -> bytes:
    """将实数向量规范化为字节串，作为链上消息 m_t 的确定性表示。

    审计时车辆开示的 m_t 必须满足 SM3(m_t) = 链上记录的摘要，
    而该摘要已由式2 绑定并逐层锚定，故车辆无法就 m_t 说谎。
    """
    import struct
    return struct.pack('>I', len(v)) + b''.join(struct.pack('>d', float(x)) for x in v)


def unpack_vec(b: bytes):
    """pack_vec 的逆变换。"""
    import struct
    n = struct.unpack('>I', b[:4])[0]
    return [struct.unpack('>d', b[4 + 8 * i:12 + 8 * i])[0] for i in range(n)]
