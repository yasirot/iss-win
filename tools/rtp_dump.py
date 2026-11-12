"""ISS_RTP_DUMPのファイルを読む。メインディスプレイのHEVCピクチャを完成した順に、
各ピクチャのDONL、POC、参照セットとともに並べ、その間にこちらが送った
RTCPフィードバックを挟んで出す。

    python tools/rtp_dump.py dump.bin [--from-ms N] [--to-ms N]

レコードの形式（session.cppのdump_packet）。u8のkind（0は受信、1はこちらのRTCP、
2は受信したがISS_LOSS_PERMILLEで捨てたもの）、0を3バイト、u32 LEの
長さ、i64 LEのマイクロ秒。その後にペイロードを復号したRTPパケット、
または平文のRTCPが続く。

AppleはRFC 7798どおりではない。どのペイロードもNALヘッダーの後ろ
（フラグメントではFUヘッダーの後ろ）にDONLを持ち、aggregation packetは
DONLを1つだけ持ってDONDを持たない。
"""
from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field

RX, TX, LOST = 0, 1, 2


# ── ビットストリーム ────────────────────────────────────────────────────

def unescape(b: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    for x in b:
        if zeros >= 2 and x == 3:
            zeros = 0
            continue
        out.append(x)
        zeros = zeros + 1 if x == 0 else 0
    return bytes(out)


class Bits:
    def __init__(self, data: bytes):
        self.d = data
        self.pos = 0

    def u(self, n: int) -> int:
        v = 0
        for _ in range(n):
            byte = self.d[self.pos >> 3]
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def ue(self) -> int:
        z = 0
        while self.u(1) == 0:
            z += 1
        return (1 << z) - 1 + self.u(z)


def ceil_log2(n: int) -> int:
    return (n - 1).bit_length() if n > 1 else 0


# ── HEVCのパラメーターセットとスライスヘッダー（H.265 §7.3） ────────────

@dataclass
class StRps:
    s0: list = field(default_factory=list)  # (delta, used)。近いものから順に
    s1: list = field(default_factory=list)


def st_ref_pic_set(b: Bits, idx: int, num: int, sets: list) -> StRps:
    if idx != 0 and b.u(1):  # inter_ref_pic_set_prediction_flag (§7.4.8)
        delta_idx = b.ue() + 1 if idx == num else 1
        sign = b.u(1)
        delta_rps = (1 - 2 * sign) * (b.ue() + 1)
        ref = sets[idx - delta_idx]
        n = len(ref.s0) + len(ref.s1)
        used, use = [], []
        for _ in range(n + 1):
            u = b.u(1)
            used.append(u)
            use.append(1 if u else b.u(1))
        out = StRps()
        nn = len(ref.s0)
        for j in range(len(ref.s1) - 1, -1, -1):
            d = ref.s1[j][0] + delta_rps
            if d < 0 and use[nn + j]:
                out.s0.append((d, bool(used[nn + j])))
        if delta_rps < 0 and use[n]:
            out.s0.append((delta_rps, bool(used[n])))
        for j in range(nn):
            d = ref.s0[j][0] + delta_rps
            if d < 0 and use[j]:
                out.s0.append((d, bool(used[j])))
        for j in range(nn - 1, -1, -1):
            d = ref.s0[j][0] + delta_rps
            if d > 0 and use[j]:
                out.s1.append((d, bool(used[j])))
        if delta_rps > 0 and use[n]:
            out.s1.append((delta_rps, bool(used[n])))
        for j in range(len(ref.s1)):
            d = ref.s1[j][0] + delta_rps
            if d > 0 and use[nn + j]:
                out.s1.append((d, bool(used[nn + j])))
        return out
    out = StRps()
    neg, pos = b.ue(), b.ue()
    d = 0
    for _ in range(neg):
        d -= b.ue() + 1
        out.s0.append((d, bool(b.u(1))))
    d = 0
    for _ in range(pos):
        d += b.ue() + 1
        out.s1.append((d, bool(b.u(1))))
    return out


def skip_ptl(b: Bits, sub_layers_minus1: int) -> int:
    b.u(88)
    level = b.u(8)
    prof, lev = [], []
    for _ in range(sub_layers_minus1):
        prof.append(b.u(1))
        lev.append(b.u(1))
    if sub_layers_minus1 > 0:
        b.u(2 * (8 - sub_layers_minus1))
    for i in range(sub_layers_minus1):
        if prof[i]:
            b.u(88)
        if lev[i]:
            b.u(8)
    return level


@dataclass
class Sps:
    width: int = 0
    height: int = 0
    chroma: int = 0
    log2_poc: int = 4
    sets: list = field(default_factory=list)
    lt_present: bool = False
    lt_sps: list = field(default_factory=list)  # (poc_lsb, used)
    tmvp: bool = False
    ctb_log2: int = 4
    separate_colour: bool = False


def parse_sps(nal: bytes) -> Sps:
    b = Bits(unescape(nal[2:]))
    s = Sps()
    b.u(4)
    sub = b.u(3)
    b.u(1)
    skip_ptl(b, sub)
    b.ue()
    s.chroma = b.ue()
    if s.chroma == 3:
        s.separate_colour = bool(b.u(1))
    s.width, s.height = b.ue(), b.ue()
    if b.u(1):
        for _ in range(4):
            b.ue()
    b.ue(), b.ue()
    s.log2_poc = b.ue() + 4
    present = b.u(1)
    for _ in range(0 if present == 0 else sub, sub + 1):
        b.ue(), b.ue(), b.ue()
    min_cb = b.ue() + 3
    s.ctb_log2 = min_cb + b.ue()
    b.ue(), b.ue(), b.ue(), b.ue()
    if b.u(1) and b.u(1):
        raise ValueError("SPS scaling lists are not handled")
    b.u(1)  # amp
    b.u(1)  # sao
    if b.u(1):  # pcm
        b.u(4), b.u(4), b.ue(), b.ue(), b.u(1)
    n = b.ue()
    for i in range(n):
        s.sets.append(st_ref_pic_set(b, i, n, s.sets))
    s.lt_present = bool(b.u(1))
    if s.lt_present:
        for _ in range(b.ue()):
            s.lt_sps.append((b.u(s.log2_poc), bool(b.u(1))))
    s.tmvp = bool(b.u(1))
    return s


@dataclass
class Pps:
    dependent_slices: bool = False
    output_flag: bool = False
    extra_bits: int = 0


def parse_pps(nal: bytes) -> Pps:
    b = Bits(unescape(nal[2:]))
    b.ue(), b.ue()
    p = Pps()
    p.dependent_slices = bool(b.u(1))
    p.output_flag = bool(b.u(1))
    p.extra_bits = b.u(3)
    return p


@dataclass
class Slice:
    nal_type: int
    first: bool
    slice_type: int = -1
    poc_lsb: int = 0
    rps: StRps | None = None
    rps_idx: int = -1  # 使ったSPSのセット。-1はスライス内で符号化したもの
    lt: list = field(default_factory=list)  # (poc_lsb, used, msb_cycleかNone)


def parse_slice(nal: bytes, sps: Sps, pps: Pps) -> Slice:
    t = (nal[0] >> 1) & 0x3F
    b = Bits(unescape(nal[2:min(len(nal), 64)]))
    s = Slice(t, bool(b.u(1)))
    if 16 <= t <= 23:
        b.u(1)
    b.ue()
    if not s.first:
        if pps.dependent_slices and b.u(1):
            return s
        ctb = 1 << sps.ctb_log2
        b.u(ceil_log2(((sps.width + ctb - 1) // ctb) * ((sps.height + ctb - 1) // ctb)))
    b.u(pps.extra_bits)
    s.slice_type = b.ue()
    if pps.output_flag:
        b.u(1)
    if sps.separate_colour:
        b.u(2)
    if t in (19, 20):
        return s
    s.poc_lsb = b.u(sps.log2_poc)
    if not b.u(1):
        s.rps = st_ref_pic_set(b, len(sps.sets), len(sps.sets), sps.sets)
    else:
        s.rps_idx = b.u(ceil_log2(len(sps.sets))) if len(sps.sets) > 1 else 0
        s.rps = sps.sets[s.rps_idx]
    if sps.lt_present:
        n_sps = b.ue() if sps.lt_sps else 0
        n_pics = b.ue()
        for i in range(n_sps + n_pics):
            if i < n_sps:
                idx = b.u(ceil_log2(len(sps.lt_sps))) if len(sps.lt_sps) > 1 else 0
                lsb, used = sps.lt_sps[idx]
            else:
                lsb, used = b.u(sps.log2_poc), bool(b.u(1))
            msb = b.ue() if b.u(1) else None
            s.lt.append((lsb, used, msb))
    return s


# ── RTP ─────────────────────────────────────────────────────────────────

@dataclass
class Rtp:
    t_ms: float
    kind: int
    ssrc: int
    seq: int
    ts: int
    marker: bool
    ext: tuple | None
    payload: bytes


def parse_rtp(t_ms: float, kind: int, p: bytes) -> Rtp | None:
    if len(p) < 12:
        return None
    cc = p[0] & 0x0F
    hdr = 12 + 4 * cc
    ext = None
    if p[0] & 0x10:
        prof, words = struct.unpack(">HH", p[hdr:hdr + 4])
        ext = (prof, p[hdr + 4:hdr + 4 + 4 * words].hex())
        hdr += 4 + 4 * words
    seq, ts, ssrc = struct.unpack(">HII", p[2:12])
    return Rtp(t_ms, kind, ssrc, seq, ts, bool(p[1] & 0x80), ext, p[hdr:])


def donl_of(pay: bytes) -> int | None:
    if len(pay) < 4:
        return None
    if (pay[0] >> 1) & 0x3F == 49:
        return struct.unpack(">H", pay[3:5])[0] if len(pay) >= 5 else None
    return struct.unpack(">H", pay[2:4])[0]


def reassemble(payloads: list) -> list:
    out, fu = [], None
    for pay in payloads:
        if len(pay) < 2:
            continue
        nt = (pay[0] >> 1) & 0x3F
        if nt == 48:
            pos = 4
            while pos + 2 <= len(pay):
                size = struct.unpack(">H", pay[pos:pos + 2])[0]
                pos += 2
                if size == 0 or pos + size > len(pay):
                    break
                out.append(pay[pos:pos + size])
                pos += size
        elif nt == 49:
            if len(pay) < 6:
                continue
            h = pay[2]
            if h & 0x80:
                fu = bytearray([(pay[0] & 0x81) | ((h & 0x3F) << 1), pay[1]]) + pay[5:]
            elif fu is not None:
                fu += pay[5:]
                if h & 0x40:
                    out.append(bytes(fu))
                    fu = None
        elif len(pay) >= 4:
            out.append(pay[:2] + pay[4:])
    return out


def describe_rtcp(p: bytes) -> str:
    parts, pos = [], 0
    while pos + 4 <= len(p):
        fmt, pt = p[pos] & 0x1F, p[pos + 1]
        n = (struct.unpack(">H", p[pos + 2:pos + 4])[0] + 1) * 4
        body = p[pos:pos + n]
        if pt == 192:
            parts.append(f"legacyFIR 0x{struct.unpack('>I', body[4:8])[0]:08x}")
        elif pt == 200:
            parts.append("SR")
        elif pt == 201:
            parts.append(f"RR({fmt})" if fmt else "RR")
        elif pt == 204:
            name = body[8:12]
            val = struct.unpack(">I", body[12:16])[0] if len(body) >= 16 else None
            parts.append(f"LTR ack {val}" if name == b"\0\0\0\x05" else f"APP/{fmt} {name!r} {val}")
        elif pt == 205:
            ssrc, pid, blp = struct.unpack(">IHH", body[8:16])
            parts.append(f"NACK 0x{ssrc:08x} {pid}+{blp:04x}")
        elif pt == 206:
            target = struct.unpack(">I", body[8:12])[0]
            if fmt == 4:
                target = struct.unpack(">I", body[12:16])[0]
            parts.append(f"{'FIR' if fmt == 4 else 'PLI' if fmt == 1 else f'PSFB{fmt}'} 0x{target:08x}")
        else:
            parts.append(f"PT{pt}")
        pos += n
    return " + ".join(parts)


# ── main ────────────────────────────────────────────────────────────────

def read_records(path: str):
    with open(path, "rb") as f:
        data = f.read()
    pos = 0
    while pos + 16 <= len(data):
        kind = data[pos]
        n, us = struct.unpack("<Iq", data[pos + 4:pos + 16])
        yield kind, us / 1000.0, data[pos + 16:pos + 16 + n]
        pos += 16 + n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--from-ms", type=float, default=0)
    ap.add_argument("--to-ms", type=float, default=1e18)
    ap.add_argument("--rr", action="store_true", help="also list plain receiver reports")
    args = ap.parse_args()

    groups: dict = {}
    order: list = []  # (t_ms, kind, item)
    for kind, t, p in read_records(args.dump):
        if kind == TX:
            order.append((t, "tx", p))
            continue
        r = parse_rtp(t, kind, p)
        if r is None:
            continue
        key = (r.ssrc, r.ts)
        if key not in groups:
            groups[key] = []
            order.append((t, "au", key))
        groups[key].append(r)

    # SSRCごとのタイル番号。連続したSSRCが1ストリームの4タイルになる。
    ssrcs = sorted({k[0] for k in groups})
    tile = {}
    base = None
    for s in ssrcs:
        if base is None or s - base > 3:
            base = s
        tile[s] = (base, s - base)

    vps = sps = pps = None
    prev_msb = prev_lsb = 0
    seen = {}  # poc → donl
    lost_pocs = set()
    stats = defaultdict(int)
    for t, what, item in order:
        if what == "tx":
            text = describe_rtcp(item)
            if text in ("RR", "SR + RR") and not args.rr:
                continue
            if args.from_ms <= t <= args.to_ms:
                print(f"{t:10.1f}  >> {text}")
            continue
        pkts = groups[item]
        first = pkts[0].seq
        pkts.sort(key=lambda r: (r.seq - first + 0x8000) & 0xFFFF)
        seqs = [r.seq for r in pkts]
        holes = sum(((b - a) & 0xFFFF) - 1 for a, b in zip(seqs, seqs[1:]))
        lost = sum(1 for r in pkts if r.kind == LOST)
        marker = any(r.marker for r in pkts)
        payloads = [r.payload for r in pkts if r.kind == RX]
        donl = next((d for d in (donl_of(r.payload) for r in pkts) if d is not None), None)
        nals = reassemble([r.payload for r in pkts])
        size = sum(len(r.payload) for r in pkts)
        exts = sorted({r.ext[1] for r in pkts if r.ext})
        base_ssrc, ti = tile[item[0]]
        desc = []
        for nal in nals:
            nt = (nal[0] >> 1) & 0x3F
            try:
                if nt == 32:
                    vps = nal
                    desc.append("VPS")
                elif nt == 33:
                    sps = parse_sps(nal)
                    desc.append(f"SPS {sps.width}x{sps.height} c{sps.chroma} poc{sps.log2_poc}b "
                                f"rps{len(sps.sets)} lt{int(sps.lt_present)}/{len(sps.lt_sps)} tmvp{int(sps.tmvp)}")
                elif nt == 34:
                    pps = parse_pps(nal)
                    desc.append("PPS")
                elif nt <= 31 and sps and pps:
                    sl = parse_slice(nal, sps, pps)
                    if not sl.first:
                        desc.append(f"slice+ t{nt}")
                        continue
                    if nt in (19, 20):
                        poc = 0
                        prev_msb = prev_lsb = 0
                    else:
                        half = 1 << (sps.log2_poc - 1)
                        lsb = sl.poc_lsb
                        if lsb < prev_lsb and prev_lsb - lsb >= half:
                            msb = prev_msb + (1 << sps.log2_poc)
                        elif lsb > prev_lsb and lsb - prev_lsb > half:
                            msb = prev_msb - (1 << sps.log2_poc)
                        else:
                            msb = prev_msb
                        poc = msb + lsb
                        if nt % 2 == 1 or nt >= 16:  # サブレイヤー非参照ピクチャではない
                            prev_msb, prev_lsb = msb, lsb
                    refs = []
                    if sl.rps:
                        for d, used in sl.rps.s0 + sl.rps.s1:
                            mark = "" if used else "~"
                            miss = "?" if used and poc + d not in seen else ""
                            refs.append(f"{mark}{poc + d}{miss}")
                    lts = [f"LT{'' if u else '~'}{lsb}{'' if m is None else f'm{m}'}" for lsb, u, m in sl.lt]
                    kind = {19: "IDR", 20: "IDR", 21: "CRA", 1: "TRAIL_R", 0: "TRAIL_N"}.get(nt, f"t{nt}")
                    rps_src = f"sps#{sl.rps_idx}" if sl.rps_idx >= 0 else "own"
                    desc.append(f"{kind} {'IPB'[2 - sl.slice_type] if 0 <= sl.slice_type <= 2 else '?'} "
                                f"poc {poc} refs [{' '.join(refs)}]{' ' + ' '.join(lts) if lts else ''} ({rps_src})")
                    if lost or holes:
                        lost_pocs.add(poc)
                    else:
                        seen[poc] = donl
                    stats["slices"] += 1
                    stats["lt" if sl.lt else "st"] += 1
                else:
                    desc.append(f"t{nt}")
            except (IndexError, ValueError) as e:
                desc.append(f"t{nt} (parse: {e})")
        if args.from_ms <= t <= args.to_ms:
            flags = ("LOST " * bool(lost)) + ("HOLE " * bool(holes)) + ("" if marker else "NOMARK ")
            print(f"{t:10.1f}  {base_ssrc & 0xFFFF:04x}.{ti} ts {item[1]:10d} donl {donl if donl is not None else '-':>5} "
                  f"{len(pkts):3d}p {size:7d}B {flags}{' | '.join(desc)}{'  ext ' + ','.join(exts) if exts else ''}")
    print(f"\nslices {stats['slices']}, with long-term refs {stats['lt']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
