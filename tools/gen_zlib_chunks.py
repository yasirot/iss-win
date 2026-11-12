"""tests/data/zlib_chunks.binを書き出す。中身はZ_SYNC_FLUSHでチャンクに区切ったzlibストリームで、
RFBのzlib系エンコーディングが1接続につき1本のストリームを送るのと同じ形にしている。

形式はリトルエンディアン。先頭にストリーム数（u32）。各ストリームはチャンク数（u32）に続いてチャンクを並べ、
各チャンクは圧縮後の長さ（u32）、そのバイト列、展開後の長さ（u32）、そのバイト列の順。

チャンクをまたいで同じデータを繰り返し、後方参照が前のチャンクまで届くようにしている。
"""
import os
import random
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "data", "zlib_chunks.bin")


def chunks(level, seed):
    rnd = random.Random(seed)
    words = [bytes(rnd.randrange(256) for _ in range(rnd.randrange(3, 40))) for _ in range(64)]
    plain = []
    for size in (5000, 1, 40000, 300, 8000):
        b = bytearray()
        while len(b) < size:
            b += rnd.choice(words) if rnd.random() < 0.8 else bytes([rnd.randrange(256)])
        plain.append(bytes(b[:size]))
    z = zlib.compressobj(level)
    return [(z.compress(p) + z.flush(zlib.Z_SYNC_FLUSH), p) for p in plain]


streams = [chunks(1, 1), chunks(6, 2), chunks(9, 3)]
with open(OUT, "wb") as f:
    f.write(struct.pack("<I", len(streams)))
    for s in streams:
        f.write(struct.pack("<I", len(s)))
        for comp, plain in s:
            f.write(struct.pack("<I", len(comp)) + comp + struct.pack("<I", len(plain)) + plain)
print(OUT, os.path.getsize(OUT))
