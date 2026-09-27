#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

BANNER_1 = b"PaCKeD By"
BANNER_2 = b"TEDSUO II"
BANNER_3 = b"[TED/UCF]"


def u16(b: bytes | bytearray, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def p16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


def mz_file_size(buf: bytes) -> int:
    cblp = u16(buf, 2)
    cp = u16(buf, 4)
    if cp == 0:
        return 0
    return (cp - 1) * 512 + (cblp if cblp else 512)


def parse_outer_mz(buf: bytes) -> dict[str, int]:
    if len(buf) < 0x1C or buf[:2] != b"MZ":
        raise ValueError("input is not a DOS executable???")

    h = {
        "cblp": u16(buf, 2),
        "cp": u16(buf, 4),
        "crlc": u16(buf, 6),
        "cparhdr": u16(buf, 8),
        "minalloc": u16(buf, 0x0A),
        "maxalloc": u16(buf, 0x0C),
        "ss": u16(buf, 0x0E),
        "sp": u16(buf, 0x10),
        "ip": u16(buf, 0x14),
        "cs": u16(buf, 0x16),
        "lfarlc": u16(buf, 0x18),
    }
    h["header_bytes"] = h["cparhdr"] * 16
    h["entry_file"] = h["header_bytes"] + h["cs"] * 16 + h["ip"]
    return h


def validate_sample(buf: bytes, h: dict[str, int]) -> None:
    if mz_file_size(buf) != len(buf):
        raise ValueError("outer header size field does not match real size???")
    if not all(x in buf[:0x80] for x in (BANNER_1, BANNER_2, BANNER_3)):
        raise ValueError("TEDSUO II [TED/UCF] banner not found???")

    expected = {
        "crlc": 0,
        "cparhdr": 8,
        "ss": 0x081E,
        "sp": 0x0B6C,
        "ip": 0x0000,
        "cs": 0x0602,
    }
    for k, v in expected.items():
        if h[k] != v:
            raise ValueError(
                f"unsupported TED/UCF variant: outer {k}={h[k]:04X}, "
                f"expected {v:04X}???"
            )

    if h["entry_file"] != 0x60A0:
        raise ValueError("unexpected outer entry-point file offset???")
    if len(buf) < 0x680D:
        raise ValueError("file is shorter than this wrapper variant requires???")


def decrypt_stage1_tail(buf: bytearray) -> None:
    base = 0x61F5
    count = 0x186
    for i in range(count):
        o = base + i * 4
        ax = u16(buf, o)
        bx = u16(buf, o + 2)

        ax = (ax + 1) & 0xFFFF
        ax = (ax + 1) & 0xFFFF
        bx = (bx + 1) & 0xFFFF
        ax = (ax - 0x08D0) & 0xFFFF
        ax, bx = bx, ax
        ax = (ax + 0xD058) & 0xFFFF
        ax = (ax + 0xE961) & 0xFFFF
        ax = (ax + 1) & 0xFFFF
        ax = (ax + 1) & 0xFFFF
        bx ^= ax

        al, ah = ax & 0xFF, (ax >> 8) & 0xFF
        bl, bh = bx & 0xFF, (bx >> 8) & 0xFF
        al, bh = bh, al
        ax = (ah << 8) | al
        bx = (bh << 8) | bl
        ax = (ax + 1) & 0xFFFF

        buf[o : o + 2] = p16(ax)
        buf[o + 2 : o + 4] = p16(bx)

    if buf[0x61F5:0x61FD] != bytes.fromhex("e4 21 1e 34 03 8c cb e8"):
        raise ValueError("stage-1 decryption did not produce the expected loader???")


def decrypt_stage2_block(buf: bytearray) -> None:
    lo = 0x62B6
    hi = 0x680A
    if hi - lo + 1 != 0x555:
        raise AssertionError

    bh = 0x6A
    bl = 0x1B
    for o in range(hi, lo - 1, -1):
        al = buf[o]
        al = (al + bh) & 0xFF
        al = (al * bl) & 0xFF
        buf[o] = al
        bh = (bh + 0xC8) & 0xFF

    if buf[lo : lo + 8] != bytes.fromhex("fa fc 33 db 58 8e c3 89"):
        raise ValueError("stage-2 decryption did not produce the expected loader???")


def decrypt_load_image(original: bytes, h: dict[str, int]) -> bytes:
    load_off = h["header_bytes"]
    enc_len = h["cs"] * 16 + h["ip"]
    if enc_len != 0x6020 or enc_len & 1:
        raise ValueError("unexpected encrypted load-image length???")

    out = bytearray(original[load_off : load_off + enc_len])
    bx = 0x41B0
    for o in range(0, len(out), 2):
        ax = u16(out, o)
        ax = (ax + bx) & 0xFFFF
        ax = (ax * 0x9F3D) & 0xFFFF
        out[o : o + 2] = p16(ax)
        bx = (bx + 0xE749) & 0xFFFF

    if b"PKLITE Copr. " not in out:
        raise ValueError("load-image decryption failed PKLITE plaintext check???")
    return bytes(out)


def backward_lz_expand(plain_packed: bytes) -> tuple[bytes, dict[str, int]]:
    src = 0x6017
    dst_end = 0x81D9

    mem = bytearray(0x10000)
    mem[: len(plain_packed)] = plain_packed
    dst = dst_end

    literals = escaped_ff = refs = ref_bytes = 0

    while src >= 0:
        a = mem[src]
        src -= 1

        if a != 0xFF:
            mem[dst] = a
            dst -= 1
            literals += 1
            continue

        if src < 0:
            raise ValueError("truncated FF escape at start of stream???")
        b = mem[src]
        src -= 1

        if b == 0xFF:
            mem[dst] = 0xFF
            dst -= 1
            escaped_ff += 1
            continue

        if src < 0:
            raise ValueError("truncated back-reference at start of stream???")
        n = mem[src]
        src -= 1
        distance = 0xFF - b
        if distance == 0:
            raise ValueError("invalid zero-distance back-reference???")

        refs += 1
        ref_bytes += n
        for _ in range(n):
            ref = dst + distance
            if not (0 <= ref < len(mem)):
                raise ValueError("back-reference outside reconstructed memory???")
            mem[dst] = mem[ref]
            dst -= 1

    image_start = dst + 1
    if image_start != 0x1000:
        raise ValueError(
            f"unexpected decompressed image start {image_start:04X}; expected 1000??"
        )

    image = bytes(mem[image_start : dst_end + 1])
    if len(image) != 0x71DA:
        raise ValueError(
            f"unexpected decompressed image size {len(image):04X}; expected 71DA???"
        )

    stats = {
        "literals": literals,
        "escaped_ff": escaped_ff,
        "backrefs": refs,
        "backref_bytes": ref_bytes,
        "image_size": len(image),
    }
    return image, stats


def recover_metadata(stage2: bytes) -> tuple[list[tuple[int, int]], int, int, int, int]:
    count = u16(stage2, 0x6566)
    if count != 49:
        raise ValueError(f"unexpected relocation count {count}; expected 49???")

    relocs: list[tuple[int, int]] = []
    pos = 0x6568
    for _ in range(count):
        off = u16(stage2, pos)
        seg = u16(stage2, pos + 2)
        relocs.append((off, seg))
        pos += 4

    if stage2[0x6478] != 0xEA:
        raise ValueError("original-entry far jump not found???")
    ip = u16(stage2, 0x6479)
    cs = 0
    if stage2[0x6455] != 0xB8 or stage2[0x645D] != 0xBC:
        raise ValueError("original stack setup not found???")
    ss = u16(stage2, 0x6456)
    sp = u16(stage2, 0x645E)

    if (ip, cs, ss, sp) != (0x38DC, 0, 0x10B8, 0x0800):
        raise ValueError("unexpected reconstructed entry/stack values???")
    return relocs, ip, cs, ss, sp


def build_mz(
    image: bytes,
    relocs: list[tuple[int, int]],
    ip: int,
    cs: int,
    ss: int,
    sp: int,
) -> bytes:
    lfarlc = 0x1C
    header_bytes = lfarlc + len(relocs) * 4
    header_bytes = (header_bytes + 15) & ~15
    cparhdr = header_bytes // 16

    image_paras = (len(image) + 15) // 16
    stack_top_paras = ss + ((sp + 15) // 16)
    minalloc = max(0, stack_top_paras - image_paras)
    maxalloc = 0xFFFF

    total = header_bytes + len(image)
    cp = (total + 511) // 512
    cblp = total & 0x1FF
    if cblp == 0:
        cblp = 0

    hdr = bytearray(header_bytes)
    struct.pack_into(
        "<14H",
        hdr,
        0,
        0x5A4D,
        cblp,
        cp,
        len(relocs),
        cparhdr,
        minalloc,
        maxalloc,
        ss,
        sp,
        0,
        ip,
        cs,
        lfarlc,
        0,
    )

    p = lfarlc
    for off, seg in relocs:
        struct.pack_into("<HH", hdr, p, off, seg)
        p += 4

    exe = bytes(hdr) + image
    if mz_file_size(exe) != len(exe):
        raise AssertionError("internal error constructing MZ size fields???")
    return exe


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Unpack TEDSUO II [TED/UCF] packed DOS PKLITE executable"
    )
    ap.add_argument("input", type=Path, help="packed DOS EXE")
    ap.add_argument("-o", "--output", type=Path, default=None, help="output EXE")
    ap.add_argument(
        "--dump-intermediates",
        action="store_true",
        help="also write decrypted loader/payload/image files",
    )
    ns = ap.parse_args()

    original = ns.input.read_bytes()
    h = parse_outer_mz(original)
    validate_sample(original, h)

    stages = bytearray(original)
    decrypt_stage1_tail(stages)
    decrypt_stage2_block(stages)

    plain_packed = decrypt_load_image(original, h)
    image, stats = backward_lz_expand(plain_packed)
    relocs, ip, cs, ss, sp = recover_metadata(stages)

    if ip >= len(image):
        raise ValueError("recovered entry point is outside decompressed image???")
    for off, seg in relocs:
        linear = seg * 16 + off
        if linear + 1 >= len(image):
            raise ValueError(f"relocation {seg:04X}:{off:04X} is outside image???")

    exe = build_mz(image, relocs, ip, cs, ss, sp)
    out = ns.output or ns.input.with_name(ns.input.stem + "-unpacked.exe")
    out.write_bytes(exe)

    if ns.dump_intermediates:
        stem = out.with_suffix("")
        stem.with_name(stem.name + "-stages.bin").write_bytes(stages)
        stem.with_name(stem.name + "-decrypted-packed.bin").write_bytes(plain_packed)
        stem.with_name(stem.name + "-image.bin").write_bytes(image)

    print(f"Input SHA-256 : {hashlib.sha256(original).hexdigest()}")
    print(f"Output        : {out}")
    print(f"Output size   : {len(exe)} bytes")
    print(f"Image size    : {len(image)} bytes (0x{len(image):04X})")
    print(f"Entry         : {cs:04X}:{ip:04X}")
    print(f"Stack         : {ss:04X}:{sp:04X}")
    print(f"Relocations   : {len(relocs)}")
    print(f"LZ literals   : {stats['literals']} + {stats['escaped_ff']} escaped FF")
    print(
        f"LZ backrefs   : {stats['backrefs']} ({stats['backref_bytes']} bytes copied)"
    )
    print(f"Output SHA-256: {hashlib.sha256(exe).hexdigest()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)
