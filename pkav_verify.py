#!/usr/bin/env python3
# pkav_verify.py
# Copyright (c) 1995-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
# SPDX-License-Identifier: MIT
# scspell-id: 33662872-bb68-11f1-a745-80ee73e9b8e7

import argparse
import struct
import sys
import zipfile

MASK32 = 0xFFFFFFFF
EF_AV = 0x0007


def make_crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if (c & 1) else 0)
        table.append(c & MASK32)
    return table


CRC_TABLE = make_crc_table()


def crc_byte(crc, c):
    return (CRC_TABLE[(crc ^ c) & 0xFF] ^ (crc >> 8)) & MASK32


def rol32(v, n):
    v &= MASK32
    n &= 31
    if n == 0:
        return v
    return ((v << n) | (v >> (32 - n))) & MASK32


def dos_datetime(zi):
    year, month, day, hour, minute, second = zi.date_time
    date = ((year - 1980) << 9) | (month << 5) | day
    time = (hour << 11) | (minute << 5) | (second // 2)
    return ((date << 16) | time) & MASK32


def av_records(extra):
    out = []
    pos = 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        end = pos + 4 + size
        if end > len(extra):
            raise ValueError("malformed central-directory extra field")
        if tag == EF_AV:
            out.append(extra[pos + 4 : end])
        pos = end
    if pos != len(extra):
        raise ValueError("trailing bytes in central-directory extra field")
    return out


def outer_decode(data):
    n = len(data)
    return bytes(b ^ ((n - i) & 0xFF) for i, b in enumerate(data))


def password_from_accumulator(acc):
    return bytes((((acc >> (4 * i)) & 0x0F) + 0x13) for i in range(8))


def zipcrypto_init(password):
    k0 = 0x12345678
    k1 = 0x23456789
    k2 = 0x34567890

    def update(k0, k1, k2, c):
        k0 = crc_byte(k0, c)
        k1 = (k1 + (k0 & 0xFF)) & MASK32
        k1 = (k1 * 0x08088405 + 1) & MASK32
        k2 = crc_byte(k2, (k1 >> 24) & 0xFF)
        return k0, k1, k2

    for c in password:
        k0, k1, k2 = update(k0, k1, k2, c)
    return k0, k1, k2, update


def zipcrypto_decrypt(data, password):
    k0, k1, k2, update = zipcrypto_init(password)
    out = bytearray()
    for cipher in data:
        t = (k2 | 2) & 0xFFFF
        stream = ((t * (t ^ 1)) >> 8) & 0xFF
        plain = cipher ^ stream
        out.append(plain)
        k0, k1, k2 = update(k0, k1, k2, plain)
    return bytes(out)


def seed_valid(seed):
    if (((seed - 26) & MASK32) % 157) != 0:
        return False
    x = seed
    digit_sum = 0
    for _ in range(10):
        digit_sum += x % 10
        x //= 10
    return digit_sum == 62


def expected_h1(seed, company):
    crc = seed & MASK32
    for c in company:
        crc = crc_byte(crc, c)
    crc = (~crc) & MASK32
    return rol32(crc, seed & 31)


def stamp_from_seed(seed):
    r = rol32(seed, 7)
    letters = (r >> 18) & 0x3FFF
    digits = (r & 0x3FFFF) // 0x107
    return "".join(
        (
            chr(ord("A") + letters // 676),
            chr(ord("A") + (letters // 26) % 26),
            chr(ord("A") + letters % 26),
            chr(ord("0") + digits // 100),
            chr(ord("0") + (digits // 10) % 10),
            chr(ord("0") + digits % 10),
        )
    )


def read_member_ignoring_stored_crc(zf, zi):
    f = zf.open(zi, "r")
    if hasattr(f, "_expected_crc"):
        f._expected_crc = None
    try:
        crc = 0
        sum16 = 0
        xor8 = 0
        while True:
            block = f.read(65536)
            if not block:
                break
            import zlib

            crc = zlib.crc32(block, crc)
            sum16 = (sum16 + sum(block)) & 0xFFFF
            for b in block:
                xor8 ^= b
        return crc & MASK32, sum16, xor8
    finally:
        f.close()


def verify(path, verbose=False):
    av_count = 0
    av_payload = None
    initial_acc = 0
    final_acc = 0
    marked = []
    zip_crc_ok = True

    with zipfile.ZipFile(path, "r") as zf:
        for zi in zf.infolist():
            if not (zi.internal_attr & 0x0006):
                continue

            recs = av_records(zi.extra)
            av_count += len(recs)
            if recs:
                av_payload = recs[-1]

            initial_acc = (initial_acc + zi.CRC) & MASK32
            if zi.internal_attr & 0x0004:
                initial_acc = (initial_acc + zi.external_attr) & MASK32
            else:
                initial_acc = (initial_acc + dos_datetime(zi)) & MASK32

            actual_crc, sum16, xor8 = read_member_ignoring_stored_crc(zf, zi)
            if actual_crc != zi.CRC:
                zip_crc_ok = False

            final_acc = (final_acc + actual_crc) & MASK32
            if zi.internal_attr & 0x0004:
                actual_aux = (
                    (xor8 << 24) | (sum16 << 8) | (zi.external_attr & 0xFF)
                ) & MASK32
                final_acc = (final_acc + actual_aux) & MASK32
            else:
                actual_aux = None
                final_acc = (final_acc + dos_datetime(zi)) & MASK32

            marked.append((zi, actual_crc, sum16, xor8, actual_aux))

    if not marked:
        return {
            "status": "NO_PKAV",
            "reason": "no DOS-host central entry has internal attributes & 0x0006",
            "zip_crc_ok": zip_crc_ok,
        }

    if av_count != 1 or av_payload is None:
        return {
            "status": "FAIL",
            "reason": "expected exactly one EF_AV (0x0007) record, found %d" % av_count,
            "initial_acc": initial_acc,
            "final_acc": final_acc,
            "zip_crc_ok": zip_crc_ok,
        }

    if len(av_payload) < 14:
        return {
            "status": "FAIL",
            "reason": "AV payload shorter than 14 bytes (12-byte header + nonempty NUL-terminated company)",
            "initial_acc": initial_acc,
            "final_acc": final_acc,
            "zip_crc_ok": zip_crc_ok,
        }

    password = password_from_accumulator(final_acc)
    decoded = outer_decode(av_payload)
    plain = zipcrypto_decrypt(decoded, password)

    opaque, h1, seed = struct.unpack_from("<III", plain, 0)
    rest = plain[12:]
    nul = rest.find(b"\0")
    if nul <= 0:
        return {
            "status": "FAIL",
            "reason": "decrypted company name is empty or lacks a NUL terminator",
            "initial_acc": initial_acc,
            "final_acc": final_acc,
            "password": password,
            "plain": plain,
            "zip_crc_ok": zip_crc_ok,
        }

    company = rest[:nul]
    tail = rest[nul + 1 :]
    expect = expected_h1(seed, company)
    s_ok = seed_valid(seed)
    h_ok = h1 == expect

    reason = None
    if not s_ok:
        reason = "seed validation failed"
    elif not h_ok:
        reason = "company authentication dword mismatch"

    result = {
        "status": "PASS" if reason is None else "FAIL",
        "reason": reason,
        "initial_acc": initial_acc,
        "final_acc": final_acc,
        "password": password,
        "payload": av_payload,
        "plain": plain,
        "opaque": opaque,
        "h1": h1,
        "expected_h1": expect,
        "seed": seed,
        "company": company,
        "tail": tail,
        "stamp": stamp_from_seed(seed),
        "seed_ok": s_ok,
        "h1_ok": h_ok,
        "zip_crc_ok": zip_crc_ok,
        "marked": marked,
    }
    return result


def printable_company(b):
    return b.decode("cp437", errors="replace")


def main():
    ap = argparse.ArgumentParser(
        description="verify PKZIP 2.x Authenticity Verification data"
    )
    ap.add_argument("zipfile", nargs="+")
    ap.add_argument("-v", "--verbose", action="store_true")
    ns = ap.parse_args()
    overall = 0

    for path in ns.zipfile:
        try:
            r = verify(path, ns.verbose)
        except Exception as exc:
            print("%s: ERROR: %s" % (path, exc))
            overall = 2
            continue

        print("%s: %s" % (path, r["status"]))
        if r.get("reason"):
            print("  reason: %s" % r["reason"])
        if "final_acc" in r:
            print(
                "  accumulator: initial=%08x final=%08x"
                % (r["initial_acc"], r["final_acc"])
            )
        if "seed" in r:
            print(
                "  decrypted: opaque=%08x h1=%08x seed=%08x"
                % (r["opaque"], r["h1"], r["seed"])
            )
            print("  expected H1: %08x" % r["expected_h1"])
            print("  company: %r" % printable_company(r["company"]))
            print("  AV stamp: %s" % r["stamp"])
            print(
                "  seed check: %s; company check: %s; AV-member CRCs: %s"
                % (
                    "ok" if r["seed_ok"] else "FAIL",
                    "ok" if r["h1_ok"] else "FAIL",
                    "ok" if r["zip_crc_ok"] else "FAIL",
                )
            )
            if ns.verbose:
                print("  password bytes: %s" % r["password"].hex())
                print("  EF_AV payload: %s" % r["payload"].hex())
                print("  decrypted AV: %s" % r["plain"].hex())
                if r["tail"]:
                    print("  tail: %s" % r["tail"].hex())
        if r["status"] == "FAIL":
            overall = max(overall, 1)
        print()

    return overall


if __name__ == "__main__":
    sys.exit(main())
