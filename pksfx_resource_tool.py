#!/usr/bin/env python3
# pksfx_resource_tool.py
# Copyright (c) 1995-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
# Copyright (c) 2023-2026 Jason Summers <jason1@pobox.com>
# SPDX-License-Identifer: MIT
# scspell-id: aef58b52-bb51-11f1-ae98-80ee73e9b8e7

from __future__ import annotations

import argparse
import binascii
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

FINGERPRINT_NBYTES = 16384
EXPECTED_HANDLER = bytes.fromhex(
    "8b dc 1e 9c 33 d2 91 58 50 25 ff fd 50 b8 10 00 "
    "ba 20 00 0e 52 cf 9a 94 c5 5f 04 8e d2 f6 c1 01"
)


@dataclass(frozen=True)
class ResourceSpec:
    item_id: str
    endpos: int
    length: int
    bshift: int = 4


@dataclass(frozen=True)
class Profile:
    file_id: str
    fingerprint: int
    resources: tuple[ResourceSpec, ...]
    code_end: int | None = None


def R(item_id: str, endpos: int, length: int, bshift: int = 4) -> ResourceSpec:
    return ResourceSpec(item_id, endpos, length, bshift)


# Resource layouts from Jason Summers' `pkstrings.py`

PROFILES = (
    Profile(
        "zipsfx2.04c",
        0xDE4CABEC,
        (
            R("reg_info", 15538, 450),
            R("intro", 15713, 173),
            R("terms", 16344, 630),
            R("usage", 16975, 629),
        ),
    ),
    Profile(
        "zipsfx2.04c-reg",
        0xFB93F922,
        (
            R("reg_info", 15075, 227),
            R("intro", 15251, 175),
            R("terms", 15729, 477),
            R("usage", 16359, 629),
        ),
    ),
    Profile(
        "zipsfx2.04e",
        0x72B5183A,
        (
            R("reg_info", 15906, 450),
            R("intro", 16081, 173),
            R("terms", 16712, 630),
            R("usage", 17343, 629),
        ),
    ),
    Profile(
        "zipsfx2.04e-reg",
        0x6A2AAD04,
        (
            R("reg_info", 15443, 227),
            R("intro", 15619, 175),
            R("terms", 16097, 477),
            R("usage", 16727, 629),
        ),
    ),
    Profile(
        "zipsfx2.04g",
        0xFAE98B00,
        (
            R("reg_info", 15906, 450),
            R("intro", 16081, 173),
            R("terms", 16712, 630),
            R("usage", 17343, 629),
        ),
        code_end=18898,
    ),
    Profile(
        "zipsfx2.04g-swmkt",
        0xC720B5AA,
        (
            R("reg_info", 16074, 650),
            R("intro", 16249, 173),
            R("terms", 16880, 630),
            R("usage", 17511, 629),
        ),
    ),
    Profile(
        "zipsfx2.04g-reg",
        0xAD5AA1CF,
        (
            R("reg_info", 15443, 227),
            R("intro", 15619, 175),
            R("terms", 16097, 477),
            R("usage", 16727, 629),
        ),
        code_end=18530,
    ),
    Profile(
        "zipsfx2.04g-reg-swmkt",
        0xA451D121,
        (
            R("reg_info", 15421, 237),
            R("intro", 15597, 175),
            R("terms", 16075, 477),
            R("usage", 16705, 629),
        ),
    ),
    Profile(
        "pksfx2.49",
        0x94FDB73C,
        (
            R("reg_info", 17452, 300),
            R("intro", 17627, 173),
            R("terms", 18269, 641),
            R("usage", 18899, 629),
        ),
    ),
    Profile(
        "zipsfx2.50",
        0x50B92554,
        (
            R("reg_info", 17150, 606),
            R("intro", 17329, 178),
            R("terms", 17807, 477),
            R("usage", 18438, 630),
        ),
    ),
    Profile(
        "zipsfx2.50-reg",
        0xF6690492,
        (
            R("contact", 16777, 233),
            R("intro", 16955, 178),
            R("terms+reg_info", 17587, 631),
            R("usage", 18218, 630),
        ),
    ),
)
PROFILE_BY_FP = {p.fingerprint: p for p in PROFILES}


@dataclass(frozen=True)
class ExeInfo:
    code_start: int
    code_end: int
    entry_rel: int
    fingerprint: int


@dataclass(frozen=True)
class Resource:
    item_id: str
    file_offset: int
    decoded_size: int
    encoded_size: int
    bshift: int
    state: str


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def s16(data: bytes, off: int) -> int:
    x = u16(data, off)
    return x - 0x10000 if x >= 0x8000 else x


def parse_exe(data: bytes) -> ExeInfo:
    if len(data) < 64 or data[:2] not in (b"MZ", b"ZM"):
        raise ValueError("not an MZ executable")
    e_cblp = u16(data, 2)
    e_cp = u16(data, 4)
    code_start = u16(data, 8) * 16
    code_end = 512 * e_cp if e_cblp == 0 else 512 * (e_cp - 1) + e_cblp
    if code_start < 64 or code_start > len(data):
        raise ValueError("invalid MZ header size")
    if code_end > len(data) or code_end < code_start:
        raise ValueError("truncated or invalid MZ load image")
    entry_rel = 16 * s16(data, 22) + u16(data, 20)
    code = data[code_start:code_end]
    nfp = min(len(code), FINGERPRINT_NBYTES)
    if entry_rel < nfp and entry_rel < len(code) and entry_rel + 20 >= len(code):
        nfp = entry_rel
    fp = binascii.crc32(code[:nfp]) & 0xFFFFFFFF
    return ExeInfo(code_start, code_end, entry_rel, fp)


def resource_start(info: ExeInfo, spec: ResourceSpec) -> int:
    return info.code_start + spec.endpos - spec.length


def decode_resource(data: bytes, info: ExeInfo, spec: ResourceSpec) -> bytes:
    start = resource_start(info, spec)
    n = spec.length
    if spec.bshift == 0:
        need = n
    else:
        need = n + 1
    if start < info.code_start or start + need > info.code_end:
        raise ValueError(f"{spec.item_id}: resource extends beyond load image")
    x = bytearray(need)
    key = n & 0xFF
    for i in range(need):
        x[i] = data[start + i] ^ key
        key = (key - 1) & 0xFF
    if spec.bshift == 0:
        return bytes(x[:n])
    out = bytearray(n)
    for i in range(n):
        out[i] = ((x[i] << spec.bshift) & 0xFF) | (x[i + 1] >> (8 - spec.bshift))
    return bytes(out)


def encode_resource(plain: bytes, original: bytes, spec: ResourceSpec) -> bytes:
    n = spec.length
    if len(plain) != n:
        raise ValueError(
            f"{spec.item_id}: replacement length is {len(plain)} bytes; {n} bytes are required"
        )
    if spec.bshift != 4:
        raise ValueError(f"{spec.item_id}: encoder currently supports bshift=4 only")
    if len(original) < n + 1:
        raise ValueError(f"{spec.item_id}: encoded resource is truncated")

    orig_x = bytearray(original[: n + 1])
    key = n & 0xFF
    for i in range(n + 1):
        orig_x[i] ^= key
        key = (key - 1) & 0xFF

    q = bytearray(n + 1)
    q[0] = orig_x[0] & 0xF0
    q[n] = orig_x[n] & 0x0F
    for i, p in enumerate(plain):
        q[i] = (q[i] & 0xF0) | ((p >> 4) & 0x0F)
        q[i + 1] = (q[i + 1] & 0x0F) | ((p & 0x0F) << 4)

    enc = bytearray(n + 1)
    key = n & 0xFF
    for i in range(n + 1):
        enc[i] = q[i] ^ key
        key = (key - 1) & 0xFF
    return bytes(enc)


def intro_plaintext_runtime_patch(data: bytes, profile: Profile) -> bool:
    if profile.file_id not in ("zipsfx2.04g", "zipsfx2.04g-reg"):
        return False
    return (
        data[0x129C : 0x129C + 15] == b"\x90" * 15
        and data[0x12D5:0x12D8] == b"\xb8\x00\x00"
    )


def detect_profile(data: bytes, info: ExeInfo) -> tuple[Profile, str]:
    p = PROFILE_BY_FP.get(info.fingerprint)
    if p is not None:
        return p, "fingerprint"
    for p in PROFILES:
        if p.code_end != info.code_end:
            continue
        h = data.find(
            EXPECTED_HANDLER,
            info.code_start,
            min(info.code_end, info.code_start + 0x5000),
        )
        if h >= 0:
            return p, "2.04g layout fallback"
    raise ValueError(f"unrecognized PKSFX stub (fingerprint 0x{info.fingerprint:08X})")


def detect_resources(data: bytes, info: ExeInfo, profile: Profile) -> list[Resource]:
    intro_plain = intro_plaintext_runtime_patch(data, profile)
    resources: list[Resource] = []
    for spec in profile.resources:
        start = resource_start(info, spec)
        encoded_size = spec.length + (1 if spec.bshift else 0)
        if start < info.code_start or start + encoded_size > info.code_end:
            raise ValueError(f"{spec.item_id}: resource location is outside load image")
        state = "plaintext" if spec.item_id == "intro" and intro_plain else "encoded"
        resources.append(
            Resource(spec.item_id, start, spec.length, encoded_size, spec.bshift, state)
        )
    return resources


def resource_plain(
    data: bytes, info: ExeInfo, profile: Profile, spec: ResourceSpec
) -> bytes:
    start = resource_start(info, spec)
    if spec.item_id == "intro" and intro_plaintext_runtime_patch(data, profile):
        return data[start : start + spec.length]
    return decode_resource(data, info, spec)


def printable_score(buf: bytes) -> float:
    if not buf:
        return 0.0
    good = sum(1 for b in buf if b in (0, 9, 10, 13) or 32 <= b <= 126 or b >= 0x80)
    return good / len(buf)


def verify_decoded(spec: ResourceSpec, plain: bytes) -> None:
    if len(plain) != spec.length:
        raise ValueError(f"{spec.item_id}: wrong decoded length")
    if printable_score(plain) < 0.80:
        print(
            f"warning: {spec.item_id} has unexpectedly little printable text",
            file=sys.stderr,
        )


def find_spec(profile: Profile, item_id: str) -> ResourceSpec:
    for spec in profile.resources:
        if spec.item_id == item_id:
            return spec
    raise ValueError(f"{profile.file_id}: no resource named {item_id!r}")


def cmd_info(args: argparse.Namespace) -> int:
    data = args.input.read_bytes()
    info = parse_exe(data)
    profile, detected_by = detect_profile(data, info)
    resources = detect_resources(data, info, profile)
    print(f"file: {args.input}")
    print(f"file id: {profile.file_id}")
    print(f"detected by: {detected_by}")
    print(f"fingerprint: 0x{info.fingerprint:08X}")
    print(f"load image: 0x{info.code_start:04X}-0x{info.code_end:04X}")
    print()
    print("resource          file-off  encoded  decoded  shift  state")
    print("----------------  --------  -------  -------  -----  ---------")
    for r in resources:
        print(
            f"{r.item_id:<16}  0x{r.file_offset:06X}  {r.encoded_size:7d}  "
            f"{r.decoded_size:7d}  {r.bshift:5d}  {r.state}"
        )
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    data = args.input.read_bytes()
    info = parse_exe(data)
    profile, _ = detect_profile(data, info)
    args.output.mkdir(parents=True, exist_ok=True)
    for spec in profile.resources:
        plain = resource_plain(data, info, profile, spec)
        verify_decoded(spec, plain)
        path = args.output / f"{spec.item_id}.txt"
        path.write_bytes(plain)
        print(
            f"{spec.item_id}: {len(plain)} bytes -> {path} "
            f"(file offset 0x{resource_start(info, spec):06X})"
        )
    return 0

def collect_replacements(args: argparse.Namespace) -> dict[str, Path]:
    repl: dict[str, Path] = {}
    for name, path in args.replace or []:
        repl[name] = path
    for name in ("reg_info", "intro", "terms", "usage"):
        path = getattr(args, name, None)
        if path is not None:
            repl[name] = path
    if not repl:
        raise ValueError("no replacements specified")
    return repl


def cmd_patch(args: argparse.Namespace) -> int:
    data = args.input.read_bytes()
    info = parse_exe(data)
    profile, _ = detect_profile(data, info)
    replacements = collect_replacements(args)
    output = bytearray(data)
    intro_plain = intro_plaintext_runtime_patch(data, profile)

    for name, path in replacements.items():
        spec = find_spec(profile, name)
        plain = path.read_bytes()
        if len(plain) != spec.length:
            raise ValueError(
                f"{name}: replacement length is {len(plain)} bytes; {spec.length} bytes are required"
            )
        start = resource_start(info, spec)
        if name == "intro" and intro_plain:
            output[start : start + spec.length] = plain
            check = bytes(output[start : start + spec.length])
        else:
            old = data[start : start + spec.length + 1]
            enc = encode_resource(plain, old, spec)
            output[start : start + len(enc)] = enc
            check = decode_resource(bytes(output), info, spec)
        if check != plain:
            raise ValueError(f"{name}: post-patch verification failed")
        print(f"patched {name}: {path} -> file offset 0x{start:06X}")

    args.output.write_bytes(output)
    print(f"wrote: {args.output}")
    print(f"sha256: {hashlib.sha256(output).hexdigest()}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Inspect and repack PKSFX nibble-shifted text resources using known "
            "pkstrings layouts (2.04c/e/g, 2.49 and 2.50 families)."
        )
    )
    sp = p.add_subparsers(dest="command", required=True)

    pi = sp.add_parser("info", help="show detected resource locations and sizes")
    pi.add_argument("input", type=Path)
    pi.set_defaults(func=cmd_info)

    pd = sp.add_parser("dump", help="decode resources to text files")
    pd.add_argument("input", type=Path)
    pd.add_argument("output", type=Path)
    pd.set_defaults(func=cmd_dump)

    pp = sp.add_parser(
        "patch", help="replace one or more resources and write a new EXE"
    )
    pp.add_argument("input", type=Path)
    pp.add_argument(
        "--reg-info",
        dest="reg_info",
        type=Path,
        help="reg_info replacement",
    )
    pp.add_argument("--intro", type=Path, help="intro/herald replacement")
    pp.add_argument(
        "--terms",
        dest="terms",
        type=Path,
        help="terms replacement",
    )
    pp.add_argument(
        "--usage",
        dest="usage",
        type=Path,
        help="usage replacement",
    )
    pp.add_argument("-o", "--output", required=True, type=Path)
    pp.set_defaults(func=cmd_patch)

    args = p.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
