#!/usr/bin/env python3
# pksfx_text_tool.py
# Copyright (c) 1995-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
# Copyright (c) 2023-2026 Jason Summers <jason1@pobox.com>
# SPDX-License-Identifier: MIT
# scspell-id: b7805b76-bb51-11f1-a02b-80ee73e9b8e7

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

FINGERPRINT_NBYTES = 16384

# Fingerprints and locations are from Jason Summers' `pkstrings.py`
# NOTE: In-place patching limited to 2.04g only at this time.


@dataclass(frozen=True)
class ItemSpec:
    item_id: str
    name: str
    endpos: int
    length: int
    bshift: int


@dataclass(frozen=True)
class Profile:
    file_id: str
    fingerprint: int
    items: tuple[ItemSpec, ...]
    patch_family: str | None = None
    code_end: int | None = None


def I(item_id: str, name: str, endpos: int, length: int, bshift: int) -> ItemSpec:
    return ItemSpec(item_id, name, endpos, length, bshift)


PROFILES = (
    Profile(
        "zipsfx2.04c",
        0xDE4CABEC,
        (
            I("intro", "intro", 15713, 173, 4),
            I("strings_1", "main_messages", 17740, 686, 0),
            I("strings_2", "error_messages", 17912, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.04c-reg",
        0xFB93F922,
        (
            I("intro", "intro", 15251, 175, 4),
            I("strings_1", "main_messages", 17380, 686, 0),
            I("strings_2", "error_messages", 17552, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.04e",
        0x72B5183A,
        (
            I("intro", "intro", 16081, 173, 4),
            I("strings_1", "main_messages", 18108, 686, 0),
            I("strings_2", "error_messages", 18306, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.04e-reg",
        0x6A2AAD04,
        (
            I("intro", "intro", 15619, 175, 4),
            I("strings_1", "main_messages", 17748, 686, 0),
            I("strings_2", "error_messages", 17946, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.04g",
        0xFAE98B00,
        (
            I("intro", "intro", 16081, 173, 4),
            I("strings_1", "main_messages", 18108, 686, 0),
            I("strings_2", "error_messages", 18306, 152, 0),
        ),
        patch_family="2.04g",
        code_end=18898,
    ),
    Profile(
        "zipsfx2.04g-swmkt",
        0xC720B5AA,
        (
            I("intro", "intro", 16249, 173, 4),
            I("strings_1", "main_messages", 18284, 686, 0),
            I("strings_2", "error_messages", 18482, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.04g-reg",
        0xAD5AA1CF,
        (
            I("intro", "intro", 15619, 175, 4),
            I("strings_1", "main_messages", 17748, 686, 0),
            I("strings_2", "error_messages", 17946, 152, 0),
        ),
        patch_family="2.04g",
        code_end=18530,
    ),
    Profile(
        "zipsfx2.04g-reg-swmkt",
        0xA451D121,
        (
            I("intro", "intro", 15597, 175, 4),
            I("strings_1", "main_messages", 17732, 686, 0),
            I("strings_2", "error_messages", 17930, 152, 0),
        ),
    ),
    Profile(
        "pksfx2.49",
        0x94FDB73C,
        (
            I("intro", "intro", 17627, 173, 4),
            I("strings_1", "main_messages", 19684, 686, 0),
            I("strings_2", "error_messages", 19836, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.50",
        0x50B92554,
        (
            I("intro", "intro", 17329, 178, 4),
            I("strings_1", "main_messages", 19821, 779, 0),
            I("strings_2", "error_messages", 19974, 152, 0),
        ),
    ),
    Profile(
        "zipsfx2.50-reg",
        0xF6690492,
        (
            I("intro", "intro", 16955, 178, 4),
            I("strings_1", "main_messages", 19597, 779, 0),
            I("strings_2", "error_messages", 19750, 152, 0),
        ),
    ),
)

PROFILE_BY_FP = {p.fingerprint: p for p in PROFILES}

EXPECTED_HANDLER = bytes.fromhex(
    "8b dc 1e 9c 33 d2 91 58 50 25 ff fd 50 b8 10 00 "
    "ba 20 00 0e 52 cf 9a 94 c5 5f 04 8e d2 f6 c1 01"
)
DISPLAY_DECODER_PREFIX = bytes.fromhex(
    "55 8b ec 56 b1 08 2a 4e 04 c4 76 08 8b 6e 06 fc 26 ad 86 e0 d3 e8"
)


@dataclass(frozen=True)
class ExeInfo:
    code_start: int
    code_end: int
    entry_rel: int
    fingerprint: int


@dataclass(frozen=True)
class PatchSites:
    string_sites: tuple[
        tuple[int, int, int], ...
    ]  # offset, byte length, decoded length
    intro_xor_site: tuple[int, int]
    intro_shift_site: int
    display_decoder_file: int


def die(msg: str) -> None:
    raise SystemExit("error: " + msg)


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def s16(data: bytes, off: int) -> int:
    x = u16(data, off)
    return x - 0x10000 if x >= 0x8000 else x


def parse_exe(data: bytes) -> ExeInfo:
    if len(data) < 64 or data[:2] not in (b"MZ", b"ZM"):
        die("input is not an MZ executable")
    e_cblp = u16(data, 2)
    e_cp = u16(data, 4)
    e_cparhdr = u16(data, 8)
    code_start = e_cparhdr * 16
    code_end = 512 * e_cp if e_cblp == 0 else 512 * (e_cp - 1) + e_cblp
    if code_start < 64 or code_start > len(data):
        die("invalid MZ header size")
    if code_end > len(data) or code_end < code_start:
        die("truncated or invalid MZ load image")
    entry_rel = 16 * s16(data, 22) + u16(data, 20)
    code = data[code_start:code_end]
    nfp = min(len(code), FINGERPRINT_NBYTES)
    if entry_rel < nfp and entry_rel < len(code) and entry_rel + 20 >= len(code):
        nfp = entry_rel
    fp = binascii.crc32(code[:nfp]) & 0xFFFFFFFF
    return ExeInfo(code_start, code_end, entry_rel, fp)


def item_start(info: ExeInfo, item: ItemSpec) -> int:
    return info.code_start + item.endpos - item.length


def decode_item(data: bytes, info: ExeInfo, item: ItemSpec) -> bytes:
    start = item_start(info, item)
    need = item.length + (1 if item.bshift else 0)
    if start < info.code_start or start + need > info.code_end:
        die(f"{item.name} extends beyond the MZ load image")
    x = bytearray(need)
    key = item.length & 0xFF
    for i in range(need):
        x[i] = data[start + i] ^ key
        key = (key - 1) & 0xFF
    if item.bshift == 0:
        return bytes(x)
    out = bytearray(item.length)
    for i in range(item.length):
        out[i] = ((x[i] << item.bshift) & 0xFF) | (x[i + 1] >> (8 - item.bshift))
    return bytes(out)


def raw_item(data: bytes, info: ExeInfo, item: ItemSpec) -> bytes:
    start = item_start(info, item)
    end = start + item.length
    if start < 0 or end > len(data):
        die(f"{item.name} extends beyond end of file")
    return data[start:end]


def stock_plain_prefix(item: ItemSpec) -> bytes:
    if item.item_id == "intro":
        return b"\r\nPKSFX"
    if item.item_id == "strings_1":
        return b"PKSFX:"
    if item.item_id == "strings_2":
        return b"*.*\x00"
    return b""


def runtime_plaintext_patched(data: bytes, profile: Profile) -> bool:
    if profile.patch_family != "2.04g":
        return False
    return (
        data[0x127C : 0x127C + 13] == b"\x90" * 13
        and data[0x1289 : 0x1289 + 14] == b"\x90" * 14
        and data[0x129C : 0x129C + 15] == b"\x90" * 15
        and data[0x12D5:0x12D8] == b"\xb8\x00\x00"
    )


def looks_plain(
    data: bytes, info: ExeInfo, item: ItemSpec, profile: Profile | None = None
) -> bool:
    if profile is not None and runtime_plaintext_patched(data, profile):
        return True
    pfx = stock_plain_prefix(item)
    return bool(pfx) and raw_item(data, info, item).startswith(pfx)


def looks_encoded(data: bytes, info: ExeInfo, item: ItemSpec) -> bool:
    pfx = stock_plain_prefix(item)
    if not pfx:
        return True
    try:
        return decode_item(data, info, item).startswith(pfx)
    except SystemExit:
        return False


def fallback_profile(data: bytes, info: ExeInfo) -> Profile | None:
    for p in PROFILES:
        if p.patch_family != "2.04g" or p.code_end != info.code_end:
            continue
        h = data.find(
            EXPECTED_HANDLER,
            info.code_start,
            min(info.code_end, info.code_start + 0x5000),
        )
        if h < 0:
            continue
        return p
    return None


def detect_profile(data: bytes, info: ExeInfo) -> tuple[Profile, str]:
    p = PROFILE_BY_FP.get(info.fingerprint)
    if p is not None:
        return p, "fingerprint"
    p = fallback_profile(data, info)
    if p is not None:
        return p, "2.04g layout fallback"
    known = ", ".join(p.file_id for p in PROFILES)
    die(
        f"unrecognized PKSFX stub (fingerprint 0x{info.fingerprint:08X}); "
        f"known layouts: {known}"
    )


def dump_blocks(data: bytes, info: ExeInfo, profile: Profile, outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    manifest = {
        "file_id": profile.file_id,
        "fingerprint": f"0x{info.fingerprint:08X}",
        "input_size": len(data),
        "code_start": info.code_start,
        "code_end": info.code_end,
        "blocks": [],
    }
    for item in profile.items:
        plain = (
            raw_item(data, info, item)
            if looks_plain(data, info, item, profile)
            else decode_item(data, info, item)
        )
        start = item_start(info, item)
        bin_path = os.path.join(outdir, item.name + ".bin")
        txt_path = os.path.join(outdir, item.name + ".txt")
        with open(bin_path, "wb") as f:
            f.write(plain)
        with open(txt_path, "wb") as f:
            f.write(plain)
        manifest["blocks"].append(
            {
                "name": item.name,
                "pkstrings_id": item.item_id,
                "file_offset": start,
                "length": item.length,
                "bshift": item.bshift,
                "state": (
                    "plaintext" if looks_plain(data, info, item, profile) else "encoded"
                ),
                "binary": os.path.basename(bin_path),
                "text": os.path.basename(txt_path),
            }
        )
        print(
            f"{item.name}: pkstrings={item.item_id}, offset=0x{start:X}, "
            f"length=0x{item.length:X}, bshift={item.bshift}"
        )
        print(f"  -> {txt_path}")
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="ascii") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def find_string_xor_sites(
    data: bytes, info: ExeInfo, lengths: set[int]
) -> list[tuple[int, int, int]]:
    hits: list[tuple[int, int, int]] = []
    start = info.code_start
    end = min(info.code_end, info.code_start + 0x2000)
    for i in range(start, max(start, end - 14)):
        # Form used for one block: ... CALL FAR [BP-6]
        if (
            data[i] == 0xB8
            and data[i + 3 : i + 5] == b"\x1e\x50"
            and data[i + 5] == 0x2D
            and data[i + 8 : i + 10] == b"\xf7\xd8"
            and data[i + 10 : i + 13] == b"\xff\x5e\xfa"
        ):
            a = u16(data, i + 1)
            b = u16(data, i + 6)
            n = (b - a) & 0xFFFF
            if n in lengths:
                hits.append((i, 13, n))
        if (
            data[i] == 0xB8
            and data[i + 3 : i + 5] == b"\x1e\x50"
            and data[i + 5] == 0x2D
            and data[i + 8 : i + 10] == b"\xf7\xd8"
            and data[i + 10 : i + 12] == b"\xff\x1e"
        ):
            a = u16(data, i + 1)
            b = u16(data, i + 6)
            n = (b - a) & 0xFFFF
            if n in lengths:
                hits.append((i, 14, n))
    return hits


def find_intro_xor_site(data: bytes, info: ExeInfo, intro: ItemSpec) -> tuple[int, int]:
    target = item_start(info, intro)
    hits: list[tuple[int, int]] = []
    start = info.code_start
    end = min(info.code_end, info.code_start + 0x2000)
    for i in range(start, max(start, end - 15)):
        if not (
            data[i] == 0xB8
            and data[i + 3] == 0xB9
            and data[i + 6 : i + 8] == b"\x51\x50"
            and data[i + 8] == 0xA1
            and data[i + 11 : i + 13] == b"\xff\x1e"
        ):
            continue
        off = u16(data, i + 1)
        seg = u16(data, i + 4)
        if info.code_start + seg * 16 + off == target:
            hits.append((i, 15))
    if len(hits) != 1:
        die(f"could not uniquely identify intro XOR setup (found {len(hits)})")
    return hits[0]


def find_intro_shift_site(data: bytes, info: ExeInfo, after: int) -> tuple[int, int]:
    hits: list[tuple[int, int]] = []
    end = min(info.code_end, after + 0x80)
    for i in range(after, max(after, end - 12)):
        if not (
            data[i : i + 4] == b"\xb8\x04\x00\x50"
            and data[i + 4] == 0xB8
            and data[i + 7] == 0xA3
            and data[i + 10 : i + 12] == b"\xff\xd0"
        ):
            continue
        target = u16(data, i + 5)
        target_file = info.code_start + target
        if (
            data[target_file : target_file + len(DISPLAY_DECODER_PREFIX)]
            != DISPLAY_DECODER_PREFIX
        ):
            continue
        hits.append((i, target_file))
    if len(hits) != 1:
        die(
            f"could not uniquely identify intro display decoder setup (found {len(hits)})"
        )
    return hits[0]


def locate_patch_sites(data: bytes, info: ExeInfo, profile: Profile) -> PatchSites:
    if profile.patch_family != "2.04g":
        die(
            f"{profile.file_id} is supported for inspection/dumping, but in-place "
            "plaintext patching has only been verified for the ordinary 2.04g "
            "Shareware and Registered stubs"
        )
    intro = next(i for i in profile.items if i.item_id == "intro")
    strings = [i for i in profile.items if i.item_id in ("strings_1", "strings_2")]
    lengths = {i.length for i in strings}
    shits = find_string_xor_sites(data, info, lengths)
    by_len = {n: [] for n in lengths}
    for hit in shits:
        by_len[hit[2]].append(hit)
    if any(len(v) != 1 for v in by_len.values()):
        counts = ", ".join(f"{n}:{len(v)}" for n, v in sorted(by_len.items()))
        die(f"could not uniquely identify strings XOR setup ({counts})")
    string_sites = tuple(by_len[n][0] for n in sorted(by_len))
    intro_xor = find_intro_xor_site(data, info, intro)
    shift_off, display_file = find_intro_shift_site(
        data, info, intro_xor[0] + intro_xor[1]
    )
    return PatchSites(string_sites, intro_xor, shift_off, display_file)


def simulate_display_plain(data: bytes, start: int, length: int) -> bytes:
    if start + length + 1 > len(data):
        die("intro display simulation would read beyond end of file")
    return bytes(data[start : start + length])


def patch_image(data: bytes, info: ExeInfo, profile: Profile) -> tuple[bytes, dict]:
    plains: dict[str, bytes] = {}
    for item in profile.items:
        plains[item.item_id] = (
            raw_item(data, info, item)
            if looks_plain(data, info, item, profile)
            else decode_item(data, info, item)
        )

    out = bytearray(data)
    report: dict[str, object] = {
        "file_id": profile.file_id,
        "blocks": [],
        "patches": [],
    }

    all_plain = all(looks_plain(data, info, item, profile) for item in profile.items)
    if all_plain:
        report["already_plaintext"] = True
        return bytes(out), report

    sites = locate_patch_sites(data, info, profile)

    for item in profile.items:
        start = item_start(info, item)
        plain = plains[item.item_id]
        out[start : start + item.length] = plain
        report["blocks"].append(
            {
                "name": item.name,
                "pkstrings_id": item.item_id,
                "file_offset": start,
                "length": item.length,
                "bshift": item.bshift,
            }
        )

    for off, plen, n in sites.string_sites:
        old = bytes(out[off : off + plen])
        out[off : off + plen] = b"\x90" * plen
        report["patches"].append(
            {
                "kind": "disable_strings_xor",
                "file_offset": off,
                "length": plen,
                "decoded_length": n,
                "old": old.hex(),
            }
        )

    ixoff, ixlen = sites.intro_xor_site
    old = bytes(out[ixoff : ixoff + ixlen])
    out[ixoff : ixoff + ixlen] = b"\x90" * ixlen
    report["patches"].append(
        {
            "kind": "disable_intro_xor",
            "file_offset": ixoff,
            "length": ixlen,
            "old": old.hex(),
        }
    )

    soff = sites.intro_shift_site
    if bytes(out[soff : soff + 3]) != b"\xb8\x04\x00":
        die("intro shift setup changed unexpectedly")
    old = bytes(out[soff : soff + 3])
    out[soff + 1 : soff + 3] = b"\x00\x00"
    report["patches"].append(
        {
            "kind": "intro_bshift_4_to_0",
            "file_offset": soff,
            "length": 3,
            "old": old.hex(),
            "new": bytes(out[soff : soff + 3]).hex(),
            "display_decoder_file_offset": sites.display_decoder_file,
        }
    )

    for item in profile.items:
        start = item_start(info, item)
        if bytes(out[start : start + item.length]) != plains[item.item_id]:
            die(f"post-patch plaintext verification failed for {item.name}")
    intro = next(i for i in profile.items if i.item_id == "intro")
    istart = item_start(info, intro)
    if simulate_display_plain(out, istart, intro.length) != plains["intro"]:
        die("post-patch intro display verification failed")

    return bytes(out), report


def print_info(data: bytes, info: ExeInfo, profile: Profile, detected_by: str) -> None:
    print(f"file id: {profile.file_id}")
    print(f"detected by: {detected_by}")
    print(f"fingerprint: 0x{info.fingerprint:08X}")
    print(f"load image: 0x{info.code_start:X}-0x{info.code_end:X}")
    print("block            pkstrings   file-off  length  shift  state")
    print("---------------  ----------  --------  ------  -----  ---------")
    for item in profile.items:
        state = "plaintext" if looks_plain(data, info, item, profile) else "encoded"
        print(
            f"{item.name:<15}  {item.item_id:<10}  0x{item_start(info, item):06X}  "
            f"{item.length:6d}  {item.bshift:5d}  {state}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Inspect and de-obfuscate PKSFX text blocks. Known pkstrings layouts "
            "can be dumped; in-place plaintext patching is verified for ordinary "
            "PKSFX 2.04g Shareware and Registered full stubs."
        )
    )
    ap.add_argument("input", help="de-PKLITE'd PKSFX full stub")
    ap.add_argument(
        "-i", "--info", action="store_true", help="show detected layout and text blocks"
    )
    ap.add_argument(
        "-d", "--dump", metavar="DIR", help="dump decoded text blocks into DIR"
    )
    ap.add_argument(
        "-p",
        "--patch",
        metavar="FILE",
        help="write a copy with plaintext intro/messages and runtime decoding disabled",
    )
    args = ap.parse_args()
    if not args.info and not args.dump and not args.patch:
        ap.error("choose --info, --dump and/or --patch")

    data = Path(args.input).read_bytes()
    info = parse_exe(data)
    profile, detected_by = detect_profile(data, info)

    if args.info:
        print_info(data, info, profile, detected_by)

    if args.dump:
        dump_blocks(data, info, profile, args.dump)

    if args.patch:
        patched, report = patch_image(data, info, profile)
        Path(args.patch).write_bytes(patched)
        print(f"patched image: {args.patch}")
        print(f"file size unchanged: {len(patched)} bytes")
        print(f"sha256: {hashlib.sha256(patched).hexdigest()}")
        if report.get("already_plaintext"):
            print("input already appears to be plaintext-patched; output is unchanged")
        report_path = args.patch + ".patch.json"
        with open(report_path, "w", encoding="ascii") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"patch report: {report_path}")


if __name__ == "__main__":
    main()
