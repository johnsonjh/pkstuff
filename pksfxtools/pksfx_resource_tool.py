#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

LOAD_ORIGIN = 0x80
BANNER = b"PKZIP(R) FAST! Create/Update Utility"

DATA_SEGMENT = 0x0425

RESOURCE_DEFS = (
    ("registered", bytes.fromhex("b8 00 00 b9 b7 03"), 0x0000, 0x004E),
    ("license", bytes.fromhex("b8 94 01 b9 b7 03"), 0x0194, 0x0052),
    ("help", bytes.fromhex("b8 72 03 b9 b7 03"), 0x0372, 0x0054),
)

EXPECTED_PREFIX = {
    "registered": b"\r\nThis is a registered version of PKSFX and is only for use on those\r\nmachine(s) that it is licensed for.\r\n",
    "license": b"\r\n\r\nPKWARE disclaims all warranties as to this software, whether express or\r\nimplied, including without limitation any implied warranties of merchant-\r\n",
    "help": b"\r\nExtracts files from a zipfile to their original name,size,date & attributes.\r\n",
}


@dataclass(frozen=True)
class Resource:
    name: str
    file_offset: int
    storage_size: int
    encoded_size: int
    decoded_size: int
    padding_size: int
    segment: int
    offset: int


def load_binary(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path}: not an MZ executable")
    if len(data) < LOAD_ORIGIN:
        raise ValueError(f"{path}: truncated MZ executable")
    return data


def find_first(data: bytes, pattern: bytes, label: str) -> int:
    hit = data.find(pattern)
    if hit < 0:
        raise ValueError(f"{label}: source-pointer signature not found")
    return hit


def detect_resources(data: bytes) -> list[Resource]:
    load = data[LOAD_ORIGIN:]
    found: list[tuple[str, int, int, int, int]] = []

    for name, pat, off, count_off in RESOURCE_DEFS:
        _ = find_first(load, pat, name)
        file_offset = LOAD_ORIGIN + 0x03B7 * 16 + off
        count_file = LOAD_ORIGIN + DATA_SEGMENT * 16 + count_off
        if count_file + 2 > len(data):
            raise ValueError(f"{name}: count field is outside the executable")
        decoded_size = int.from_bytes(data[count_file : count_file + 2], "little")
        if decoded_size == 0 or decoded_size > 0x7FFF:
            raise ValueError(
                f"{name}: implausible decoded size {decoded_size} from "
                f"{DATA_SEGMENT:04X}:{count_off:04X}"
            )
        found.append((name, file_offset, 0x03B7, off, decoded_size))

    found.sort(key=lambda x: x[1])

    banner_off = data.find(BANNER)
    if banner_off < 0:
        raise ValueError("could not locate the ordinary plaintext PKZIP banner")
    if banner_off <= found[-1][1]:
        raise ValueError("resource/banner ordering is inconsistent")

    resources: list[Resource] = []
    for idx, (name, start, seg, off, decoded_size) in enumerate(found):
        end = found[idx + 1][1] if idx + 1 < len(found) else banner_off
        size = end - start
        if size < 2:
            raise ValueError(f"{name}: implausibly small resource block ({size} bytes)")

        encoded_size = decoded_size + 1
        if encoded_size > size:
            raise ValueError(
                f"{name}: encoded size {encoded_size} exceeds storage block {size}"
            )

        block = data[start:end]
        padding = block[encoded_size:]
        resources.append(
            Resource(
                name=name,
                file_offset=start,
                storage_size=size,
                encoded_size=encoded_size,
                decoded_size=decoded_size,
                padding_size=len(padding),
                segment=seg,
                offset=off,
            )
        )
    return resources


def decode_resource(block: bytes, decoded_size: int, encoded_size: int) -> bytes:
    if encoded_size != decoded_size + 1:
        raise ValueError("encoded_size must equal decoded_size + 1")
    if encoded_size > len(block):
        raise ValueError("encoded resource exceeds storage block")

    x = bytearray(block[:encoded_size])
    n = decoded_size

    for i in range(n):
        x[i] ^= (n - i) & 0xFF

    out = bytearray(n)
    for i in range(n):
        out[i] = ((x[i] << 4) | (x[i + 1] >> 4)) & 0xFF
    return bytes(out)


def encode_resource(
    plain: bytes, original_block: bytes, decoded_size: int, encoded_size: int
) -> bytes:
    if len(plain) != decoded_size:
        raise ValueError(
            f"replacement length is {len(plain)} bytes; "
            f"{decoded_size} bytes are required"
        )
    if encoded_size != decoded_size + 1:
        raise ValueError("encoded_size must equal decoded_size + 1")
    if encoded_size > len(original_block):
        raise ValueError("encoded resource exceeds storage block")

    orig_x = bytearray(original_block[:encoded_size])
    n = decoded_size
    for i in range(n):
        orig_x[i] ^= (n - i) & 0xFF

    q = bytearray(n + 1)

    q[0] = orig_x[0] & 0xF0
    q[n] = orig_x[n] & 0x0F

    for i, p in enumerate(plain):
        q[i] = (q[i] & 0xF0) | ((p >> 4) & 0x0F)
        q[i + 1] = (q[i + 1] & 0x0F) | ((p & 0x0F) << 4)

    enc = bytearray(q)
    for i in range(n):
        enc[i] ^= (n - i) & 0xFF

    result = bytearray(original_block)
    result[:encoded_size] = enc
    return bytes(result)


def verify_resource(resource: Resource, block: bytes, plain: bytes) -> None:
    expected = EXPECTED_PREFIX.get(resource.name)
    if expected and not plain.startswith(expected):
        print(
            f"warning: {resource.name} does not have the expected stock prefix",
            file=sys.stderr,
        )

    if resource.encoded_size != resource.decoded_size + 1:
        raise ValueError(f"{resource.name}: invalid size relation")

    rebuilt = encode_resource(
        plain, block, resource.decoded_size, resource.encoded_size
    )
    if rebuilt != block:
        raise ValueError(f"{resource.name}: internal round-trip check failed")


def cmd_info(args: argparse.Namespace) -> int:
    data = load_binary(args.input)
    resources = detect_resources(data)

    print(f"file: {args.input}")
    print(f"size: {len(data)} bytes")
    print(f"load origin: 0x{LOAD_ORIGIN:04X}")
    print()
    print("resource          file-off  storage  encoded  decoded  padding  far-pointer")
    print("----------------  --------  -------  -------  -------  -------  -----------")
    for r in resources:
        print(
            f"{r.name:<16}  0x{r.file_offset:06X}  "
            f"{r.storage_size:7d}  {r.encoded_size:7d}  "
            f"{r.decoded_size:7d}  {r.padding_size:7d}  "
            f"{r.segment:04X}:{r.offset:04X}"
        )
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    data = load_binary(args.input)
    resources = detect_resources(data)
    outdir = args.output
    outdir.mkdir(parents=True, exist_ok=True)

    for r in resources:
        block = data[r.file_offset : r.file_offset + r.storage_size]
        plain = decode_resource(block, r.decoded_size, r.encoded_size)
        verify_resource(r, block, plain)

        path = outdir / f"{r.name}.txt"
        path.write_bytes(plain)
        print(
            f"{r.name}: {len(plain)} bytes -> {path} "
            f"(file offset 0x{r.file_offset:06X})"
        )
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    data = load_binary(args.input)
    resources = detect_resources(data)
    by_name = {r.name: r for r in resources}

    replacements = {
        "registered": Path(args.registered),
        "license": Path(args.license),
        "help": Path(args.help),
    }

    output = bytearray(data)
    for name, path in replacements.items():
        r = by_name[name]
        plain = path.read_bytes()
        block = data[r.file_offset : r.file_offset + r.storage_size]
        new_block = encode_resource(plain, block, r.decoded_size, r.encoded_size)
        output[r.file_offset : r.file_offset + r.storage_size] = new_block
        check = decode_resource(new_block, r.decoded_size, r.encoded_size)
        if check != plain:
            raise ValueError(f"{name}: post-patch verification failed")

    args.output.write_bytes(output)
    print(f"wrote: {args.output}")
    print(f"sha256: {hashlib.sha256(output).hexdigest()}")

    detect_resources(bytes(output))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Dump/repack the custom PKSFX 2.04g license/help resources."
    )
    sp = p.add_subparsers(dest="command", required=True)

    pi = sp.add_parser("info", help="show detected resource locations and sizes")
    pi.add_argument("input", type=Path)
    pi.set_defaults(func=cmd_info)

    pd = sp.add_parser("dump", help="decode resources to text files")
    pd.add_argument("input", type=Path)
    pd.add_argument("output", type=Path)
    pd.set_defaults(func=cmd_dump)

    pp = sp.add_parser("patch", help="replace all three resources and write a new EXE")
    pp.add_argument("input", type=Path)
    pp.add_argument("--registered", required=True, type=Path, help="registered.txt")
    pp.add_argument("--license", required=True, type=Path, help="license.txt")
    pp.add_argument(
        "--help-text", dest="help", required=True, type=Path, help="help.txt"
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
