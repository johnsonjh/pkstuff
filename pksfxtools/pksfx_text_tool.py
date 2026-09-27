#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import sys

BLOCKS = [
    {
        "name": "main_messages",
        "offset": 0x4326,
        "length": 0x02AE,
        "key": 0xAE,
        "patch_offset": 0x127C,
        "patch_length": 13,
    },
    {
        "name": "error_messages",
        "offset": 0x4602,
        "length": 0x0098,
        "key": 0x98,
        "patch_offset": 0x1289,
        "patch_length": 14,
    },
]

EXPECTED_HANDLER = bytes.fromhex(
    "8b dc 1e 9c 33 d2 91 58 50 25 ff fd 50 b8 10 00 "
    "ba 20 00 0e 52 cf 9a 94 c5 5f 04 8e d2 f6 c1 01"
)

EXPECTED_PATCHES = [
    bytes.fromhex("b8 32 03 1e 50 2d ca 03 f7 d8 ff 5e fa"),
    bytes.fromhex("b8 56 00 1e 50 2d 04 03 f7 d8 ff 1e 94 05"),
]


def die(msg):
    raise SystemExit("error: " + msg)


def decode_block(data, spec):
    start = spec["offset"]
    end = start + spec["length"]
    key = spec["key"]
    if end > len(data):
        die(f"{spec['name']} extends beyond end of file")
    src = data[start:end]
    return bytes(b ^ ((key - i) & 0xFF) for i, b in enumerate(src))


def validate_input(data):
    if len(data) < 0x3BD0:
        die("input is too small to be the expected de-PKLITE'd full stub")
    if data[:2] != b"MZ":
        die("input does not have an MZ header")
    if data[0x3B99 : 0x3B99 + len(EXPECTED_HANDLER)] != EXPECTED_HANDLER:
        die("decryptor at file offset 0x3B99 does not match the expected routine")
    for spec, expected in zip(BLOCKS, EXPECTED_PATCHES):
        off = spec["patch_offset"]
        if data[off : off + len(expected)] != expected:
            die(
                f"startup sequence at file offset 0x{off:X} does not match "
                "the expected version of the decoder setup"
            )


def dump_blocks(data, outdir):
    os.makedirs(outdir, exist_ok=True)
    manifest = {"input_size": len(data), "blocks": []}
    for spec in BLOCKS:
        decoded = decode_block(data, spec)
        bin_path = os.path.join(outdir, spec["name"] + ".bin")
        txt_path = os.path.join(outdir, spec["name"] + ".txt")
        with open(bin_path, "wb") as f:
            f.write(decoded)
        with open(txt_path, "wb") as f:
            f.write(decoded)
        manifest["blocks"].append(
            {
                "name": spec["name"],
                "offset": spec["offset"],
                "length": spec["length"],
                "key": spec["key"],
                "binary": os.path.basename(bin_path),
                "text": os.path.basename(txt_path),
            }
        )
        print(
            f"{spec['name']}: offset=0x{spec['offset']:X}, "
            f"length=0x{spec['length']:X}, key=0x{spec['key']:02X}"
        )
        print(f"  -> {txt_path}")
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="ascii") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def patch_image(data):
    out = bytearray(data)
    for spec in BLOCKS:
        decoded = decode_block(data, spec)
        start = spec["offset"]
        end = start + spec["length"]
        out[start:end] = decoded

        poff = spec["patch_offset"]
        plen = spec["patch_length"]
        if plen != len(EXPECTED_PATCHES[BLOCKS.index(spec)]):
            die("internal patch-length mismatch")
        out[poff : poff + plen] = b"\x90" * plen
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="de-PKLITE'd PKSFX full stub")
    ap.add_argument(
        "-d", "--dump", metavar="DIR", help="dump de-obfuscated blocks into DIR"
    )
    ap.add_argument(
        "-p",
        "--patch",
        metavar="FILE",
        help="write a copy with plaintext blocks and decoder setup disabled",
    )
    args = ap.parse_args()

    if not args.dump and not args.patch:
        ap.error("choose --dump and/or --patch")

    with open(args.input, "rb") as f:
        data = f.read()

    validate_input(data)

    if args.dump:
        dump_blocks(data, args.dump)

    if args.patch:
        patched = patch_image(data)
        with open(args.patch, "wb") as f:
            f.write(patched)
        print(f"patched image: {args.patch}")
        print("file size unchanged: %d bytes" % len(patched))


if __name__ == "__main__":
    main()
