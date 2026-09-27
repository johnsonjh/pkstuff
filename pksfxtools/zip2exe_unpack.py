#!/usr/bin/env python3

from __future__ import print_function

import argparse
import json
import os
import shutil
import subprocess
import sys

MZ = b"MZ"
FULL_MAGIC = b"PKLITE"
MINI_MAGIC = b"PKSFX (R)"


def u16(buf, off):
    return buf[off] | (buf[off + 1] << 8)


def xor_decode(buf, key0):
    return bytes(byte ^ ((key0 - i) & 0xFF) for i, byte in enumerate(buf))


def mz_image_size(buf):
    if len(buf) < 0x1C or buf[:2] != MZ:
        return None

    last = u16(buf, 0x02)
    pages = u16(buf, 0x04)
    hdr_paras = u16(buf, 0x08)
    reloc = u16(buf, 0x06)

    if pages == 0 or last > 511:
        return None
    if hdr_paras == 0 or hdr_paras > 0x100:
        return None
    if reloc > 0x1000:
        return None

    if last == 0:
        return pages * 512
    return (pages - 1) * 512 + last


def candidate_score(decoded):
    size = mz_image_size(decoded)
    if size is None or size > len(decoded):
        return None

    score = 0

    if decoded[0x18] == 0 or decoded[0x18] < size:
        score += 1

    pos_full = decoded.find(FULL_MAGIC, 0, min(size, 0x100))
    if pos_full >= 0:
        score += 10

    pos_mini = decoded.find(MINI_MAGIC, 0, size)
    if pos_mini >= 0:
        score += 10

    return score, size


def find_candidates(data):
    result = []
    for off in range(0, len(data) - 0x1C):
        key0 = data[off] ^ 0x4D
        if (data[off + 1] ^ ((key0 - 1) & 0xFF)) != 0x5A:
            continue

        head = xor_decode(data[off : off + 0x40], key0)
        size = mz_image_size(head)
        if size is None or size > len(data) - off:
            continue

        decoded = xor_decode(data[off : off + size], key0)
        check = candidate_score(decoded)
        if check is None:
            continue
        score, size2 = check
        if size2 != size:
            continue

        result.append(
            {
                "offset": off,
                "key": key0,
                "size": size,
                "score": score,
                "decoded": decoded,
            }
        )

    return result


def choose_stub(candidates, kind):
    if kind == "full":
        matches = [
            c
            for c in candidates
            if c["decoded"].find(FULL_MAGIC, 0, min(c["size"], 0x100)) >= 0
            and c["size"] >= 0x1000
        ]
        if matches:
            return max(matches, key=lambda c: (c["score"], c["size"]))

        if candidates:
            return max(candidates, key=lambda c: (c["size"], c["score"]))

    if kind == "mini":
        matches = [
            c
            for c in candidates
            if c["decoded"].find(MINI_MAGIC) >= 0 and c["size"] < 0x1000
        ]
        if matches:
            return min(matches, key=lambda c: (c["size"] * -1, -c["score"]))

    return None


def write_stub(path, decoded):
    with open(path, "wb") as f:
        f.write(decoded)


def run_deark(deark, stub_path, outdir):
    os.makedirs(outdir, exist_ok=True)
    cmd = [deark, "-opt", "execomp", "-od", outdir, stub_path]
    print("Deark:", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
    except OSError as exc:
        print("WARNING: unable to execute Deark: %s" % (exc), file=sys.stderr)
        return 127

    if proc.stdout:
        sys.stdout.write(proc.stdout)
        if not proc.stdout.endswith("\n"):
            sys.stdout.write("\n")
    if proc.returncode != 0:
        print(
            "WARNING: Deark returned %d for %s" % (proc.returncode, stub_path),
            file=sys.stderr,
        )
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="de-PKLITE'd ZIP2EXE.EXE")
    ap.add_argument(
        "-o",
        "--output-dir",
        default="zip2exe-stubs",
        help="output directory (default: zip2exe-stubs)",
    )
    ap.add_argument(
        "--deark",
        nargs="?",
        const="deark",
        help="also invoke Deark on both extracted stubs; optionally give path",
    )
    ap.add_argument(
        "--force", action="store_true", help="overwrite existing extracted files"
    )
    ap.add_argument(
        "--list-candidates",
        action="store_true",
        help="print every plausible outer-XOR MZ candidate",
    )
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    candidates = find_candidates(data)
    if args.list_candidates:
        for c in sorted(candidates, key=lambda x: x["offset"]):
            decoded = c["decoded"]
            print(
                "candidate offset=0x%04x key=0x%02x size=0x%x score=%d"
                % (c["offset"], c["key"], c["size"], c["score"])
            )
            print(
                "  PKLITE=%s PKSFX=%s"
                % (decoded.find(FULL_MAGIC) >= 0, decoded.find(MINI_MAGIC) >= 0)
            )

    full = choose_stub(candidates, "full")
    mini = choose_stub(candidates, "mini")

    if full is None or mini is None:
        print("ERROR: could not identify both embedded SFX stubs", file=sys.stderr)
        return 1

    if full["offset"] == mini["offset"]:
        print("ERROR: full and mini candidates collapsed to one image", file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)

    outputs = [
        ("full", full, os.path.join(args.output_dir, "PKSFX-FULL.PACKED.EXE")),
        ("mini", mini, os.path.join(args.output_dir, "PKSFX-MINI.EXE")),
    ]

    manifest = {
        "input": os.path.abspath(args.input),
        "file_size": len(data),
        "outer_encoding": {
            "type": "xor-descending-byte-key",
            "formula": "decoded[i] = encoded[i] ^ ((key0 - i) & 0xff)",
        },
        "stubs": [],
    }

    for kind, c, outpath in outputs:
        if os.path.exists(outpath) and not args.force:
            print("ERROR: output exists: %s (use --force)" % outpath, file=sys.stderr)
            return 1

        write_stub(outpath, c["decoded"])
        print(
            "%s: file 0x%04x, key 0x%02x, size 0x%x (%d bytes) -> %s"
            % (kind, c["offset"], c["key"], c["size"], c["size"], outpath)
        )

        manifest["stubs"].append(
            {
                "kind": kind,
                "source_offset": c["offset"],
                "outer_key": c["key"],
                "size": c["size"],
                "output": os.path.basename(outpath),
                "pklite": bool(
                    c["decoded"].find(FULL_MAGIC, 0, min(c["size"], 0x100)) >= 0
                ),
            }
        )

    manifest_path = os.path.join(args.output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print("manifest -> %s" % manifest_path)

    if args.deark:
        deark = shutil.which(args.deark) or args.deark
        for kind, c, outpath in outputs:
            is_packed = c["decoded"].find(FULL_MAGIC, 0, min(c["size"], 0x100)) >= 0
            if not is_packed:
                print("Deark: skipping %s (not identified as PKLITE-packed)" % outpath)
                continue
            deark_dir = os.path.join(args.output_dir, "deark-%s" % kind)
            run_deark(deark, outpath, deark_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
