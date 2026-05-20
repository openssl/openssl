#!/usr/bin/env python3

# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# This script generates missing-kdf.der - a password-encrypted CMS message
# without the keyDerivationAlgorithm field, which is used in the
# “PWRI missing keyDerivationAlgorithm regression” test.
#
# Usage: python3 make_missing_kdf_der.py valid.der missing-kdf.der

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Node:
    off: int
    tag: int
    hdr_len: int
    length: int
    end: int
    children: list["Node"]


def read_len(data: bytes, off: int) -> tuple[int, int]:
    first = data[off]
    if first < 0x80:
        return first, 1
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError(f"unsupported DER length form at {off}")
    val = 0
    for b in data[off + 1 : off + 1 + n]:
        val = (val << 8) | b
    return val, 1 + n


def parse_node(data: bytes, off: int) -> Node:
    tag = data[off]
    length, len_len = read_len(data, off + 1)
    hdr_len = 1 + len_len
    end = off + hdr_len + length
    children: list[Node] = []
    if tag & 0x20:
        cur = off + hdr_len
        while cur < end:
            child = parse_node(data, cur)
            children.append(child)
            cur = child.end
        if cur != end:
            raise ValueError(f"child parse ended at {cur}, expected {end}")
    return Node(off=off, tag=tag, hdr_len=hdr_len, length=length, end=end, children=children)


def encode_len(length: int, existing_len_len: int) -> bytes:
    if existing_len_len == 1:
        if length >= 0x80:
            raise ValueError("new length no longer fits in short-form DER")
        return bytes([length])
    payload_len = existing_len_len - 1
    max_len = (1 << (payload_len * 8)) - 1
    if length > max_len:
        raise ValueError("new length no longer fits in existing long-form DER")
    out = bytearray([0x80 | payload_len])
    for shift in range((payload_len - 1) * 8, -8, -8):
        out.append((length >> shift) & 0xFF)
    return bytes(out)


def patch_length_field(buf: bytearray, node: Node, delta: int) -> None:
    new_len = node.length + delta
    if new_len < 0:
        raise ValueError("negative patched length")
    len_bytes = encode_len(new_len, node.hdr_len - 1)
    start = node.off + 1
    end = start + len(node.hdr_len.to_bytes(1, "big")) - 1  # unused, kept for clarity
    buf[start : start + len(len_bytes)] = len_bytes


def main() -> int:
    ap = argparse.ArgumentParser(description="Remove PWRI keyDerivationAlgorithm from a CMS DER blob.")
    ap.add_argument("input_der")
    ap.add_argument("output_der")
    args = ap.parse_args()

    data = Path(args.input_der).read_bytes()
    root = parse_node(data, 0)

    # CMS structure we expect:
    # SEQUENCE { OID envelopedData, [0] SEQUENCE { version, SET recipientInfos, ... } }
    ed_wrapper = root.children[1]
    env_seq = ed_wrapper.children[0]
    recipient_set = env_seq.children[1]
    pwri_choice = recipient_set.children[0]  # [3]

    if pwri_choice.tag != 0xA3:
        raise ValueError(f"expected PWRI choice tag 0xA3, found 0x{pwri_choice.tag:02x}")
    if len(pwri_choice.children) < 3:
        raise ValueError("unexpected PWRI child count")

    version = pwri_choice.children[0]
    maybe_kdf = pwri_choice.children[1]
    keyenc = pwri_choice.children[2]
    if version.tag != 0x02:
        raise ValueError("PWRI version is not INTEGER")
    if maybe_kdf.tag != 0xA0:
        raise ValueError(f"PWRI child after version is not [0] keyDerivationAlgorithm: 0x{maybe_kdf.tag:02x}")
    if keyenc.tag != 0x30:
        raise ValueError("PWRI keyEncryptionAlgorithm is not SEQUENCE")

    remove_start = maybe_kdf.off
    remove_end = maybe_kdf.end
    remove_len = remove_end - remove_start

    out = bytearray(data)
    del out[remove_start:remove_end]

    # Adjust ancestors whose length spans the removed field.
    for node in [root, ed_wrapper, env_seq, recipient_set, pwri_choice]:
        patch_length_field(out, node, -remove_len)

    Path(args.output_der).write_bytes(out)
    print(f"removed {remove_len} bytes at [{remove_start}, {remove_end})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
