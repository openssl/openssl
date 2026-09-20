#! /usr/bin/env python3
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""
Convert and check the Ed25519 constants in crypto/ec/curve25519.c.

The file carries the curve constant d, 2*d, sqrt(-1), the base point table
k25519Precomp[i][j] = (j+1)*256^i*B and the odd multiples table
Bi[j] = (2*j+1)*B twice: in the reference base 2^25.5 representation (ten
signed 32-bit limbs at bit offsets 0, 26, 51, 77, 102, 128, 153, 179, 204,
230) and in the base 2^51 representation (five 51-bit limbs).

    util/curve25519-fe51-tables.py check crypto/ec/curve25519.c

parses both representations and checks each value against an independent
implementation of the curve arithmetic below, written from the definition
of the curve with affine coordinates and nothing shared with curve25519.c.

    util/curve25519-fe51-tables.py emit crypto/ec/curve25519.c

prints the base 2^51 definitions, converted from the base 2^25.5 ones, in
the form in which they appear in the file.
"""

import re
import sys

p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
REF10_SHIFTS = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
MASK51 = (1 << 51) - 1


# --- independent curve arithmetic ------------------------------------------

def edwards_add(P, Q):
    """Affine addition on -x^2 + y^2 = 1 + d x^2 y^2."""
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + d * x1 * x2 * y1 * y2, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) * pow(1 - d * x1 * x2 * y1 * y2, -1, p) % p
    return (x3, y3)


def scalar_mult(k, P):
    R = (0, 1)
    while k:
        if k & 1:
            R = edwards_add(R, P)
        P = edwards_add(P, P)
        k >>= 1
    return R


def base_point():
    """B = (x, 4/5) with x positive, i.e. even."""
    y = 4 * pow(5, -1, p) % p
    xx = (y * y - 1) * pow(d * y * y + 1, -1, p) % p
    x = pow(xx, (p + 3) // 8, p)
    if x * x % p != xx:
        x = x * pow(2, (p - 1) // 4, p) % p
    assert x * x % p == xx
    if x & 1:
        x = p - x
    assert (-x * x + y * y - 1 - d * x * x * y * y) % p == 0
    return (x, y)


def precomp(P):
    """The (y+x, y-x, 2dxy) form the tables are stored in."""
    x, y = P
    return [(y + x) % p, (y - x) % p, 2 * d * x * y % p]


# --- representations -------------------------------------------------------

def ref10_to_int(limbs):
    assert len(limbs) == 10
    return sum(v << s for v, s in zip(limbs, REF10_SHIFTS)) % p


def fe51_to_int(limbs):
    assert len(limbs) == 5
    assert all(0 <= v <= MASK51 for v in limbs), "limb not reduced"
    return sum(v << (51 * i) for i, v in enumerate(limbs)) % p


def int_to_fe51(v):
    assert 0 <= v < p
    return [(v >> (51 * i)) & MASK51 for i in range(5)]


# --- parsing ---------------------------------------------------------------

def definitions(src, decl):
    """
    All definitions 'static const <decl> = { ... };' in src, each as a
    flat list of the integers it contains, tagged with the representation.
    """
    found = []
    for m in re.finditer(r"static const " + re.escape(decl) + r" = \{(.*?)\n\};",
                         src, re.S):
        body = m.group(1)
        if "0x" in body:
            nums = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", body)]
            found.append(("fe51", nums))
        else:
            nums = [int(x) for x in re.findall(r"-?\d+", body)]
            found.append(("ref10", nums))
    return found


def chunks(lst, n):
    assert len(lst) % n == 0
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def parse(src):
    """
    {representation: {name: value or list of [yplusx, yminusx, xy2d]}}
    """
    out = {"ref10": {}, "fe51": {}}
    limbs = {"ref10": 10, "fe51": 5}
    to_int = {"ref10": ref10_to_int, "fe51": fe51_to_int}
    for name in ("d", "sqrtm1", "d2"):
        for rep, nums in definitions(src, "fe " + name):
            out[rep][name] = to_int[rep](nums)
    for name, decl in (("k25519Precomp", "ge_precomp k25519Precomp[32][8]"),
                       ("Bi", "ge_precomp Bi[8]")):
        for rep, nums in definitions(src, decl):
            elems = [to_int[rep](e) for e in chunks(nums, limbs[rep])]
            out[rep][name] = chunks(elems, 3)
    return out


# --- checking --------------------------------------------------------------

def expected():
    B = base_point()
    return {
        "d": d,
        "d2": 2 * d % p,
        "sqrtm1": pow(2, (p - 1) // 4, p),
        "k25519Precomp": [precomp(scalar_mult((j + 1) * 256**i, B))
                          for i in range(32) for j in range(8)],
        "Bi": [precomp(scalar_mult(2 * j + 1, B)) for j in range(8)],
    }


def check(src):
    want = expected()
    assert want["sqrtm1"] * want["sqrtm1"] % p == p - 1
    got = parse(src)
    ok = True
    for rep in ("ref10", "fe51"):
        for name, value in want.items():
            if name not in got[rep]:
                print("%s: %s missing" % (rep, name))
                ok = False
            elif got[rep][name] != value:
                print("%s: %s differs from the independent computation"
                      % (rep, name))
                ok = False
            else:
                count = len(value) * 3 if isinstance(value, list) else 1
                print("%s: %s ok (%d field elements)" % (rep, name, count))
    return ok


# --- emitting --------------------------------------------------------------

def fmt_fe(v, indent):
    l = ["0x%013x" % x for x in int_to_fe51(v)]
    return (indent + "{ " + ", ".join(l[:3]) + ",\n"
            + indent + "    " + ", ".join(l[3:]) + " }")


def fmt_precomp(e, indent):
    return (indent + "{\n"
            + ",\n".join(fmt_fe(v, indent + "    ") for v in e) + ",\n"
            + indent + "}")


def emit(src):
    ref = parse(src)["ref10"]
    for name in ("d", "sqrtm1", "d2"):
        l = ["0x%013x" % x for x in int_to_fe51(ref[name])]
        print("static const fe %s = {\n    %s,\n    %s\n};\n"
              % (name, ", ".join(l[:3]), ", ".join(l[3:])))
    print("static const ge_precomp k25519Precomp[32][8] = {")
    for i in range(32):
        print("    {")
        for j in range(8):
            print(fmt_precomp(ref["k25519Precomp"][i * 8 + j], "        ") + ",")
        print("    },")
    print("};\n")
    print("static const ge_precomp Bi[8] = {")
    for j in range(8):
        print(fmt_precomp(ref["Bi"][j], "    ") + ",")
    print("};")


def main(argv):
    if len(argv) != 3 or argv[1] not in ("check", "emit"):
        sys.stderr.write("usage: %s check|emit crypto/ec/curve25519.c\n" % argv[0])
        return 2
    src = open(argv[2]).read()
    if argv[1] == "emit":
        emit(src)
        return 0
    return 0 if check(src) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
