#!/usr/bin/env python3
"""
binary_to_file.py

Convert a printed byte-slice string (for example produced by Rust's `{:x?}` or by printing a list of hex/decimal bytes)
into a binary file.

Usage:
  python3 binary_to_file.py -i input.txt -o out.bin
  echo "[81, 0, ff, 10]" | python3 binary_to_file.py -o out.bin

The script is permissive and accepts tokens like:
- hex (with or without 0x prefix): ff, 3b, a, 0f
- decimal: 255, 18

It will attempt to interpret tokens as hex first; if that would produce a value > 255 it will fall back to decimal.
"""

from __future__ import annotations

import argparse
import sys
import re
from typing import List


def parse_report_string(s: str) -> bytes:
    """Parse a text containing a bracketed byte list and return bytes.

    The parser is tolerant: it removes markdown code fences, surrounding quotes and brackets,
    splits on commas, and extracts the first contiguous hex/decimal token from each item.
    Tokens are parsed as hex first (so "ff" -> 255), falling back to decimal when necessary.
    """
    s = s.strip()
    s = s.replace(" ", "")
    print(s)
    #print(' '.join(str(ord(c)) for c in s))
    # Remove markdown code fences if present
    if s.startswith("```"):
        # Strip the opening ```... line and trailing ```
        s = re.sub(r"^```.*?\n", "", s, flags=re.DOTALL)
        s = re.sub(r"\n```$", "", s, flags=re.DOTALL)
        s = s.strip()
    print("test")
    # If the string contains an assignment like: report_string = "[...]" or report_string = '[...]'
    #m_assign = re.search(r"report_string\s*=\s*(['\"])(?P<body>.*)(?P=1)", s, flags=re.DOTALL)
    #if m_assign:
    #    s = m_assign.group("body").strip()
    print("test2")
    # Remove surrounding brackets if present
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    print(s)
    # Split on commas (the printed output uses commas as separators)
    parts = s.split(",")
    out: List[int] = []

    for part in parts:
        token = part.strip()
        if not token:
            continue

        # Extract the first contiguous token of hex/digits or a 0x-prefixed token
        m = re.search(r"(?i)0x[0-9a-f]+|[0-9a-f]+", token)
        if not m:
            # fall back to extract decimal digits
            m = re.search(r"(\d+)", token)
            if not m:
                raise ValueError(f"Cannot find a numeric token in: {token!r}")

        tok = m.group(0)

        # Try hex first (handles tokens printed with '{:x?}'), fall back to decimal
        try:
            val = int(tok, 16)
            if not (0 <= val <= 0xFF):
                # if parsed hex is outside a byte range, try decimal
                raise ValueError
        except Exception:
            try:
                val = int(tok, 10)
            except Exception:
                raise ValueError(f"Cannot parse token as number: {tok!r}")

        if not (0 <= val <= 0xFF):
            raise ValueError(f"Parsed value out of byte range (0-255): {val} from token {tok!r}")

        out.append(val)

    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert a printed byte-slice string (hex/decimal tokens) into a binary file"
    )
    parser.add_argument("-i", "--infile", help="Input text file (default: read from stdin)")
    parser.add_argument("-o", "--outfile", default="tdx_report.bin", help="Output binary file (default: tdx_report.bin)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    """
    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        if sys.stdin.isatty():
            print("Waiting for input on stdin (paste the report string), then Ctrl-D/EOF.\n", file=sys.stderr)
        content = sys.stdin.read()
        if not content:
            parser.print_help(sys.stderr)
            return 1
    """
    #content = "[81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 18, 1a, 3, ff, 0, 3, 0                                                     , 0, 0, 0, 0, 0, 0, 0, b2, ce, f, ff, fe, bc, de, 95, 45, 29, c4, 18, a8, 4, ac, 8e, 99, 1, 3b, fa, 65,                                                      b5, 60, ac, 5d, 88, c, d, 86, 34, bf, 93, e2, 0, bb, 81, e4, d6, 8d, 8d, fc, 70, 42, 48, 7e, b6, 85, 6                                                     9, 48, 1b, 2f, d1, 34, be, 5f, 74, 98, 91, f1, ad, 11, 70, e1, 83, 76, ef, a2, 85, 94, 8c, 5c, 48, 7f,                                                      25, 8c, e4, ca, 41, 73, ab, 6e, 86, a2, a0, a, 70, 33, 14, b4, d3, 73, e9, 5a, a3, 4c, 13, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                     , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 92, 55, e, c3, b3, 66, 51, d1, 7c                                                     , b9, 49, ce, 99, 33, 7d, f2, 6b, 89, a9, 35, 1b, e3, c9, f5, c, b3, a2, cd, be, d0, 5e, c3, ff, 1, 3,                                                      0, 0, 0, 0, 0, 7, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, b6, 6f, aa, 45, 1d, 19, eb, bd, be,                                                      89, 37, 1b, 8d, af, 2b, 65, aa, 39, 84, ec, 90, 11, 3, 43, e9, e2, ee, c1, 16, af, 8, 85, f, a2, e, 3b,                                                      1a, a9, a8, 74, d7, 7a, 65, 38, e, e7, e6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 7, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                     , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                     , e7, 18, 6, 0, 0, 0, 0, 0, 77, fc, 75, a3, 94, c8, 29, 17, 4b, 70, 88, a0, 94, aa, 28, 17, e4, 9b, 23,                                                      c9, a2, b8, 90, 59, ef, b5, 49, 92, b9, 40, 5e, 8b, 6a, 26, 83, e6, 37, b5, aa, 65, 45, 68, e8, db, db                                                     , 28, e7, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                     , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 89, 23, b0, f9, 55, d0, 8d, a0, 77, c9, 6a, ab, a5, 22, b9, de, c                                                     e, de, 61, c5, 99, ce, a6, c4, 18, 89, cf, be, a4, ae, 4d, 50, 52, 9d, 96, fe, 4d, 1a, fd, af, b6, 5e,                                                      7f, 95, bf, 23, c4, 51, 89, 23, b0, f9, 55, d0, 8d, a0, 77, c9, 6a, ab, a5, 22, b9, de, ce, de, 61, c5,                                                      99, ce, a6, c4, 18, 89, cf, be, a4, ae, 4d, 50, 52, 9d, 96, fe, 4d, 1a, fd, af, b6, 5e, 7f, 95, bf, 23                                                     , c4, 10, 62, 7d, e, ce, 9f, b6, 56, 3d, fe, a7, af, 64, 80, ee, dc, 40, 94, 14, e6, 2f, 42, 5d, b4, 62                                                     , 1e, 4f, 1d, df, a8, d1, 7f, b8, 78, b5, 63, 8d, 8d, c3, 95, 9b, 96, 21, b6, 5c, 9, 13, 43, 0, 0, 0, 0                                                     , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                     , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"
    content = "[81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 19, 1b, 4, ff, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, c1, a9, 13, 2c, d5, 64, 5a, 88, 82, ee, b0, 4, 54, 72, 2f, a2, 77, ff, ee, 1c, e, 9b, 7e, 6e, 0, c, 18, 18, 70, 28, 5f, 6c, 67, 9f, 61, 9c, 46, 11, b4, f6, 79, 8f, a8, 9a, 54, a7, f4, 4a, 48, 1b, 2f, d1, 34, be, 5f, 74, 98, 91, f1, ad, 11, 70, e1, 83, 76, ef, a2, 85, 94, 8c, 5c, 48, 7f, 25, 8c, e4, ca, 41, 73, ab, 6e, 86, a2, a0, a, 70, 33, 14, b4, d3, 73, e9, 5a, a3, 4c, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 23, d6, 81, ec, 92, 1c, c6, e7, e7, 7f, d0, c8, 17, ea, d4, e4, 15, 58, 60, d9, 70, 8b, 93, 85, fc, 88, 3e, da, 1, 3e, 9b, ff, 1, 3, 0, 0, 0, 0, 0, c, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, d0, d8, c, 8, 51, 66, ba, 78, cc, c6, 9a, f2, 68, e5, 75, 3c, f0, f3, 39, 45, 23, cb, 4f, f7, c5, b, 8, d9, 26, 5c, 82, 48, 9c, 9, 9c, 37, 7b, e6, a4, 0, e4, d2, b5, 7d, a9, 24, 1, 2c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, c, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, e7, 18, 6, 0, 0, 0, 0, 0, 77, fc, 75, a3, 94, c8, 29, 17, 4b, 70, 88, a0, 94, aa, 28, 17, e4, 9b, 23, c9, a2, b8, 90, 59, ef, b5, 49, 92, b9, 40, 5e, 8b, 6a, 26, 83, e6, 37, b5, aa, 65, 45, 68, e8, db, db, 28, e7, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 89, 23, b0, f9, 55, d0, 8d, a0, 77, c9, 6a, ab, a5, 22, b9, de, ce, de, 61, c5, 99, ce, a6, c4, 18, 89, cf, be, a4, ae, 4d, 50, 52, 9d, 96, fe, 4d, 1a, fd, af, b6, 5e, 7f, 95, bf, 23, c4, 51, 89, 23, b0, f9, 55, d0, 8d, a0, 77, c9, 6a, ab, a5, 22, b9, de, ce, de, 61, c5, 99, ce, a6, c4, 18, 89, cf, be, a4, ae, 4d, 50, 52, 9d, 96, fe, 4d, 1a, fd, af, b6, 5e, 7f, 95, bf, 23, c4, 10, 62, 7d, e, ce, 9f, b6, 56, 3d, fe, a7, af, 64, 80, ee, dc, 40, 94, 14, e6, 2f, 42, 5d, b4, 62, 1e, 4f, 1d, df, a8, d1, 7f, b8, 78, b5, 63, 8d, 8d, c3, 95, 9b, 96, 21, b6, 5c, 9, 13, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"
    try:
        data = parse_report_string(content)
    except Exception as e:
        print(f"Failed to parse input: {e}", file=sys.stderr)
        return 2

    with open(args.outfile, "wb") as f:
        f.write(data)

    if args.verbose:
        print(f"Wrote {len(data)} bytes to {args.outfile}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())