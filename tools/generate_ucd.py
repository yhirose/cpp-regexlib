#!/usr/bin/env python3
"""
generate_ucd.py — Generate the self-contained Unicode tables that regexlib needs,
directly from the Unicode Character Database (UCD).

regexlib needs a thin slice of the UCD: UTF-8 decode/encode, General_Category
(\\w \\d \\p), grapheme-cluster segmentation (UAX #29), simple case folding ((?i)),
and White_Space (\\s). This script regenerates ONLY the data those features need and
splices it into a single `// [BEGIN GENERATED ...]` / `// [END GENERATED ...]` block
in regexlib.h, so the library ships as one header with no external dependency.

Division of labour (see also tools/README):
  * This generator owns 100% of the DATA: the property tables and the
    version-dependent enum value lists (GraphemeBreak, Emoji, Incb).
  * The UAX #29 grapheme RULES (is_grapheme_boundary) and the UTF-8 codec live as
    hand-maintained C++ in regexlib.h, OUTSIDE the generated block — algorithms are
    not auto-derived from the spec, only the property data they consume is.

The dense properties use a two-level, de-duplicated page table (see
emit_page_table) that keeps the generated block compact; a full-range self-check
(_check_table) guards every regeneration.

Usage:
    python3 tools/generate_ucd.py emit            # print the generated block to stdout
    python3 tools/generate_ucd.py update FILE     # splice the block into FILE in place
    python3 tools/generate_ucd.py verify          # parse + internal-consistency checks
Optional:  --ucd-dir DIR   (default: tools/ucd)
"""

import argparse
import io
import os
import re
import sys

MAX_CP = 0x10FFFF

# Must match `enum class GeneralCategory` in regexlib.h (ordinal = position). The
# category set is fixed by Unicode, so this is hand-pinned rather than parsed.
GC_ORDER = [
    "Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl", "No",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So",
    "Zs", "Zl", "Zp", "Cc", "Cf", "Cs", "Co", "Cn",
]

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_UCD = os.path.join(HERE, "ucd")

BEGIN = "// -------- [BEGIN GENERATED UCD BLOCK] --------"
END = "// -------- [END GENERATED UCD BLOCK] --------"

# Range regex shared by the simple "cp [.. cp] ; Value # ..." UCD property files.
PROP_RE = re.compile(r"([0-9A-Fa-f]+)(?:\.\.([0-9A-Fa-f]+))?\s*;\s*(\w+)")


# ---------------------------------------------------------------------------
# Two-level page table (dense props: General_Category, GraphemeBreak, Emoji)
#
# The 0x110000 code points are mapped to enum values through two compression
# layers, then a get_value(cp) that does two array lookups:
#
#   leaf level  : code points are cut into 128-cp leaf blocks. Blocks that are
#                 uniform (every cp shares one value) cost nothing; the rest are
#                 emitted once each, de-duplicated, as `_leafN[]`. Each leaf
#                 block is summarised by a "block code":
#                     code <  NLEAF  -> _leaves[code]   (a real leaf array)
#                     code >= NLEAF  -> uniform fill, enum ordinal = code-NLEAF
#   super level : the block-code array (one entry per leaf block) is itself
#                 mostly long runs (huge unassigned / private-use spans), so it
#                 is compressed the same way into SB-sized super blocks. `_dir`
#                 holds one entry per super block:
#                     d <  NSUPER    -> _supers[d]      (a real super array)
#                     d >= NSUPER    -> uniform super, block code = d-NSUPER
#
# Only the leaf arrays carry enum names; every directory array is small ints,
# so the whole table packs into far fewer (and shorter) lines than a flat
# per-code-point page table would. The hand-written grapheme/codec code below
# the generated block only ever calls get_value(), so this layout is internal.
# ---------------------------------------------------------------------------

_LEAF = 128  # code points per leaf block (mask 0x7f, shift 7 in get_value)


def _wrap(out, items, per_line, indent=" "):
    """Write `items` (already-formatted strings) wrapped at `per_line` per line."""
    for i, s in enumerate(items):
        out.write((indent if i == 0 else "\n" + indent) if i % per_line == 0 else "")
        out.write(s)
    out.write("\n")


def _split_blocks(values, bs):
    """Cut `values` into bs-sized blocks (padding the tail with values[-1]'s default
    is unnecessary here: len is a multiple of bs). Return list of tuples."""
    return [tuple(values[i:i + bs]) for i in range(0, len(values), bs)]


def _resolve_codes(raw, nleaf, ordmap):
    out = []
    for kind, payload in raw:
        out.append(payload if kind == "L" else nleaf + ordmap[payload])
    return out


def _best_super_shift(codes):
    """Pick SB = 2**shift (super block size, in leaf blocks) minimising emitted
    directory entries: NSUPER*SB + nsuper."""
    best = None
    for shift in range(2, 11):  # SB from 4 .. 1024 leaf blocks
        sb = 1 << shift
        padded = codes + [codes[-1]] * ((-len(codes)) % sb)
        uniq = {}
        nsuper = 0
        for i in range(0, len(padded), sb):
            blk = tuple(padded[i:i + sb])
            nsuper += 1
            if any(x != blk[0] for x in blk):
                uniq.setdefault(blk, len(uniq))
        cost = len(uniq) * sb + nsuper
        if best is None or cost < best[0]:
            best = (cost, shift)
    return best[1]


def emit_page_table(out, name, ctype, order, defval, values):
    """Emit `namespace name { ... get_value(char32_t) ... }` for an enum property.

    `order`  : ordered list of enum member names (ordinal = index).
    `values` : list of length MAX_CP+1 of enum-member names (strings)."""
    ordmap = {n: i for i, n in enumerate(order)}

    # leaf level
    leaf_index, leaves, raw = {}, [], []
    for blk in _split_blocks(values, _LEAF):
        if all(x == blk[0] for x in blk):
            raw.append(("U", blk[0]))
        else:
            if blk not in leaf_index:
                leaf_index[blk] = len(leaves)
                leaves.append(blk)
            raw.append(("L", leaf_index[blk]))
    nleaf = len(leaves)
    codes = _resolve_codes(raw, nleaf, ordmap)

    # super level
    shift = _best_super_shift(codes)
    sb = 1 << shift
    codes_pad = codes + [nleaf + ordmap[defval]] * ((-len(codes)) % sb)
    super_index, supers, dirraw = {}, [], []
    for i in range(0, len(codes_pad), sb):
        blk = tuple(codes_pad[i:i + sb])
        if any(x != blk[0] for x in blk):
            if blk not in super_index:
                super_index[blk] = len(supers)
                supers.append(blk)
            dirraw.append(("S", super_index[blk]))
        else:
            dirraw.append(("U", blk[0]))
    nsuper = len(supers)
    directory = []
    for kind, payload in dirraw:
        directory.append(payload if kind == "S" else nsuper + payload)

    # self-check: the emitted lookup must reproduce `values` for every code point
    _check_table(values, ordmap, defval, leaves, nleaf, supers, nsuper, shift)

    # --- emit ---
    out.write("namespace %s {\n" % name)
    out.write("using T = %s;\n" % ctype)
    out.write("const auto D = %s::%s;\n" % (ctype, defval))

    for i, blk in enumerate(leaves):
        out.write("static const T _l%d[] = {" % i)
        out.write("".join("D," if v == defval else "T::%s," % v for v in blk))
        out.write("};\n")
    out.write("static const T *const _leaves[] = {\n")
    _wrap(out, ["_l%d," % i for i in range(nleaf)] or ["0,"], 16)
    out.write("};\n")

    for i, blk in enumerate(supers):
        out.write("static const short _s%d[] = {" % i)
        out.write("".join("%d," % c for c in blk))
        out.write("};\n")
    out.write("static const short *const _supers[] = {\n")
    _wrap(out, ["_s%d," % i for i in range(nsuper)] or ["0,"], 16)
    out.write("};\n")

    out.write("static const short _dir[] = {\n")
    _wrap(out, ["%d," % d for d in directory], 32)
    out.write("};\n")

    out.write("static const int NLEAF = %d, NSUPER = %d, SB_SHIFT = %d, SB_MASK = %d;\n"
              % (nleaf, nsuper, shift, sb - 1))
    out.write(
        "inline %s get_value(char32_t cp) {\n"
        "  unsigned bi = cp >> 7;\n"
        "  short d = _dir[bi >> SB_SHIFT];\n"
        "  short bc = d < NSUPER ? _supers[d][bi & SB_MASK] : (short)(d - NSUPER);\n"
        "  return bc < NLEAF ? _leaves[bc][cp & 127] : (T)(bc - NLEAF);\n"
        "}\n"
        "}  // namespace %s\n" % (ctype, name)
    )


def _check_table(values, ordmap, defval, leaves, nleaf, supers, nsuper, shift):
    """Re-implement get_value() in Python over the compressed arrays and assert it
    reproduces `values` for all 0x110000 code points (catches encoding bugs before
    the C++ ever compiles)."""
    sb_mask = (1 << shift) - 1
    leaf_t = [tuple(b) for b in leaves]
    super_t = [tuple(b) for b in supers]
    inv = {i: n for n, i in ordmap.items()}
    # rebuild directory deterministically the same way emit did
    # (cheap: just recompute codes + dir)
    codes = []
    li = {b: i for i, b in enumerate(leaf_t)}
    for i in range(0, len(values), _LEAF):
        blk = tuple(values[i:i + _LEAF])
        if all(x == blk[0] for x in blk):
            codes.append(nleaf + ordmap[blk[0]])
        else:
            codes.append(li[blk])
    sb = 1 << shift
    codes_pad = codes + [nleaf + ordmap[defval]] * ((-len(codes)) % sb)
    si = {b: i for i, b in enumerate(super_t)}
    directory = []
    for i in range(0, len(codes_pad), sb):
        blk = tuple(codes_pad[i:i + sb])
        if any(x != blk[0] for x in blk):
            directory.append(si[blk])
        else:
            directory.append(nsuper + blk[0])
    for cp in range(MAX_CP + 1):
        bi = cp >> 7
        d = directory[bi >> shift]
        bc = super_t[d][bi & sb_mask] if d < nsuper else d - nsuper
        got = inv[bc - nleaf] if bc >= nleaf else leaf_t[bc][cp & 127]
        if got != values[cp]:
            raise AssertionError("table mismatch at U+%04X: got %s want %s"
                                 % (cp, got, values[cp]))


# ---------------------------------------------------------------------------
# UCD parsers
# ---------------------------------------------------------------------------

def parse_general_category(ucd):
    """UnicodeData.txt -> values[cp] = 'Lu'/'Ll'/.../'Cn'. Handles First>/<Last ranges."""
    defval = "Cn"
    values = [defval] * (MAX_CP + 1)
    rows = []
    with open(os.path.join(ucd, "UnicodeData.txt"), encoding="utf-8") as f:
        for line in f:
            flds = line.rstrip("\n").split(";")
            if len(flds) >= 3:
                rows.append(flds)
    i = 0
    while i < len(rows):
        flds = rows[i]
        cp = int(flds[0], 16)
        if flds[1].endswith("First>"):
            last = int(rows[i + 1][0], 16)
            cat = rows[i + 1][2]
            for c in range(cp, last + 1):
                values[c] = cat
            i += 2
        else:
            values[cp] = flds[2]
            i += 1
    return defval, values


def parse_enum_prop(ucd, relpath, defval="Unassigned"):
    """A 'cp[..cp] ; Value' property file -> (ordered value names, values[cp])."""
    values = [defval] * (MAX_CP + 1)
    order = [defval]
    seen = {defval}
    with open(os.path.join(ucd, relpath), encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0]
            m = PROP_RE.match(line.strip())
            if not m:
                continue
            lo = int(m.group(1), 16)
            hi = int(m.group(2), 16) if m.group(2) else lo
            name = m.group(3)
            if name not in seen:
                seen.add(name)
                order.append(name)
            for c in range(lo, hi + 1):
                values[c] = name
    return order, values


def parse_white_space_ranges(ucd):
    """PropList.txt White_Space -> sorted list of (lo, hi)."""
    ranges = []
    with open(os.path.join(ucd, "PropList.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0]
            m = PROP_RE.match(line.strip())
            if m and m.group(3) == "White_Space":
                lo = int(m.group(1), 16)
                hi = int(m.group(2), 16) if m.group(2) else lo
                ranges.append((lo, hi))
    ranges.sort()
    return ranges


def parse_incb(ucd):
    """DerivedCoreProperties.txt InCB -> sorted (lo, hi, 'Consonant'|'Extend'|'Linker')."""
    incb_re = re.compile(
        r"([0-9A-Fa-f]+)(?:\.\.([0-9A-Fa-f]+))?\s*;\s*InCB\s*;\s*(\w+)")
    ranges = []
    with open(os.path.join(ucd, "DerivedCoreProperties.txt"), encoding="utf-8") as f:
        for line in f:
            m = incb_re.match(line.strip())
            if m:
                lo = int(m.group(1), 16)
                hi = int(m.group(2), 16) if m.group(2) else lo
                ranges.append((lo, hi, m.group(3)))
    ranges.sort()
    return ranges


def parse_case_folding(ucd):
    """CaseFolding.txt -> sorted [(cp, folded)] using simple_case_folding semantics
    (status S preferred, else C; F/T full mappings are not used by regexlib).

    Note: code points with ONLY a full (F) fold — e.g. U+00DF ß, U+0130 İ — have no
    simple fold and are intentionally omitted, so simple_case_folding() returns them
    unchanged."""
    common, simple = {}, {}
    r = re.compile(r"\s*([0-9A-Fa-f]+)\s*;\s*([CFST])\s*;\s*([0-9A-Fa-f ]+?)\s*;")
    with open(os.path.join(ucd, "CaseFolding.txt"), encoding="utf-8") as f:
        for line in f:
            m = r.match(line)
            if not m:
                continue
            cp = int(m.group(1), 16)
            status = m.group(2)
            if status == "C":
                common[cp] = int(m.group(3), 16)
            elif status == "S":
                simple[cp] = int(m.group(3), 16)
    pairs = []
    for cp in sorted(set(common) | set(simple)):
        folded = simple.get(cp, common.get(cp))
        if folded is not None and folded != cp:
            pairs.append((cp, folded))
    return pairs


# ---------------------------------------------------------------------------
# Emitters for the sparse/flat tables (regexlib-specific optimizations)
# ---------------------------------------------------------------------------

def emit_enum(out, name, members):
    out.write("enum class %s {\n  " % name)
    out.write(",\n  ".join(members))
    out.write(",\n};\n")


def emit_white_space(out, ranges):
    out.write("// White_Space (PropList.txt); membership backs \\s.\n")
    out.write("static const char32_t _white_space_ranges[][2] = {\n")
    _wrap(out, ["{0x%04X,0x%04X}," % (lo, hi) for lo, hi in ranges], 6)
    out.write("};\n")
    out.write(
        "inline bool is_white_space(char32_t cp) {\n"
        "  for (auto &r : _white_space_ranges)\n"
        "    if (cp >= r[0] && cp <= r[1]) return true;\n"
        "  return false;\n"
        "}\n"
    )


def emit_incb(out, ranges):
    emit_enum(out, "Incb", ["None", "Consonant", "Extend", "Linker"])
    out.write("// Indic_Conjunct_Break (DerivedCoreProperties.txt); backs grapheme GB9c.\n")
    out.write("static const struct { char32_t lo, hi; Incb v; } _incb_ranges[] = {\n")
    _wrap(out, ["{0x%04X,0x%04X,Incb::%s}," % (lo, hi, v) for lo, hi, v in ranges], 4)
    out.write("};\n")
    out.write(
        "inline Incb incb_value(char32_t cp) {\n"
        "  int lo = 0, hi = (int)(sizeof(_incb_ranges) / sizeof(_incb_ranges[0])) - 1;\n"
        "  while (lo <= hi) {\n"
        "    int m = (lo + hi) / 2;\n"
        "    if (cp < _incb_ranges[m].lo) hi = m - 1;\n"
        "    else if (cp > _incb_ranges[m].hi) lo = m + 1;\n"
        "    else return _incb_ranges[m].v;\n"
        "  }\n"
        "  return Incb::None;\n"
        "}\n"
        "inline bool is_incb_consonant(char32_t cp){return incb_value(cp)==Incb::Consonant;}\n"
        "inline bool is_incb_extend(char32_t cp){return incb_value(cp)==Incb::Extend;}\n"
        "inline bool is_incb_linker(char32_t cp){return incb_value(cp)==Incb::Linker;}\n"
    )


def emit_case_folding(out, pairs):
    out.write("// Simple case folding (CaseFolding.txt, status C/S); backs (?i).\n")
    out.write("static const char32_t _case_fold[][2] = {\n")
    _wrap(out, ["{0x%04X,0x%04X}," % (cp, folded) for cp, folded in pairs], 6)
    out.write("};\n")
    out.write(
        "inline char32_t simple_case_folding(char32_t cp) {\n"
        "  int lo = 0, hi = (int)(sizeof(_case_fold) / sizeof(_case_fold[0])) - 1;\n"
        "  while (lo <= hi) {\n"
        "    int m = (lo + hi) / 2;\n"
        "    if (cp < _case_fold[m][0]) hi = m - 1;\n"
        "    else if (cp > _case_fold[m][0]) lo = m + 1;\n"
        "    else return _case_fold[m][1];\n"
        "  }\n"
        "  return cp;\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# Build the whole generated block
# ---------------------------------------------------------------------------

def version(ucd):
    p = os.path.join(ucd, "VERSION")
    if os.path.exists(p):
        return open(p).read().strip()
    return "unknown"


def build_block(ucd):
    out = io.StringIO()
    ver = version(ucd)
    out.write("// Generated by tools/generate_ucd.py from the Unicode Character\n")
    out.write("// Database, version %s. DO NOT EDIT BY HAND — run:\n" % ver)
    out.write("//   python3 tools/generate_ucd.py update regexlib.h\n")
    out.write("// The UAX #29 grapheme rules and UTF-8 codec that consume these tables\n")
    out.write("// are hand-maintained below this block.\n\n")

    # --- General_Category ---
    # GC_ORDER must match the hand-written `enum class GeneralCategory` above the
    # generated block (ordinal = position); the table stores those ordinals.
    gc_def, gc_vals = parse_general_category(ucd)
    emit_page_table(out, "_general_category_properties", "GeneralCategory",
                    GC_ORDER, gc_def, gc_vals)
    out.write("\n")

    # --- GraphemeBreak (enum value list is version-dependent) ---
    gcb_order, gcb_vals = parse_enum_prop(ucd, "auxiliary/GraphemeBreakProperty.txt")
    emit_enum(out, "GraphemeBreak", gcb_order)
    emit_page_table(out, "_grapheme_break_properties", "GraphemeBreak",
                    gcb_order, "Unassigned", gcb_vals)
    out.write("\n")

    # --- Emoji (Extended_Pictographic etc., for GB11) ---
    emo_order, emo_vals = parse_enum_prop(ucd, "emoji/emoji-data.txt")
    emit_enum(out, "Emoji", emo_order)
    emit_page_table(out, "_emoji_properties", "Emoji",
                    emo_order, "Unassigned", emo_vals)
    out.write("\n")

    # --- Indic_Conjunct_Break (GB9c) ---
    emit_incb(out, parse_incb(ucd))
    out.write("\n")

    # --- White_Space (\\s) ---
    emit_white_space(out, parse_white_space_ranges(ucd))
    out.write("\n")

    # --- Simple case folding ((?i)) ---
    emit_case_folding(out, parse_case_folding(ucd))

    return out.getvalue()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_emit(ucd):
    sys.stdout.write(build_block(ucd))


def cmd_update(ucd, path):
    with open(path, encoding="utf-8") as f:
        content = f.read()
    b = content.find(BEGIN)
    e = content.find(END)
    if b == -1 or e == -1 or e < b:
        sys.exit("error: BEGIN/END UCD markers not found in %s" % path)
    block = build_block(ucd)
    new = (content[: b + len(BEGIN)] + "\n" + block + "\n" + content[e:])
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    print("updated %s (Unicode %s)" % (path, version(ucd)))


def cmd_verify(ucd):
    gc_def, gc_vals = parse_general_category(ucd)
    assert gc_vals[ord("A")] == "Lu", gc_vals[ord("A")]
    assert gc_vals[ord("a")] == "Ll"
    assert gc_vals[ord("0")] == "Nd"
    assert gc_vals[0x3042] == "Lo"  # HIRAGANA A
    gcb_order, gcb_vals = parse_enum_prop(ucd, "auxiliary/GraphemeBreakProperty.txt")
    assert gcb_vals[0x0D] == "LF" or gcb_vals[0x0A] == "LF"
    assert "ZWJ" in gcb_order and "Extend" in gcb_order
    emo_order, _ = parse_enum_prop(ucd, "emoji/emoji-data.txt")
    assert "Extended_Pictographic" in emo_order
    incb = parse_incb(ucd)
    assert any(v == "Linker" for _, _, v in incb)
    ws = parse_white_space_ranges(ucd)
    assert any(lo <= 0x20 <= hi for lo, hi in ws)
    fold = dict(parse_case_folding(ucd))
    assert fold[ord("A")] == ord("a")
    assert fold[0x039C] == ord("μ")  # GREEK CAPITAL MU -> small mu (simple fold)
    assert 0x0130 not in fold      # dotted capital I is full-fold only, not simple
    print("verify: OK (Unicode %s)" % version(ucd))
    print("  general_category pages, grapheme=%d emoji=%d incb_ranges=%d ws_ranges=%d folds=%d"
          % (len(gcb_order), len(emo_order), len(incb), len(ws), len(fold)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["emit", "update", "verify"])
    ap.add_argument("file", nargs="?", help="target file for `update`")
    ap.add_argument("--ucd-dir", default=DEFAULT_UCD)
    args = ap.parse_args()

    if args.command == "emit":
        cmd_emit(args.ucd_dir)
    elif args.command == "verify":
        cmd_verify(args.ucd_dir)
    elif args.command == "update":
        if not args.file:
            ap.error("update requires a FILE argument")
        cmd_update(args.ucd_dir, args.file)


if __name__ == "__main__":
    main()
