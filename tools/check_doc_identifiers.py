#!/usr/bin/env python3
"""Check that code identifiers mentioned in the docs still exist in the code.

Renames rot the docs silently: a member or function renamed in the header
leaves stale backtick references behind (e.g. `byte_suffix_var_` survived the
prefilter-struct rename until a later refactor stumbled on it). This script
extracts identifier-shaped tokens from inline code spans AND fenced code
blocks in the Markdown docs and verifies each one still occurs in regexlib.h
or test/*.cc (the docs also describe the fuzzer and the bench/corpus
harnesses).

Checked token shapes (the ones that rot on a rename):
  - trailing-underscore members:        dfa_ok_, suffix_, byte_prefix_probe_
  - snake_case functions/identifiers:   analyze_byte_suffix, find_iter
  - CamelCase types (two humps or more): FindCache, MatchResult, ByteAssertDfa
  - dotted member references:           prefix_.icase, suffix_.var_pre —
    checked as the EXACT dotted spelling against the source text, so a struct
    field rename cannot hide behind its still-existing parent

The known-identifier set is harvested from the sources with comments STRIPPED:
a stale name surviving in a source comment must not validate the same stale
name in the docs (that exact circle happened with prefix_icase_). Identifiers
that are canonical in comments by design (the [Tier: ...] labels) are
allowlisted instead.

Usage: python3 tools/check_doc_identifiers.py   (from the repo root)
Exits 1 and lists file:line for every stale token found.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [ROOT / 'regexlib.h'] + sorted(ROOT.glob('test/*.cc'))
DOCS = sorted(ROOT.glob('docs/*.md')) + [ROOT / 'README.md']

# External / non-code jargon that legitimately appears in code spans.
ALLOW = {
    # Unicode property and segmentation names (UAX #29 / UCD)
    'Grapheme_Cluster_Break', 'Extended_Pictographic', 'Regional_Indicator',
    'SpacingMark', 'ZWJ', 'InCB',
    # other engines' / std internals cited for comparison
    'ReverseSuffix', 'ReverseInner', 'regex_automata', 'pcre2_match_data',
    'match_data', 'wchar_t',
    # illustrative placeholders in doc examples, not real code
    'lvalue_string', 'rvalue_string', 'read_file', 're_comma',
    # build / tooling
    'CMakeLists', 'cmake_minimum_required', 'FetchContent',
    'add_subdirectory', 'target_link_libraries', 'BUILD_BENCH',
    # canonical [Tier: ...] vocabulary — lives in code COMMENTS by design
    # (every dispatch rung carries its label), so comment-stripped harvesting
    # cannot see it
    'LiteralAlt', 'EgcByte', 'AssertAnchor',
}

# A span is skipped entirely when it looks like one of these.
SPAN_SKIP = re.compile(
    r'\.(h|cc|cpp|md|py|yml|txt)\b'   # file names / paths
    r'|^https?://'                     # URLs
    r'|^\$'                            # shell command lines
    r'|^-D'                            # cmake/compiler flags
)

TOKEN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
TRAILING_UNDERSCORE = re.compile(r'^[A-Za-z]\w*_$')
SNAKE = re.compile(r'^[a-z][a-z0-9]*(?:_[a-z0-9]+)+_?$')
CAMEL = re.compile(r'^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+$')
# A struct-member reference spelled the way the code spells it (foo_.bar /
# foo_.bar.baz). The single-word field side (bar) matches none of the shapes
# above, so dotted references are checked as exact substrings instead.
DOTTED = re.compile(r'\b[A-Za-z]\w*_(?:\.\w+)+')

# C++ comment stripper for the known-set harvest. String literals containing
# // or /* would be over-stripped; that only ever REMOVES tokens from the
# known set (a false positive, fixed by allowlisting), never hides rot.
CPP_COMMENT = re.compile(r'//[^\n]*|/\*.*?\*/', re.S)


def candidates(span):
    for tok in TOKEN.findall(span):
        if len(tok) < 3 or tok in ALLOW:
            continue
        if (TRAILING_UNDERSCORE.match(tok) or SNAKE.match(tok)
                or CAMEL.match(tok)):
            yield tok


def doc_spans(text):
    """Yield (lineno, span) for inline `code` spans and fenced-block lines."""
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith('```'):
            in_fence = not in_fence
            continue
        if in_fence:
            yield lineno, line
        else:
            for span in re.findall(r'`([^`]+)`', line):
                yield lineno, span


def main():
    known = set()
    code_text = []
    for src in SOURCES:
        code = CPP_COMMENT.sub(' ', src.read_text(encoding='utf-8'))
        known.update(TOKEN.findall(code))
        code_text.append(code)
    code_text = '\n'.join(code_text)

    stale = []
    for doc in DOCS:
        for lineno, span in doc_spans(doc.read_text(encoding='utf-8')):
            if SPAN_SKIP.search(span):
                continue
            for tok in candidates(span):
                if tok not in known:
                    stale.append((doc.relative_to(ROOT), lineno, span, tok))
            for ref in DOTTED.findall(span):
                if ref not in code_text and TOKEN.match(ref) and \
                        ref.split('.', 1)[0] not in ALLOW:
                    stale.append((doc.relative_to(ROOT), lineno, span, ref))
    for path, lineno, span, tok in stale:
        print(f'{path}:{lineno}: `{span}` — "{tok}" not found in '
              f'regexlib.h / test/*.cc (comments excluded)')
    if stale:
        print(f'{len(stale)} stale identifier reference(s).', file=sys.stderr)
        return 1
    print(f'docs OK: all identifier references exist in the sources '
          f'({len(DOCS)} doc files checked)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
