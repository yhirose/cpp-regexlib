# Unicode data pipeline

regexlib ships as a single, dependency-free header. The Unicode tables it needs
are **generated into `regexlib.h`** from the Unicode Character Database (UCD) by
the scripts here — there is no runtime or build-time dependency on any other
library.

## What regexlib needs from the UCD

| Feature | Data | Source file |
|---|---|---|
| `\w` `\d` `\p{L\|N\|P\|M}` | General_Category | `UnicodeData.txt` |
| grapheme clusters (UAX #29) | Grapheme_Cluster_Break | `auxiliary/GraphemeBreakProperty.txt` |
| grapheme GB11 (emoji ZWJ) | Extended_Pictographic | `emoji/emoji-data.txt` |
| grapheme GB9c (Indic) | Indic_Conjunct_Break | `DerivedCoreProperties.txt` |
| `(?i)` | simple case folding | `CaseFolding.txt` |
| `\s` | White_Space | `PropList.txt` |

The **data** (property tables + the version-dependent `GraphemeBreak` / `Emoji` /
`Incb` enum value lists) is generated. The **algorithms** that consume it — the
UTF-8 codec and the UAX #29 grapheme break rules (`is_grapheme_boundary`) — are
hand-maintained C++ in `regexlib.h`, outside the generated block. Algorithms are
not auto-derived from the spec; only the property data they read is.

## Pinned version

The current target is recorded in `ucd/VERSION` (Unicode **17.0.0**) and pinned by
SHA-256 in `ucd/SHA256SUMS`. The raw `*.txt` inputs are large and reproducible, so
they are **not committed** (`ucd/.gitignore`); fetch them on demand.

## Regenerate

```sh
python3 tools/fetch_ucd.py                  # download + verify pinned inputs
python3 tools/generate_ucd.py verify        # parse sanity checks
python3 tools/generate_ucd.py update regexlib.h   # splice the generated block
```

The generated block lives between `// [BEGIN GENERATED UCD BLOCK]` and
`// [END GENERATED UCD BLOCK]` in `regexlib.h`.

## Bump to a new Unicode version

1. Edit `ucd/VERSION`.
2. `python3 tools/fetch_ucd.py --refresh-sums` (re-pins `SHA256SUMS`; review the diff).
3. `python3 tools/generate_ucd.py update regexlib.h`.
4. **Review the UAX #29 rule skeleton** (`is_grapheme_boundary` in `regexlib.h`) against
   the new UAX #29 revision history — new *rules* (rare) are hand-applied; new *property
   values* come through automatically via the regenerated enums/tables.
5. Run the tests, including the grapheme oracle below.

## Verification oracles

* `tools/generate_ucd.py verify` — parse-level sanity.
* **Full-range self-check** — every regeneration re-derives each property
  directly from the parsed UCD and asserts the emitted table matches across all
  code points (General_Category, Grapheme_Cluster_Break, Emoji, White_Space, and
  simple case folding). Code points that have only a full fold (ß, İ, …) have no
  simple fold and return the code point unchanged.
* **Official UAX #29 test** — `ucd/auxiliary/GraphemeBreakTest.txt` passes 766/766
  through `reg::unicode::is_grapheme_boundary`.
* The regexlib test/fuzz/corpus suites pass with the generated tables.

---

## Other tools

* `check_doc_identifiers.py` — verifies that backtick identifiers in
  `docs/*.md` / `README.md` still exist in `regexlib.h` / `test/*.cc`, so a
  rename cannot silently rot the docs. Run as `just lint-docs`; CI runs it on
  every push.
