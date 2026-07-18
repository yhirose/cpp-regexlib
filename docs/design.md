# regexlib — internal design

How `regexlib.h` works inside. The user-facing reference (syntax, semantics,
public API) is [`reference.md`](reference.md); this document is the engine.

The implementation is a stack of accelerators over one proven baseline. The
**grapheme Pike VM** (a Thompson-NFA virtual machine that segments the subject
into Unicode extended grapheme clusters) is correct but slow; every faster path
— a leftmost-first lazy DFA, a UTF-8 byte path for non-ASCII subjects, bounded
capture engines, SIMD prefilters, view-based result containers — must produce
*exactly* what that baseline produces. The whole design is organized around
keeping that equivalence while running, whenever provably safe, on something
much faster than the Pike.

Two contracts are non-negotiable and shape everything:

- **Linear time / ReDoS immunity.** No engine backtracks unboundedly; an
  unanchored search is a single forward pass that never re-seeds per candidate.
- **Leftmost-first (Perl) semantics**, on every path, for every pattern.

---

## Architecture at a glance

A pattern is compiled once into bytecode; each match request is then routed to the
cheapest engine that is provably equivalent to the baseline for that pattern and
that subject.

```
  pattern
    |   compile (sec 3): lower the AST to NFA bytecode
    v
  Program(s):  byte program        (Op::Byte sub-automata, run by the DFA tiers)
               code-point program  (Op::Char/Class/Any, run by the Pike family)
    |
    |   match request on a subject:  test / search / find_iter / find_all
    v
  tier dispatch (sec 2):  is the pattern DFA-able? + is the subject simple?
    |
    +-- Tier 1  capture-free & DFA-able  -->  lazy DFA finds [s,e); no Pike   (sec 2,4,5)
    |
    +-- Tier 2  captures & DFA-able      -->  DFA finds [s,e), then a capture
    |                                         engine fills groups in the span (sec 6)
    |
    +-- Tier 3  lookaround / overflow    -->  grapheme Pike VM over the whole
    |                                         subject, helped by prefilters   (sec 7)
    v
  result delivery (sec 8):  MatchResult (one) | find_iter (lazy bulk) | find_all (eager bulk)
```

**Which engine actually runs** depends on both the pattern's shape and the
subject's content:

| Pattern is… | Subject is… | Engine that runs |
| --- | --- | --- |
| capture-free, DFA-able | ASCII (or *any* subject in UnicodeScalar mode) | lazy **DFA** — the fast path (§2) |
| capture-free, DFA-able | non-ASCII, but every cluster is one code point | **EGC byte-path** DFA (§4) |
| capture-free, DFA-able | non-ASCII with a real multi-code-point cluster | grapheme **Pike** (§4) |
| has captures, DFA-able | (any) | DFA locates the span, then a **capture engine** (§6) |
| lookaround / nested empty loop / DFA state-cap overflow | (any) | grapheme **Pike** — the fallback (§2) |

The grapheme Pike VM (§1) is the one proven baseline; every other row is an
accelerator that must return *exactly* what the Pike would. §9 is how that
equivalence is enforced.

### Where decisions live: `Plan` vs. per-call state

Everything decided *per pattern* — the compiled programs, the tier-eligibility
flags (`dfa_ok_`, `byte_path_`, …), and the prefilter state (§7) — lives in one
immutable struct, `Regex::Plan`. Its constructor builds it in named stages
(`compile_core`, `analyze_core`, `plan_egc_byte_path`, `plan_assert_tiers`, …),
and match-time code only reads it as `plan_.…` (every match entry point is
`const`). Auxiliary programs are stored as `Plan::Compiled` — a program bundled
with its `Match` pc, whose `ok()` answers "was this program built". State that
mutates per call lives elsewhere: the lazy-DFA caches and scratch buffers in
the per-thread `FindCache` (§8).

---

## 1. Matching model: the grapheme cluster

The defining choice: **the unit of matching is the Unicode extended grapheme
cluster (EGC)** (UAX #29), not the code point. `.` consumes exactly one
user-perceived character, so `/.+/` against `"👨‍👩‍👧‍👦"` matches a single
element. Match positions are **byte offsets** into the original UTF-8 subject
and always fall on cluster boundaries.

Grapheme breaking is **stateful** — whether a boundary exists between two code
points depends on their `Grapheme_Cluster_Break` properties and the surrounding
run — which is the root of both the engine's distinctiveness and its one
performance cliff (§4): a byte automaton sees bytes, not clusters.

### Segmentation (`Segmented`)

```cpp
struct Segmented {
  std::vector<std::u32string> graphemes;  // code points of each cluster
  std::vector<size_t> byte_begin;         // size == graphemes.size() + 1 (last = end)
  std::string_view source;                // the original UTF-8 subject
  bool ascii = false;  // all bytes < 0x80, so grapheme index == byte index
};
```

`segment()` has an **ASCII fast path** (every byte `< 0x80` → each byte is its
own cluster, `byte_begin[i] == i`, no decode/break work) and a **general path**
(decode to code points remembering byte offsets, then group via
`reg::unicode::grapheme_length`). `segment_cp()` is the UnicodeScalar counterpart:
one entry per code point — a plain UTF-8 decode, **not** grapheme breaking. The
Pike VM runs over either `Segmented` unchanged.

### Class membership is decided by the base code point

A class / `\d\w\s\p{…}` classifies a cluster **by its base (first) code point**
— the cluster behaves like the single character it displays as:

```cpp
bool matches(const std::u32string &g, bool icase) const {
  return g.empty() ? negate : matches_cp(g[0], icase);
}
```

So `\w`/`\p{L}` match `é` whether NFC (`U+00E9`) or NFD (`e` + `◌́`), and `\s`
matches a CR-LF cluster. A single-code-point cluster *is* its own base, so this
is identical to `matches_cp` there — which is why the byte/code-point engines,
which call `matches_cp` directly, agree with the grapheme engine on
single-code-point input. (This base-code-point rule is a deliberate semantic
choice; an earlier "a class matches only single-code-point clusters" rule was
wrong.)

### Pattern literals are grapheme-segmented too

A literal in the pattern matches a cluster only by **full equality** of its code
points (`lit_match`), not by base code point — so an exact literal is stricter
than a class. For that to behave predictably the pattern's literal text must be
segmented into clusters exactly as the subject is. Typed literals already are
(the tokenizer hands the parser whole clusters), but **escapes — `\r`, `\n`,
`\uXXXX` — each parse to their own single-code-point literal**, so an escaped
run like `\r\n` would stay two literals and could never match the indivisible
CR-LF cluster (UAX #29 GB3) a subject presents. `parse_concat` therefore runs a
fusion pass (`fuse_literal_graphemes`) that re-segments each maximal run of
adjacent, unquantified literals on grapheme boundaries, so `\r\n` compiles to
the single `U"\r\n"` cluster literal — exactly the node the equivalent typed
text produces. (A quantified escape, e.g. the `\n?` in `\r\n?`, is its own atom
and does not fuse.) In CodePoint mode the pass is a no-op: a multi-code-point
literal emits the same per-code-point match sequence as the separate literals.

---

## 2. The leftmost-first lazy DFA

**In one line:** replace the all-threads-at-once Pike VM with a deterministic
state machine (a DFA), built lazily as the subject is scanned, that still tracks
thread *priority* — so it returns Perl's leftmost-first match, not the longest.

The Pike VM's hot cost is `add_thread`'s ε-closure (the set of states reachable
without consuming any input) plus the capture copy-on-write — structural to a
Pike VM, 1–2 orders of magnitude behind RE2 on dense matches.
The fix: **a DFA that produces the leftmost-first match directly** — the RE2 /
Rust `regex-automata` design.

It is a **priority-ordered, match-cut** lazy DFA. A DFA state is an **ordered**
(priority) vector of NFA program counters, interned *without sorting* (order is
part of state identity). The ε-closure mirrors the Pike's `add_thread` (DFS
pre-order, `Split.x` before `Split.y`) but carries no captures and **cuts at the
first `Match`**: program counters at lower priority than a reached `Match` are
dropped (a live match kills later alternatives). A plain "record last accept"
forward scan then yields the leftmost-first end: greedy `a+` keeps its
higher-priority continue thread (longest run), lazy `a+?` and `a|ab` stop at the
cut.

There is **no longest-safe predicate**. An earlier DFA was leftmost-*longest*
(POSIX) while the contract is leftmost-*first* (Perl), so a static predicate
gated which patterns the DFA could serve — incomplete (it rejected DFA-able
alternations) and unsound (it mis-classified some variable-optional-prefix
patterns). The ordered+cut DFA expresses thread priority, so it is leftmost-first
for *any* pattern, with no predicate.

**Unanchoredness lives in the program**, not in per-position reseeding (which
would break priority across start positions): the forward program is
`lf_prog_ = (?s:.)*? + pattern`, a single lazy lowest-priority prefix the match
cut removes once any pattern match is live. For byte automata the prefix is
**any-BYTE**, not any-code-point (the latter cannot skip a lone UTF-8
continuation byte).

### Recovering the start (the reverse DFA)

A DFA state is the *set* of program counters it occupies; it carries no "where
did this begin" (carrying it would make the state count grow with the input).
So the forward scan reports where a match *ends*, not where it began. The start
is recovered by a **reverse byte DFA** scanning a reversed program leftward from
`e`, recording the smallest accepting `s`. The reverse DFA stays **unordered**
(sorted): "is `[s, e)` a match?" is a boolean reachability question. A reverse
*Pike* would need the grapheme `Segmented`, defeating tier-1's no-segmentation
win — hence a byte DFA.

### Tier dispatch

Three tiers, picked structurally from the pattern:

| Tier | When | What runs |
| --- | --- | --- |
| **1** | capture-free ∧ DFA-able | Forward ordered+cut DFA finds the leftmost-first end `e`; the reverse scan finds the start `s`; return `[s, e)`. **No Pike.** Covers the ASCII grapheme tier, the UTF-8 byte tier (§4/§5), and `^ $ \b \A \z` via an assertion-aware DFA. Targets `\w+`, `[a-z]+`, literals, general alternation (`a\|ab`, `(?m)^…\|…$`). |
| **2** | captures ∧ DFA-able | The lf DFA locates `[s, e)`, then a capture engine resolves groups *bounded by `e`* (§6). Whole-match captures (every group == the whole match, e.g. `(\w+)`) skip the engine entirely. |
| **2a** | captures ∧ assertion-DFA-able (`^ $ \b \A \z` + groups, e.g. `(\w+)$`, `\.([a-z]+)$`) | The **assertion-aware** DFA locates `[s, e)` (capture-stripped); the bounded backtracker (`bitstate_bytes`, which evaluates the assert ops via `empty_flags_cp`) resolves groups on it — replacing the Pike, which dominated these patterns (`(\w+)$`: 5300→700 ns). The locate runs on the grapheme assert DFA (ASCII subject) or the **byte** assert DFA (`ByteAssertDfa`: a non-ASCII EGC subject, or **US mode on any subject** — see below). |
| **3** | DFA-ineligible (lookaround / nested empty-loop) or state-cap overflow | Pike VM over the whole subject, with the §7 prefilters. The fallback. |

`dfa_ok_` = "regular" program (no lookaround, no `Op::Loop`); `dfa_assert_ok_`
additionally admits empty-width assertions, served by the assertion DFA. Both
are purely structural. Tier 2a is the capture analogue of the Tier 1
assertion-DFA path: an assert-bearing capture pattern (not `dfa_ok_`) still gets
a DFA-located span instead of the Pike, because the backtracker now evaluates
assertions absolutely (`$` = real end-of-text, not the span end).

**The byte assert tier is shared by EGC non-ASCII and US mode.** The
`ByteAssertDfa` decodes the UTF-8 byte program one code point at a time and
evaluates assertions code-point-wise — which is exactly what an EGC non-ASCII
subject (byte == grapheme) *and* US matching (code points, no graphemes) both
need. So US does not get a copied assert engine: a US `^ $ \b`-anchored pattern
(capture or not) reuses `assert_byte_find_span` / `assert_prefix_find` /
`ByteAssertDfa` on **any** subject, with the same prefilters and the same
`cp_prog_` bitstate capture resolution. `assert_byte_path_ok` is the only
mode-aware gate (US: any subject; EGC: non-ASCII, no multi-code-point cluster).
The EGC-ASCII grapheme assert DFA stays as a separate fast path. US captures
whose span overflows the bitstate still fall back to the code-point Pike.

### Canonical tier names (the `[Tier: …]` labels)

The numbered tiers above say *what engine runs*; each public entry point
(`test` / `search` / `match` / `fill_matches` / `find_iter`) walks its own
dispatch ladder over them. The ladders genuinely differ (anchoring, capture
resolution, streaming state), so they are not unified — instead every branch
carries a `[Tier: …]` label in the source, with one canonical name per
(pattern-class × subject-class) combination:

| Label | Gate | What runs |
| --- | --- | --- |
| `Literal` | `literal_only_` | memmem (+ grapheme-boundary check); no subject classification |
| `LiteralAlt` | `literal_alt_` non-empty | Teddy / first-byte multi-literal scan, ordered verify |
| `AssertAnchor` | `assert_.anchor_gatefree` | memmem + per-hit boundary & anchor-flag verify; any subject |
| `AnchoredOnePass` | `aop_.ok` (the `^body$` / `^body` validation shape: assert-free greedy-only body) | ONE compact deterministic walk from 0 (`anchored_onepass_try`, shared by search / match / test) — u16 rows, accept byte off the dependency chain; a trailing `$` is the accept-lands-at-n test (uncut table); bare `^body` uses the leftmost-first-cut table, whose last accept is the exact leftmost-first end. Sound on ANY subject: the walk bails on a non-ASCII byte, and on `\r` when the pattern could split a CR-LF cluster (`onepass_walk_bails_cr`) |
| WordOnePass | `wop_.ok` (`\b body \b`, capture-free, word-only head/tail atoms; with a trailing `\b`, every accepting state's outgoing bytes must be word bytes) | per-candidate compact walk: candidates = non-word-preceded viable start bytes; the trailing `\b` is one next-byte test at the last accept (exact via the accepting-state admission: a passed-over accept is always followed by a word byte) |
| `Dfa/US` | `us_ ∧ dfa_ok_` | byte lazy DFA over `byte_prog_` (suffix/inner prefilters); `+cap`: groups via the bounded cp engine |
| `Dfa/EgcByte` | EGC ∧ `egc_byte_path(text)` | byte lazy DFA (icase-prefix / suffix / inner prefilters, fused EGC literal scan); `+cap` as above |
| `Dfa/Ascii` | EGC ∧ `dfa_ok_` ∧ ASCII subject | lazy DFA over the grapheme program (byte == grapheme); `+cap` as above |
| `Assert/Ascii` | `dfa_assert_ok_` ∧ ASCII subject | `AssertDfa` (start recovery via the cached `AssertRevDfa`) + assert literal/prefix/suffix/word prefilters; `+cap`: assert-aware bitstate |
| `Assert/Byte` | `assert_byte_path_ok(text)` (US: any subject; EGC: non-ASCII simple) | `ByteAssertDfa` / `ByteAssertRevDfa`, same prefilters |
| `Pike` / `Pike/cp` | always (the fallback) | grapheme Pike VM over `prog_`; US: code-point Pike over `cp_prog_` |

Every ladder tries its eligible tiers top-down and falls through on a DFA
state cap; `Pike` is the proven baseline every other tier must agree with
(§9). To see how one tier behaves across all entry points, grep its label.

### Linearity (the O(n²) trap)

The unanchored search must never restart per candidate (anchored-per-candidate
retry is O(n²) and can hang for hundreds of seconds). So: the forward DFA scan
is a **single pass**, resumed from where it left off; the reverse scan is
**clamped not to go left of the previous match's end** (reverse work sums to
total match length); after a match the forward scan resumes from the confirmed
Perl end. Net: forward touches each byte once, reverse sums to match length, the
tier-2 capture pass runs only inside matched windows. Linear.

The candidate+verify **prefilters** (§7) are the sanctioned exception — they DO
re-verify from each literal candidate, which is quadratic when a repeat in the
pattern can absorb its own candidate byte (`a[a-z]+0` over `aaaa…`: every `a`
is a candidate and every failed verify re-walks the overlapping tail). Every
such site therefore carries a **failed-walk byte budget** (the `WalkBudget`
type; exhaustion returns `kWalkBail`):
successful verifies advance the cursor past their end and cannot overlap, so
only FAILED walks are deducted; exhausting the budget (≈ one subject's worth)
permanently abandons that prefilter for the call/iterator and falls back to
the single-pass machinery above. Worst case is one wasted subject-length of
walking, once — O(n) total. Guarded sites: the fused EGC prefix scan, the
ReverseInner non-absorbing verify, the (?i)-prefix probe verify, the assert
literal prefix/suffix finders, the unbounded one-pass candidate drivers, the
suffix-tier candidate loop (a scalar-verify absorb bail re-enters the
O(n)-per-candidate DFA reverse scan), and the chain-capture walks (a
right-of-anchor element may absorb anchor bytes, so failed walks can overlap).
The fill/iterator loops own ONE budget across all their calls (a per-call
budget would reset at every match and still admit O(matches × n)). The other
prefilters need no budget: their verifies are O(1)/pattern-bounded (literal,
Teddy, anchor flags) or shape-bounded by admission (the var-pre suffix's
one-atom rule, the word scan's one-candidate-per-word).

### Safety net: the DFA state cap

Interned states are bounded; exceeding the cap abandons the DFA and falls back to
the Pike VM (unaffected). Keeps a pathological `dfa_ok_` pattern (`.*a.{18}`
needs 2¹⁸ states) from exhausting memory.

---

## 3. Compiler & bytecode

The compiler lowers the AST to an NFA `Program`. Two pressures shaped it —
**compile time** and **program memory** — both dominated by Unicode classes
(`\w`, `\p{L}`), which expand to hundreds of UTF-8 byte-range sequences.

### The instruction (`Inst`) — 16 bytes, trivially relocatable

```
Char  Class  Any  Byte        // consuming
Split Jmp  Save  Loop         // control flow (Loop = empty-guarded back-edge)
Look                          // zero-width lookaround (subs[x])
AssertBOL AssertEOL AssertWB AssertNWB AssertBeginText AssertEndText AssertEndTextNL
Match
```

`Inst` is **16 bytes and trivially copyable.** The heavy operands — literal text
(`std::u32string`), char class (`CharClass`), lookaround body (`Program`) — do
**not** live in the instruction; they live in out-of-line pools on the owning
`Program`:

```cpp
struct Program {
  std::vector<Inst> insts;
  std::vector<std::u32string> lits;            // Char literals
  std::vector<CharClass> classes;              // Class operands
  std::vector<std::shared_ptr<Program>> subs;  // lookaround bodies
  int nslots = 2;                              // 2 per group; group 0 = whole match
};
```

The instruction stores only a small index, and since no operand index coexists
with a control-flow target they all **overlap the `x` slot** (the op selects the
meaning): `lit_idx()`/`cls_idx()`/`sub_idx()` all read `x`; `Byte` packs its
`[lo,hi]` bounds into `x`. With `op` in a `uint8_t` and no owned members, the
struct is 16 bytes of POD. This is what makes building a large Unicode-class byte
automaton a **`memcpy`** with no per-instruction construct/move/destruct. Steady
throughput is insensitive to `Inst` size (the byte DFA runs off transition tables
and never reads `Inst` in the hot loop), so the win is compile time and memory —
exactly where it was needed (`\w+` byte program: 359 → 159 KiB after the
160→32→16-byte shrink).

### UTF-8 range compilation

In UnicodeScalar mode and on the byte path a class / `.` / `\d\w\s\p{…}` is a
**byte sub-automaton**. A code-point range `[lo, hi]` compiles to a set of UTF-8
byte-range *sequences* (Russ Cox's `utf8_ranges`: split at UTF-8 length
boundaries, then where the leading byte differs). A code point lies in `[lo, hi]`
iff its UTF-8 bytes are matched by exactly one sequence — so the byte DFA matches
Unicode classes **with no decoding**, just stepping bytes. `build_class_block`
emits one set as an alternation of `Byte` chains where **only `Split`/`Jmp` carry
targets** (`Op::Byte` advances by fall-through), so a block built at base 0 can be
appended at *any* offset by rebasing just the `Split`/`Jmp` targets — the
relocatability the 16-byte `Inst` buys.

### Class-compilation caches

A Unicode class expands to the same hundreds of ranges every time it appears, and
a `Regex` emits each class more than once (forward + reverse programs, and per
occurrence). Three `static`, mutex-guarded memo layers, keyed by the *source*
class (so the lookup is proportional to the predicate, not the expansion):

1. **`enum_cp_ranges`** — `\p{…}`/predicate → code-point ranges, by scanning
   `0..0x10FFFF` once (surrogates excluded), cached by predicate.
2. **`utf8_ranges_cached`** — a code-point set → its UTF-8 byte-range sequences,
   memoized by the normalized set, direction-independent.
3. **`class_block_cached`** — the whole emitted `Inst` block, memoized by
   `(set, direction)`; each later emission is a `memcpy`-append + target rebase.

Together these took Unicode-class compile from the dominant cost to a block
`memcpy` (~12–14× on the compile benchmark: `\w+` 0.44 → 0.037 ms).

### The two-program split

A Unicode-mode pattern emits up to two programs from one AST:

- the **byte program** (`Op::Byte` sub-automata) the byte DFA runs — large
  (a class is its UTF-8 sub-automaton), but never re-walked per character;
- the **code-point program** (`cp_prog_`, `Op::Char`/`Class`/`Any`) the
  Pike-family engines run, where a Unicode class stays a *single* `Op::Class`
  (decode one code point, test it) — tiny, so the backtracker / one-pass capture
  engines never pay the byte-automaton size.

The operand-pool split lets both share the exact same `Inst`/`Program` types.

---

## 4. The non-ASCII cliff and the EGC byte path

Every DFA tier is a byte/code-point automaton, so historically an `is_ascii()`
gate dropped *any* non-ASCII subject off every DFA tier onto the grapheme Pike —
a ~6× cliff (dense `\w+`: 58 → 9 MB/s with one `é`). On real prose the trigger
was subtler: **CRLF line endings**, where each `\r\n` is one cluster (UAX #29
GB3), pushed the whole subject onto the grapheme Pike at ~24 MB/s.

**The key observation: when every cluster in the subject is a single code point,
grapheme-unit and code-point-unit matching coincide** — so the UTF-8 byte DFA
produces exactly the grapheme engine's result without segmenting. For a regular
(`dfa_ok_`) pattern the engine compiles byte programs alongside the grapheme one
(`byte_prog_`, `byte_rev_prog_`, `byte_lf_prog_`) and sets `byte_path_`. The
ordered+cut byte DFA is leftmost-first for any `dfa_ok_` pattern — no
longest-safe predicate, exactly as on ASCII.

### `simple_from` — the per-subject gate

`egc_byte_path(text)` decides per subject. It scans (vectorized) to the first
non-ASCII byte; a pure-ASCII subject bails to the cheaper ASCII tiers, a non-ASCII
one pays a check only over the remainder. `simple_from(s8, start)` returns true
iff the subject has **no multi-code-point cluster** (so code-point ≡ grapheme,
and the byte DFA's answer equals the grapheme engine's). It is one forward pass:
check the ASCII prefix for a `CR×LF` fusion; from `start`, decode and reject the
moment two adjacent code points fuse (`gb_fuses`); **SIMD-skip printable-ASCII
runs** (a printable-ASCII run cannot hold a multi-code-point cluster). Any fusion
→ fall back to the grapheme Pike.

### CRLF — the cliff, and `crlf_byte_safe`

`simple_from` rejects every `\r\n`, so CRLF prose never took the byte path. But a
CR-LF cluster only matters if the *pattern* can tell a one-cluster CR-LF from a
two-byte `\r``\n`. Most can't. `crlf_byte_safe(node)` is a structural predicate —
a pattern is safe if no element observes the difference:

- a literal never contains `\r`/`\n`;
- a class matches **neither** `\r` nor `\n`, or matches **both** but only as the
  directly-repeated atom of an unbounded greedy repetition (a greedy run consumes
  `\r` then `\n` in two byte-steps exactly where the grapheme engine consumes the
  cluster in one — same span, no boundary between). A class matching **exactly
  one** of `\r`/`\n` diverges and is unsafe;
- `.` touches `\r`/`\n` only under dotall, and only transparently;
- transparency stops at group boundaries and at fixed-count / non-greedy structure.

`can_match_empty_` (nullable) additionally forces a **non-empty** match for CRLF
admission (an empty match could land on the LF interior to a cluster — a position
that exists in byte mode but not grapheme). `simple_from_crlf_ok` is then
`simple_from` plus "a CR×LF cluster is permitted", SIMD-skipping whole ASCII runs
(including the `\r\n` breaks) to the next non-ASCII byte.

Together with the §7 prefilters this took `/Sherlock/` from ~24 to ~13000 MB/s.

### `crlf_collapse` — bounded `\r\n`-class repeats

`crlf_byte_safe` admits a both-`\r\n` class only as an *unbounded-greedy* atom; a
**bounded or lazy** repeat (`[^"']{0,30}`, `[^u-z]{13}`) counts a CR-LF as one
cluster but two bytes and is rejected — exactly the patterns that lost worst on
the (CRLF) Sherlock corpus (`["'][^"']{0,30}[?!.]["']` at ~15 MB/s). For a
**capture-free** pattern whose every `\r\n`-touching class is **negated**, the
engine rewrites each such class `C` into `(?:\r\n | C')`, where `C'` is `C` with
`\r`/`\n` excised (added to its negated range set). The `\r\n` branch consumes a
CR-LF pair as a single element — matching the grapheme engine's one-cluster step
— and is the *only* CR-LF consumer (no split parse), so the collapsed byte
programs (`byte_prog_` / `byte_rev_prog_` / `byte_lf_prog_`, compiled from the
collapsed AST) reproduce the grapheme engine on a paired-CRLF subject.
`egc_byte_path` then admits such subjects, gated by `no_lone_crlf`: a lone `\r`
or `\n` is unmatchable in the collapsed program, so every `\r\n` must be paired.

Capture-free only — with captures the byte DFA locates the span by grapheme count
(CR-LF = 1) but groups are resolved on `cp_prog_`, a code-point program (CR-LF =
2), so a bounded group spanning a CR-LF would drop the match; such patterns stay
on the grapheme Pike. This took `["'][^"']{0,30}[?!.]["']` from ~15 to ~740 MB/s
(ahead of RE2). `[a-q][^u-z]{13}x` clears the cliff too (~7 → ~50 MB/s); its
residual gap is the `.{13}` DFA-state blow-up, not the cliff.

For a collapse pattern with a **required suffix anchor**, the per-call gates
(`simple_from_crlf_ok` + `no_lone_crlf`, two O(n) passes before the suffix
prefilter's own pass) are folded into the suffix scan itself
(`egc_fused_collapse_ok` → `egc_literal_fused_find` with `collapse=true`). The
cluster condition rides the scan's non-ASCII stop. The lone-CR/LF condition is
**not** scanned for at all: a lone CR/LF only matters where the collapsed byte
program actually *walks*, so the per-candidate verify checks just the examined
window (`crlf_pairs_ok_window` — the DFA reverse scan reports its examined
floor, the forward re-expansion its reach, and the window is widened one byte
so a pair straddling its edge is judged by its real neighbor). Gaps between
candidates can hold lone CR/LF harmlessly, the gap scan stays on the cheap
plain predicate, and the subject is read once. A disqualifying window (a lone
CR/LF — i.e. ordinary Unix-newline text — near a match) or a fusing cluster
bails to the non-fused ladder; the iterator re-primes it (`reprime_unfused`)
rather than downgrading to the Pike, so plain LF text still lands on the ASCII
DFA tier. A var-pre suffix is admitted when the scalar chain verifier serves
it (exact ends, no forward re-expansion past the vetted window). Took
`[a-q][^u-z]{13}x` on the CRLF Sherlock corpus from ~7.7 to ~11.8 GB/s (rure
~12.9), and the window localization lifted the negated-class quote pattern
~11.5 → ~14.8 GB/s.

### The assertion byte tier

`\b`/`^$`/`\A\z` patterns are `dfa_assert_ok_` (not `dfa_ok_`), served by an
assertion-aware DFA. The same EGC-byte-path idea is built for them: a
code-point-aware `ByteAssertDfa` runs a non-ASCII subject through the assert DFA,
reusing the `crlf_byte_safe_` / `can_match_empty_` gate.

### What stays on the grapheme Pike

A subject that genuinely contains a multi-code-point cluster — combining marks,
ZWJ emoji, Hangul jamo, regional-indicator flags, a `Prepend` run — fails
`simple_from` and runs on the grapheme Pike, where breaking is stateful and
correct. That residual cliff is inherent (no byte automaton for a stateful
grapheme `.`); §5 is the escape hatch.

**CR-LF on a pure-ASCII subject.** The ASCII fast path assumes byte ≡ code point
≡ cluster, which holds for every ASCII byte except a CR-LF pair (one cluster per
GB3, but two bytes). To keep ASCII consistent with the grapheme model, `segment()`
routes any ASCII subject containing a `\r` to the grapheme path (so the pair
fuses), and `ascii_grapheme_ok()` gates the ASCII DFA / assert tiers on the same
`crlf_byte_safe_ && !can_match_empty_` predicate as the non-ASCII byte path: a
CRLF-sensitive pattern (a counted `\r\n`-class repeat, dotall `.{n}`, a nullable
body, multiline `^`/`$`) on an ASCII-CRLF subject defers to the CR-LF-fusing Pike.
This needs no special case for `.`: a non-dotall `.` already excludes `\r\n`, so
the byte path and the grapheme engine both stop before the cluster — they agree,
and `.`-proximity patterns (`Holmes.{0,25}Watson`) stay on the byte DFA at full
speed. The only real divergence is an empty match on the LF interior of a
cluster, excluded by `!can_match_empty_`.

---

## 5. UnicodeScalar mode (the byte automaton)

The `CodePoint` match unit (`reg::set_default_match_unit`) switches the matching
unit to the **Unicode scalar (code point)** — the RE2 / Rust `regex` model — and
removes the cliff entirely: the
byte DFA runs directly over raw UTF-8 with no segmentation and no `is_ascii`
gate. Syntax, leftmost-first semantics, linear time, and byte-offset reporting
are unchanged; only the unit of `.`/classes and the offset boundary change.

It keeps the **two programs** of §3 (`prog_`/byte + `cp_prog_`/code-point).
`run()`/`run_saves()` are parametrized on the program, so the proven grapheme
Pike runs `cp_prog_` unchanged with code-point semantics and byte offsets;
subjects feed it via `segment_cp` (plain UTF-8 decode).

### Case folding at compile time

A byte DFA cannot fold per byte, so icase is baked into the byte program at
compile time. `case_fold_groups` scans `0..0x10FFFF` once (cached), grouping code
points by `simple_case_folding` into orbits of size ≥ 2 (`{a,A}`, `{k,K,U+212A}`);
`case_expand` adds, for every orbit intersecting a literal/class, all its members
— so `prog_` accepts every case variant directly, matching the same
fold-equivalence the Pike applies at match time on `cp_prog_`. (`ß`→`ss` full
folding is out of scope, as in the grapheme engine.)

DFA-based engines (byte DFA, one-pass) apply to US (any subject) and ASCII
grapheme mode, but not to non-ASCII *grapheme* matching, where breaking is
stateful. So US is the fast path for non-ASCII; non-ASCII grapheme captures stay
on the grapheme Pike.

---

## 6. Capture engines

The ordered+cut DFA locates the leftmost-first `[s, e)`; groups are then resolved
*within that span* (bounded by `e`) by the cheapest capable engine over the
**code-point** program `cp_prog_`. Three engines, tried fastest-first:

| Engine | Runs when | How it works |
| --- | --- | --- |
| **CpOnePass** (`build_cp_onepass`) | the pattern is one-pass; span is all single-code-point | A deterministic capture-recording DFA: pc-set states, each transition carrying `(next state, bitmask of capture slots to set here)`. Records captures in one forward pass at ~DFA speed. Built in two flavours: *uncut* (the full accept set — a longest-match engine, run bounded by `e` or with an accept-at-`n` condition) and *leftmost-first cut* (each state's closure is explored in thread-priority order and truncated at its first `Match`, so an unbounded walk's last accept is the exact leftmost-first end; sound for Alt-free greedy-only programs, where priority order is ascending pc). The per-byte step is **one packed `u32` load** — next-state id, capture-write mask id and a next-state-accepts bit in a single word — instead of three loads from separate arrays (three cache lines on the dependency chain); a state that self-loops on all but ≤ 8 ASCII bytes with no slot write (a repeat run like `\S+`) skips the whole run with one `scan64` for its exit set instead of a dependent load per byte — engaged once per state *entry* after four scalar probe bytes, since short runs cost less on the per-byte loop than the SIMD setup. A non-ASCII code point in the span aborts it (→ BitState). |
| **BitState** (`bitstate_bytes`) | not one-pass; span ≤ `kBitStateCap` | Bounded leftmost-first backtracking over `cp_prog_` on the located span, decoding code points on the fly (no segmentation), with a visited bitmap over `(pc, byte-pos)` so it stays O(prog × span); capture writes undo on backtrack. |
| **code-point Pike** (`run_saves` on `cp_prog_` + `segment_cp`) | span overflow, or a DFA state-cap that drops the whole pattern | The universal fallback. |

Whole-match captures (every group == the whole match, e.g. `(\w+)`) skip all
three: each group's span *is* `[s, e)`. All engines are leftmost-first over the
same NFA, so they agree with the grapheme engine.

**Unbounded one-pass find (`cp_onepass_find`, `onepass_unbounded_`).** The
bounded chain walks each match three times (forward DFA for `e`, reverse DFA
for `s`, then the capture engine over `[s, e)`). When the AST has **no
alternation, no lazy repeat, and no capturing group under a repeat**, the
table is built with the leftmost-first cut, under which the walk's last
accept from a fixed start *is* the leftmost-first end (greediness alone is
not enough: adjacent nullable repeats like `x(?:ab)?(?:abc)?` commit before
the longest accept) and no capture slot is written after the final accepting
position — so, given the match START from a candidate source, ONE unbounded
one-pass walk yields the end and every capture. Two candidate
sources drive it on the ASCII tier: a required ASCII literal prefix
(`\{\{\s*(\w+)\s*\}\}`, `/users/(\d+)`; every match begins with it, so the
first completing candidate is leftmost) and a non-absorbing ReverseInner
floor (`(\w+)=(\S+)`; the floor is the exact start). A failed-walk byte
budget guards linearity (a repeat that can absorb the prefix byte, e.g.
`a([a-z]+)0` over `aaaa…`, would otherwise re-walk overlapping tails
quadratically) — exhaustion falls back to the located-span chain. Lifted
mustache `\{\{\s*(\w+)\s*\}\}` ~0.69 → ~1.3 GB/s and markdown
`\[([^\]]+)\]\(([^)]+)\)` ~0.18 → ~0.52 GB/s (both past rure), key=value
~0.85 → ~1.1 GB/s; `match()` uses the same walk anchored at 0. The drivers
route through one front door (`onepass_driver_find`: literal prefix →
non-absorbing ReverseInner → position scan, where every position is a
candidate and a wrong one usually dies on its first byte — access-log
~0.13 → ~0.31 GB/s, past RE2), and a pattern whose only assertion is a
trailing `$` joins the family with the accept-lands-at-n condition
(`\.([a-zA-Z0-9]+)$`: 73 → 50 ns).

**Anchored scalar-chain capture find (`chain_capture_find`,
`analyze_chain_capture`).** One step past the one-pass walk: when the *whole*
pattern is a concatenation of ASCII literal chars and one-code-point class
repeats around a fixed interior/edge literal, and the parse around an anchor
occurrence is **forced**, a match and *all* its groups come from plain byte
walks — no automaton at all. `(\w+)=(\S+)`: find `=` (rare-byte / pair-probe
scan), walk `\w` left, walk `\S` right; the group spans are the run
boundaries. Forcing conditions: left of the anchor (walked right-to-left),
adjacent elements' ASCII sets disjoint — or every left element fixed-count —
each variable element `min ≥ 1` greedy, and no left element may consume an
anchor byte (the walk then never crosses an earlier anchor occurrence, which
pins the leftmost start and keeps candidates ordered); right of the anchor
(walked forward), each variable element ASCII-disjoint from its successor
(the greedy max-run can never need backtracking), the final element
unconstrained; every capture wraps exactly one element. A non-ASCII byte near
a candidate bails to the automaton drivers, and the walks draw on the shared
failed-walk budget (a right element may absorb anchor bytes, so failed
candidates can overlap). key=value `(\w+)=(\S+)` ~944 → ~2160 MB/s.

---

## 7. Prefilters

A prefilter answers "what is the next position that could start a match?" with a
cheap SIMD-friendly scan over raw bytes, so the engine only runs at candidates.
Constraints: **soundness** (false positives ok, never a false negative — each is
derived from the program), **linearity** (single pass, no per-candidate reseed),
**no external dependencies** (built from `memchr`/`memcmp` + hand-written
NEON/SSE; never a fast platform `memmem`).

**One scan loop (`scan64` / `scan64_visit`).** Every prefilter byte scan is the
same shape — "first index in `[off, n)` whose byte satisfies a
16-lane-expressible predicate" — so the fast loop exists exactly once: an
eight-block entry ramp (so a caller resuming after a hit pays the cheap
one-block cost when hits are dense), then four 16-byte blocks per iteration
with a single any-hit test per 64 bytes. 64 bytes per iteration is what lifts a
stop-free scan from ~25 GB/s (libc `memchr`: 16 bytes per iteration plus a call
per stop) to ~65 GB/s, and every scan expressed through the primitive gets that
rate. A predicate is a small struct supplying the platform lane mask and the
matching scalar test (`PredEq`, `PredPair`, `PredInList`, `PredSetPair`, …),
and predicates **compose**: `PredOrNonAscii<P>` adds the byte-path tiers'
stop-at-non-ASCII to any scan. The `_visit` form drives candidate verification
*in place* — the verifier runs on each hit inside the stride and a rejected
candidate continues from the next ctz, not a loop restart — so the
candidate+verify prefilters below (the `find_substr` compare, the `(?i)` fold
compare, the fused-collapse verify) pay one bit-scan per false positive even
when the probe byte is common.

**Where they run.** The DFA tiers fold the skip into the forward scan's start
state: a literal-prefix **memmem** (`find_substr` over `prefix_` / `byte_prefix_`)
first, else a first-byte set skip. The memmem is essential, not redundant — the
unanchored lf program is `(?s:.)*?` + pattern, whose start ε-closure includes the
prefix's `.` (every byte), so the first-byte set is universal and never skips for
a literal-led pattern; without the memmem a literal scan on a pure-ASCII subject
falls to byte-at-a-time DFA (≈7× slower than the byte tier, which always had the
memmem). The standalone prefilters also stay live on the Pike fallback
(lookaround, etc.). The dispatch is exclusive: `dfa_ok_ && ascii` → DFA, else
Pike + prefilters. Two prefilter families reason over different alphabets: the
grapheme-program prefilter (`prefix_`, `first_bytes_.set`) over ASCII bytes; the
byte-program prefilter (`byte_prefix_`, …, from `byte_prog_`) over arbitrary
UTF-8 on the byte tiers (sound because the byte automaton is self-delimiting).
The per-subject byte-path gate (`first_nonascii` — the SIMD scan to the first
non-ASCII byte) is computed **once per call** and shared by `egc_byte_path` and
`ascii_grapheme_ok` (both take the precomputed index), so the dispatch classifies
the subject a single time instead of one O(n) pass per gate — otherwise a fast
literal find on a pure-ASCII subject would pay the gates, not the find.

- **Literal-prefix substring search (`find_substr`)** — the **rare-byte trick**.
  `memmem` is not reliably fast (macOS floors at ~1.3 GB/s), so instead `memchr`
  the **rarest** byte of the literal (chosen by an English-prose frequency table:
  space common, punctuation/digits/non-ASCII rare → good probes), then `memcmp`
  to verify (both legs ride `scan64_visit`; zero dependencies). An all-ASCII
  prefix (`prefix_.ascii`) is `memmem`-skippable on *any* UTF-8 subject. When
  the rarest byte is itself **common** (per-mille frequency ≥ 16 — the
  genuinely common lowercase letters: `ing`, `Holmes`), the scan upgrades to a
  **two-byte pair probe** (`PredPair` — rure's memmem shape): stop only where
  *both* of the needle's two rarest bytes appear at their exact needle
  distance, multiplying the two densities — an order of magnitude fewer stops
  (`ing` on the Sherlock corpus: 8033 → 2934) for one extra load per block.
  The pair distance is capped (48) so the extra readahead keeps the vector
  loops, and the partner is picked **at plan time** (`pair_probe` → the
  `probe2` fields), not per call — a per-find recomputation costs per match.
- **Short (?i) literal → case-orbit alternation (`decase_ascii_literal`)** — a
  pure printable-ASCII `(?i)` literal whose every character is *clean* (its
  only fold pre-images are its own ASCII cases, per the live fold table) and
  with ≤ 4 cased letters is rewritten at plan time into the explicit
  case-sensitive alternation (`(?i)the` → 8 branches) and `icase_` is dropped
  — the Teddy/LiteralAlt tier then serves it like any literal alternation.
  The orbit enumerates exactly the byte strings the icase literal matches, on
  any subject, so every tier downstream is automatically correct. Lifted
  `(?i)the` (dense) ~0.73 → ~1.7 GB/s (past rure ~1.4 and PCRE2-JIT ~1.6). An
  unclean letter (`k`, `s`) or a longer literal (`(?i)Sherlock` = 256
  branches) keeps the prefix-prefilter paths below; a literal with no cased
  letters just drops the inert `icase_` and runs the plain Literal tier.
- **Case-insensitive literal prefix (`find_substr_icase`)** — under `IgnoreCase`,
  an all-ASCII required prefix is still a useful filter, but only on an **ASCII
  subject**: ASCII case folding is exact there, whereas over UTF-8 a fold
  pre-image (Kelvin K → k, long-s ſ → s) is multi-byte and a byte-level fold
  scan could land inside a cluster. So `prefix_.icase` is set (prefix stored
  lowercased) iff the prefix is all-ASCII and the engine is not US mode, and
  *every* prefix-skip site is split. On an **ASCII subject** the sites (DFA scan,
  `search_at_or_after`) call `find_substr_icase` — a SIMD `memchr2` for both cases
  of the rarest **case-folded** byte (`'k'` over `'s'`, since lowercase `'s'` is
  common) then an ASCII fold verify; lifted `(?i)Sherlock` ~1000 → ~8000 MB/s
  (≈ rure; RE2 ~440). On a **non-ASCII subject** a byte-level fold scan can land
  inside a cluster, so the prefilter instead works in raw UTF-8: a `memchr2` over
  **two rare case-folded probe bytes** — one drawn from an *unclean* fold orbit,
  one from a *clean* (single-byte) orbit — each pruned/guarded so a multi-byte fold
  pre-image (Kelvin `K`, long-s `ſ`, whose leading byte is `0xE2`) is never skipped,
  then a bounded anchored verify over the located window. Candidate starts are
  pre-pruned by the byte first-byte set (`byte_first_bytes_.set`); the orbits come from
  `case_fold_groups()`. Lifted non-ASCII `(?i)Sherlock` ~1035 → ~6316 MB/s
  (≈ rure 0.82×; previously unfiltered). Sound on both: the verify is the engine's
  own fold-aware match. The pair probe has a `(?i)` analogue (`PredFoldPair`):
  when the fast probe's char is still common (`k` in `(?i)Sherlock`) *and* the
  subject contains no fold pre-image lead byte of **any** prefix char (the
  `pair_leads` guard — every prefix char is then exactly one byte on this
  subject), the scan stops only where the two rarest chars' case pairs sit at
  their exact prefix distance. Byte distances being fixed, a hit pins the
  single candidate start — no window walk. Stops on the CRLF Sherlock corpus
  3681 → 771; `(?i)Sherlock` ~6.3 → ~8.6 GB/s, `(?i)Holmes` ~2.7 → ~9.0.
- **Teddy — SIMD multi-literal.** A literal alternation (`fox|dog|cat`) has no
  single prefix and a first-byte skip stops at every `f`/`d`/`c`. Teddy (the
  Hyperscan / Rust-regex "slim" design) matches the leading `N` bytes of *all*
  alternatives 16 positions at a time: each fingerprint owns one bit of an 8-bit
  mask; per 16-byte chunk a `PSHUFB`/`TBL` nibble lookup plus a shifted-overlap AND
  leaves a nonzero lane exactly where some literal's `N`-byte prefix occurs.
  `N` is the longest fingerprint the shortest literal allows (capped at 4). NEON
  and SSSE3 are hand-written; a scalar `teddy_hit` is the tail/fallback. The
  SSSE3 scan (`_mm_shuffle_epi8`) is not part of the x86-64 baseline (SSE2 is),
  so a plain `-O2` Release build defines neither `__SSSE3__` nor `-mssse3` and
  used to silently fall to the scalar Teddy — a ~10–18× cliff on
  literal-alternation patterns that hit every default Linux build (macOS is NEON;
  cl.exe assumes an SSSE3 baseline). The scan now lives in a
  `target("ssse3")`-tagged `teddy_scan_ssse3` reached through a cached
  `cpu_has_ssse3()` runtime check (`__builtin_cpu_supports`, `REGEXLIB_SSSE3_DYNAMIC`
  tier), so the PSHUFB path compiles at the SSE2 baseline and runs whenever the
  CPU supports it — no build flag required. `REGEXLIB_DISABLE_SSSE3` forces the
  scalar path (exotic toolchains / A-B testing). The same dispatch shape was
  tried on `scan64_visit` for the VEX/AVX2 encoding win and **rejected on
  measurement**: an attributed wrapper cannot inline into baseline callers, and
  outlining the scan loses the caller fusion (probe + verify as one compiled
  unit), costing more than VEX gains — see the comment at `scan64_visit`.
  Host-tuned builds (`-march=native`, `REGEXLIB_ENABLE_NATIVE`) deliver that
  win instead. Lifted
  `fox|dog|cat` ~19 → ~390 MB/s. When **every** alternative is a full ASCII
  literal (not just a shared prefix — `analyze_literal_alternation` → `literal_alt_`),
  Teddy is not a prefilter but the matcher itself: `literal_alt_locate` takes the
  Teddy hit, tries the literals in alternation order, and returns the span
  directly with **no DFA verify** (a grapheme-boundary check keeps it sound on
  any subject) — a pure-literal-alternation tier. A *mixed* alternation (some
  branch not a bare literal) keeps Teddy as a candidate-finder feeding the DFA.
  `teddy_next` dispatches the runtime fingerprint length to a compile-time-`N`
  `teddy_scan<N>`, so the nibble tables live in registers instead of being
  copied to a stack array per call (a 128-byte memmove that cost ~10% of the
  tier — the iterator calls this once per match); the short-literal verify is
  an inlined `bytes_eq` (the libc `memcmp` *call* was another ~20%).
- **First-byte (dead-byte) skip** — the generalization of a literal prefix to a
  leading first-byte *set* (`analyze_first_bytes` over the start ε-closure).
  `skip_to_first_byte` is tiered by set size (1 → `memchr`; ≤ 8 → NEON/SSE2 scan;
  else table lookup) and gated on `first_bytes_.sparse` (≤ 32): a dense set
  (`\w` ≈ 63 bytes) would fire rarely and only add overhead, so it pays nothing.
- **ASCII-prefix skip on non-ASCII subjects** — a non-ASCII subject on the
  grapheme Pike still benefits if the pattern has an all-ASCII required prefix:
  `prefix_skip_nonascii` runs `find_substr` over raw UTF-8 with a
  grapheme-boundary guard (part of removing the `/Sherlock/` cliff).
- **Required-suffix-literal scan (`suffix_find`)** — the mirror of the literal
  prefix, for patterns that *begin* with a class/`.` (so the DFA's own first-byte
  skip is dense and useless) but *end* with a fixed ASCII literal after a
  fixed-length body — e.g. `[a-q][^u-z]{13}x`, whose trailing `x` is rare. The
  forward DFA would otherwise walk every byte; instead `find_substr` the rare
  suffix. The literal is a **seed, not the answer**: a hit recovers a *floor* for
  the start (a reverse-DFA scan from the suffix, floored at the non-overlap bound),
  but the end is always retaken by an anchored **forward** DFA from there — a
  greedy variable body can sit the literal mid-match (`...ing` inside `singing`),
  so reading the end off the suffix would clip it. A *fixed-length* pre-suffix
  (`analyze_byte_suffix`) makes each suffix occurrence a unique leftmost-first
  candidate; the memmem cursor advances past failed candidates while the floor
  stays put, so a later suffix still completes a match that began before a failed
  one. A *variable-length* pre-suffix (`suffix_.var_pre`, rure's *ReverseSuffix*)
  extends this to `[a-zA-Z]+ing` and the like — but **only** when the body is
  step-1 prefix-closed (a one-code-point atom under an unbounded repeat). A general
  variable pre-suffix breaks leftmost-first: a longer match can start left of an
  earlier suffix hit yet end at a later one (the fuzzer caught `(?:[^a-c].\w+)?b`
  taking `[1,2)` over the correct `[0,4)`), so those fall back to the plain DFA.
  Unlike the others this runs *on* the DFA tiers (find_all / matches / scan /
  search), capture-free, and is gated off when a literal prefix already exists (the
  prefix memmem is then optimal). Lifted `[a-q][^u-z]{13}x` ~57 → ~1650 MB/s
  (RE2 ~260; rure ~12000 via a flatter verify) and `[a-zA-Z]+ing` ~258 → ~1640
  (past RE2 ~389). Two refinements close the rest of that gap. (1) A **scalar
  forced-parse verifier** (`Verify::Scalar`, `analyze_suffix_scalar_verify`):
  when the pre-suffix body is a chain of ASCII literal chars and
  one-code-point class repeats whose parse is *forced* — every pair of
  elements that can become adjacent has disjoint byte sets (immediate
  neighbors, and, since a `min=0` element can be empty, the transitive closure
  across empty-able elements), or every element is fixed-count, where position
  alone forces the layout — each candidate is confirmed by plain table walks
  (~0.3 ns/B) instead of the reverse-DFA + forward-retake pair (~2.2 ns/B
  each). `absorb_last` covers the `[a-zA-Z]+ing` shape, where the **last**
  occurrence inside a class run is the match end (an overlap-periodicity
  argument forces it). A non-ASCII byte — or, on the collapse tier, any CR/LF
  — near a candidate bails that one candidate to the DFA verify. (2)
  **Class-tail anchors** (`suffix_.cls`, `PredSetPair`): the anchor need not
  be a literal — a pattern *tail* of two fixed small classes
  (`["'][^"']{0,30}[?!.]["']`) is scanned as a class-pair adjacency. The two
  classes must be **disjoint**: an overlapping pair admits a one-byte anchor
  slide (`[ab]+[bc][cd]` on `abcd` would report a clipped match), and
  admission is chain-or-nothing — the scalar verifier's conditions must hold,
  the DFA serving only the per-candidate bails. Quoted strings on the CRLF
  corpus ~1.25 → ~2.5 GB/s.
- **Rare interior literal (`ReverseInner`)** — for a class-led pattern with **no**
  literal prefix *or* suffix but a rare fixed literal in the **middle**
  (`\w+ Holmes \w+`, `\w+@\w+`): with nothing at either end the DFA has no skip and
  walks every byte. `find_substr` the interior literal, recover a start floor with a
  reverse DFA over the prefix, then run the normal lf forward + reverse from there.
  Same **seed-not-answer** discipline as the suffix scan: the end is retaken by a
  full forward pass from the floor, because a greedy prefix can swallow the interior
  literal (`.{2,}c\d?`) and reading the span off the literal would be wrong (the
  inner analogue of the *singing* bug — the fuzzer caught it). Lifted
  `\w+ Holmes \w+` ~386 → ~10300 MB/s, `\w+@\w+` ~275 → ~21400. (An interior-gap
  literal *alternation*, `Holmes.{0,25}Watson`, is left to Teddy, which already
  fires.) Capture patterns are admitted too — the prefilter only *locates* the
  span, and the capture engine resolves groups on it — but only with a
  **single-node pre** (`(\w+)=(\S+)`): the capture chain re-walks the located
  span anyway, so a long pre-part makes the extra reverse(pre) pass a net loss
  on dense matches (the 7-group access-log pattern regressed before this
  gate). Lifted `(\w+)=(\S+)` over a config corpus ~285 → ~830 MB/s (past RE2
  ~310).
- **Assertion-tier fixed-text literal** — an assertion pattern (`(?m)^X`, `X$`,
  `^X$`, `\bX\b`) is served by the assertion DFA, which otherwise scans every
  position. When stripping the zero-width assertions leaves a single **fixed
  literal** (`fixed_text`, extracted recursively), the engine `memmem`s that
  literal and confirms each hit with the anchored assertion DFA, shared through
  `assert_find_span` / `assert_byte_find_span`. Lifted
  `(?m)^Sherlock Holmes|Sherlock Holmes$` ~229 → ~12700 MB/s (≈ rure ~8000; RE2
  ~455). An assertion body that *ends* in a literal is caught by the
  required-suffix prefilter below; one with no usable literal anchor keeps the
  full scan.
- **Assertion-tier required-suffix literal** (`assert_.suffix`,
  `analyze_assert_suffix`) — the suffix analogue of the leading-literal prefilter,
  for an assertion pattern that *ends* in a fixed ASCII literal after a
  fixed-length / one-code-point-repeat body. The assertion DFA would scan every
  position; instead `assert_suffix_find` `memmem`s the trailing literal and
  confirms each occurrence with the anchored assertion scan, recovering the
  variable start by reverse. A special **word-scan fast shape** handles the exact
  shape `\b \w{n,m} <lit> \b` (`\b\w+n\b`, `\b\w+ing\b`) — "a whole word ending in
  `<lit>`" — with **no DFA at all**: `memmem` the literal, confirm the trailing
  `\b` (the next code point is non-word), then walk left over word code points to
  the run start (`assert_word_find`), checking the `\w` run length against
  `{n,m}`. Sound because the assert tier serves only single-code-point clusters
  (code point == grapheme) and the `\w` here is exactly the bare Word predicate,
  so the walk reproduces the regex. Lifted `\b\w+n\b` ~190 → ~776 MB/s (past
  rure/RE2).
- **Assertion-tier leading literal** (`assert_.prefix`) — when the assertion
  pattern is *not* a fixed text but its **first consuming atom** is a fixed ASCII
  literal (only zero-width assertions before it: `\.([a-z]+)$`, `^foo(\w+)`,
  `\bID(\d+)`), every match begins with that literal, so a `memmem` of it yields
  every candidate start; an **anchored** assert forward scan then verifies the
  whole match (leading + trailing assertions) and gives the variable end. Unlike
  the fixed-text and trailing-literal prefilters this is **not** gated
  capture-free — it drives the location for the assert-capture tier (2a) as well,
  so `\.([a-z]+)$` (capture) and `\.[a-z]+$` (capture-free) both skip the
  position-by-position assert scan (EGC ~640/~515 → ~220/~90 ns). memmem order is
  start order and every match starts with the prefix, so the first verifying hit
  is leftmost-first.
- **Single-pass pure-literal find** — a plain printable-ASCII literal pattern
  (`literal_only_`) used to pay *two* passes: classify the subject for the
  byte-path gate, then `memmem`. Printable ASCII is
  `Grapheme_Cluster_Break=Other`, so a literal hit can be a false cluster boundary
  in only two locally-checkable ways (a `Prepend` immediately before, an
  `Extend`/`ZWJ`/`SpacingMark` immediately after); the literal tier checks just
  those and skips whole-subject classification, matching in **one** pass. `zqj`
  ~20000 → ~38600 MB/s, `/Sherlock/` ~13500 → ~23800 (past RE2). The same
  byte-level literal prefilter is also wired into **UnicodeScalar** mode — it had
  been EGC-only, a missing-prefilter hole that left US `zqj` at ~450 MB/s.

Every prefilter has a correct scalar fallback and the dispatch is exclusive, so
disabling any prefilter changes speed, never results.

---

## 8. Result delivery: `search`/`find_iter`/`find_all`

Where a match *is* (the engine above) is separate from how results are
*delivered*. The API splits by arity and laziness:

- **`search()` / `match()`** — one match, returned as a self-contained owning
  `MatchResult` (copies the matched text + group strings). One copy is cheap and
  lifetime-safe; the cost of owning copies only bites in bulk.
- **`find_iter()`** — *lazy* bulk. A `MatchIter` range steps the engine **one match per
  `++`** (reusing this thread's warm DFAs), so breaking out early skips scanning
  the rest. Each iteration yields a `Match` **view** (offsets + views
  into the subject, `to_owned()` to keep one), valid only until the next `++`. A
  temporary subject is rejected (the views would dangle).
- **`find_all()`** — *eager* bulk. A `Regex::MatchList` columnar container: all
  matches up front as a Structure-of-Arrays of byte offsets (`vector<uint32_t>`,
  one `2*(ngroups+1)` row per match) plus one subject buffer; `str()`/`group()`
  are `string_view`s into it via a `Match` proxy. Random access, `size()`,
  multiple passes.

Both bulk forms are **view-based** — no per-match `std::string`/`std::vector`
allocation. (An owning `vector<MatchResult>` is just `find_iter()`/`find_all()` +
`to_owned()`.) This is deliberate: profiling dense `\w+` once found the per-match
materialization (allocs + reallocating a vector of heavy 120-byte objects)
dominating the run while the offsets-only scan already beat RE2. The columnar
container runs at the offsets-only scan rate (~2.7× over an owning vector on
dense matches) at ~15× less memory.

### Shared stepping

Both bulk forms walk matches with the same per-tier single-step primitives the
engine already has: `dfa_forward_lf` + `dfa_reverse_scan` (capture-free),
`+ capture_saves_bytes` (captures, byte offsets, no strings), `assert_find_span`
(assert tiers), `run_saves` + `append_match_spans` (Pike). `find_all()` runs the
tier loop to completion appending rows; `find_iter()` runs one step per `++`. A DFA
tier that hits the state cap mid-`find_iter` downgrades to the Pike VM and continues
from the current cursor.

### Cross-call DFA reuse (`FindCache`)

Each call would otherwise rebuild its `LazyDfa`s from scratch — for `\w+` the
full-Unicode byte DFA is ~4 ms to build, so tokenizing many small documents with
one `Regex` re-discovers the same states every call (a benchmark shows ~57 vs
~11 MB/s, one document vs 8000 small ones — a 5× gap that is *construction*, not
scanning). A **caller-held `FindCache`** (the PCRE2 `match_data` / Hyperscan
scratch / `regex-automata` `Cache` idiom) persists the DFAs across calls:

```cpp
class Regex::FindCache {       // opaque; holds only text-independent state:
  const Regex *owner_;         //   the DFA transition tables + Scratch capacity
  std::optional<LazyDfa> ...;  // (segmentation is per-text and not cached)
  Scratch sc_;
};
MatchList find_all(std::string_view, FindCache&) const;
MatchIter find_iter(std::string_view, FindCache&) const;
```

The no-cache `find_iter(s)`/`find_all(s)` reuse a **`thread_local` cache** bound by a
process-unique `Regex` id (the id avoids the ABA hazard of a raw-address key — a
destroyed `Regex` whose address is reused gets a different id, so a stale DFA is
never served). The mutable-cache-in-`Regex`-plus-mutex model (RE2's) was rejected
because it would serialize concurrent matching on a shared `Regex`; matching here
stays lock-free, the `Regex` stays `const` and shareable. **Lifetime/threading
contract**: one `FindCache` per thread (not shared), destroyed before the `Regex`
it bound to. A cache that trips the state cap simply keeps falling back —
correct, just unaccelerated.

`MatchIter` additionally owns its **own** `Scratch` (Pike/backtracker state) and
re-fetches the shared warm DFA each step, so it is safe across a suspension point
(a `++` boundary where the caller might run other matching on the same thread):
another regex rebinding the `thread_local` cache merely costs a rebuild, never a
dangling read.

---

## 9. Verification — differential fuzzing with no trusted reference

A regex engine has **no known-correct answer to check against**: the obvious
reference — another engine you trust to be right — doesn't exist here, because the
candidates disagree (`std::regex` differs across standard libraries on `\b` at
string end and on complexity limits; PCRE/RE2 differ on POSIX vs Perl, Unicode
level, empty-match handling). Worse, the bugs that matter are **equivalence
bugs** — an accelerator that disagrees with the baseline — and the tempting check
(assert it agrees with another of the engine's own paths) is the trap: both can
**share the same wrong assumption** because they go through the same dispatch and
compiled program.

The strategy (`test/regexlib_fuzz.cc`, fixed seed `0xC0FFEE`, run under
ASan/UBSan) is layered:

- **Layer 1 — invariants that need no known-correct answer (fails CI).** Random
  patterns/subjects never crash, hang, or throw anything but `RegexError` at
  construction, and every match is self-consistent: `m.str == subject.substr(m.begin,
  len)` (and every group); `scan()[0] == search` when matched; matches ordered and
  non-overlapping; `test == search().matched`. These hold for *any* correct engine,
  so checking them needs no reference.
- **Layer 2 — DFA-vs-Pike differential (the reference we actually trust).** The accelerated path
  is checked against the grapheme Pike running the *same* semantics, with the Pike
  **forced** by a transformation the accelerator cannot see through:

  ```cpp
  pike = Regex("(?:" + pat + ")(?:\\b|\\B)");
  ```

  The always-true zero-width `(?:\b|\B)` matches at every position and consumes
  nothing, making the program non-DFA-able (`dfa_ok_`/`dfa_assert_ok_` bow out) so
  this `Regex` runs the Pike — while matching the exact same whole spans. The
  scan's full sequence is compared span-for-span **and capture-for-capture**
  against the forced-Pike result. This is the check that caught the CRLF
  soundness bugs: `gen_subject` deliberately emits `\r` and `\n`, and only a
  grapheme engine that *does* treat CR-LF as one cluster can expose a byte path
  that wrongly treats it as two.
- **Layer 3 — US-vs-EGC.** UnicodeScalar is a separate byte automaton; the
  reference it is checked against is the proven EGC engine, valid because on a
  subject of **single-code-point, single-grapheme** characters
  (`a b 1 ␣ é ñ α β 日 A É Α`) grapheme- and code-point-unit matching coincide. The alphabet includes case pairs so the
  `IgnoreCase` differential exercises folding (US folds at compile time, EGC at
  match time — they must agree).
- **Layer 4 — non-ASCII assertion byte tier** against the forced grapheme Pike,
  multiline on/off.
- **Layer 5 — `find_iter` vs `find_all`.** The lazy `find_iter()` full sequence must equal
  the eager `find_all()` (every whole span and capture) — the two view containers
  go through different assembly (one-step-per-`++` vs run-to-completion). Plus a
  **`FindCache` reuse** check: a single cache reused across a subject sequence vs
  fresh per subject must agree, guarding cross-subject state accumulation.

A `std::regex` differential is kept but is **informational, never a gate** (its
semantics vary across standard libraries). A portable semantic-regression corpus
(`regexlib_corpus`), adjudicated once against Python's `re` and baked in, needs no
reference engine at run time.

**The design principle:** the guarantee is not "we tested a lot of cases" — it is
that **every accelerator is checked against a baseline that cannot share its blind
spot**, with the baseline forced into play by a transformation the accelerator
cannot exploit. When adding an accelerator, it is not done until a differential
pits it against the forced baseline on inputs that exercise its specific
assumption; a self-consistency check is not a substitute.

---

## Invariants (non-negotiable)

- **Linear time / ReDoS immunity** — single forward pass, reverse clamp, state
  cap; no engine backtracks unboundedly.
- **Leftmost-first for every pattern** — the ordered+cut DFA needs no
  longest-safe predicate, so no class of pattern silently gets a non-Perl answer.
- **Grapheme semantics are the contract** — a class is decided by the cluster's
  base code point; `.` is one cluster; offsets land on cluster boundaries. The
  EGC byte path is a pure accelerator, gated by `simple_from` /
  `simple_from_crlf_ok`, falling back to the grapheme Pike otherwise.
- **Every accelerator == the forced baseline**, held by the differential fuzzer
  at all times (DFA, byte path, capture engines, prefilters, both view
  containers), checking spans **and** captures, with CR/LF and case pairs in the
  generated subjects.
- **No external dependencies** — Unicode tables generated into the header;
  prefilters from `memchr`/`memcmp` + hand-written SIMD.
- **`Inst` stays 16 bytes and trivially copyable** — class-block emission and
  program growth are `memcpy`.
