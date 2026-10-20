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
| lookaround / nested empty loop / a DFA that gave up on its cache (§2) | (any) | grapheme **Pike** — the fallback (§2) |

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
single-code-point input. `\b`/`\B` ask the same question of the clusters on
either side (`word_at`), so `\w+\b` ends after an NFD `é` too. (This
base-code-point rule is a deliberate semantic choice; an earlier "a class
matches only single-code-point clusters" rule was wrong.)

### Pattern literals are grapheme-segmented too

A literal in the pattern matches a cluster only by **full equality** of its code
points (`lit_match`), not by base code point — so an exact literal is stricter
than a class. For that to behave predictably the pattern's literal text must be
segmented into clusters exactly as the subject is. Typed literals mostly are
(`literal_len` reads a typed cluster, stopping at a metacharacter), but **escapes — `\r`, `\n`,
`\uXXXX` — each parse to their own single-code-point literal**, so an escaped
run like `\r\n` would stay two literals and could never match the indivisible
CR-LF cluster (UAX #29 GB3) a subject presents. `parse_concat` therefore runs a
fusion pass (`fuse_literal_graphemes`) that re-segments each maximal run of
adjacent, unquantified literals on grapheme boundaries, so `\r\n` compiles to
the single `U"\r\n"` cluster literal — exactly the node the equivalent typed
text produces. (A quantified escape, e.g. the `\n?` in `\r\n?`, is its own atom
and does not fuse.) `literal_len` sets how far an atom reaches — what a
quantifier repeats — and the pass sets how a run is matched, so it also
rejoins a metacharacter that is literal there to a cluster the subject has
(a Prepend before a literal `{`). It runs in grapheme mode only: in CodePoint
mode a literal is one code point.
The parser reads the pattern a code point at a time in both modes, so syntax
never depends on its neighbours: a combining mark after `(`, `]`, `+` or `\` is
literal text after it, not part of it (segmenting the whole pattern into
clusters, as an earlier tokenizer did, glued it to the metacharacter, so
`(a)◌́` lost its `)`), and a pattern built by splicing `reg::escape(s)` into a
template parses as the template does. Only literal text forms clusters: in
grapheme mode `literal_len` reads the cluster a literal starts, up to the next
metacharacter (a Prepend takes no `(`), so a quantifier repeats the whole
cluster, as Swift coalesces literal scalars into characters. In CodePoint mode
a literal is one code point, so NFD `é+` repeats the mark and `[a-é]` is `a`–`e`
and the mark, as in every code-point engine. A metacharacter is always one code
point, typed or escaped: `]◌́+` and `\]◌́+` both repeat the mark. In grapheme mode a cluster of
literal text in a class adds each of its code points but is no range endpoint
(`BadCharRange`), as in Swift and Raku; an escape is always one code point.

### Inline flags: scoped in the syntax, one value in the plan

`(?i)` lasts to the end of its group and `(?i:…)` covers its own, as in Perl,
PCRE, RE2 and Rust; but the compiler and every engine read one value per flag,
pattern-wide (the plan's `icase_`, `multiline_`, `dotall_` — the case-folded
byte automata, the icase prefilters, the line-anchor tables). The parser keeps
the flags in force as it reads, taking a `(?flags)` where it stands (no node is
left for it), and settles `(?m)` itself: a `^` / `$` without it is written
`\A` / `\z`, which the planner already treats alike, so `multiline_` is just
"the pattern has a line anchor". It stamps each node with the other two, and
`resolve_flags` settles them. A flag that has one value on every node it bears
on — icase on a literal or class it can change (one whose case closure is not
itself), dotall on `.` — is that value, the nodes as they are: a pattern whose
flags are uniform plans as it would with the flag pattern-wide. A flag whose
nodes disagree is off, and the nodes that have it are *lowered* to flag-free
equivalents, so no engine has to learn per-node flags: a `(?s)` `.` becomes the
class of everything; an icase class its case closure (the case variants its
members lack joined to it, `case_extras` — the byte compiler's icase rule, the
one function both use); an icase literal the class of its code point's case
variants in CodePoint mode, and in grapheme mode, where a class matches a
cluster by its base, the alternation of the clusters whose code points fold as
its do — counted against the program's size, since each code point compiles to
an instruction. Under icase a class holds a character when any case variant of
it is a member — any member, `\p{…}` and the predicates included, as RE2 and
Rust have it (U+0345 is no `\w`, but its variant ι is, so `(?i)\w` holds it).

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

### The find from the end (`EndAnchor`)

A pattern that can only end at the end of the text — every alternative ends
in `\z`, or in a `$` that is not (?m)'s (`forces_text_end`, the mirror of
`forces_text_begin`) — has every match end at `n`. Of those, the
leftmost-first match is the one with the leftmost start, which is what the
reverse DFA finds run from `n` down to the cursor: the forward scan is not
needed at all. That is RE2's special case in `RE2::Match` ("we already know
where the match must end") and `regex-automata`'s `ReverseAnchored`; like
them it is not taken for a pattern anchored at the start as well (the walk
from 0 has those). `$` here is the end of the text only, as in RE2, Rust and
Go; in PCRE2, Python or Java it also matches before a final newline, which
is this library's `\Z`, and not end-anchored.

The scan reads what the match spans, and the rung runs before the subject
is classified, so nothing else reads the rest either: a whole-subject check
would make the find O(n) again. Instead the rung vets the bytes it read
(`end_region_ok`) — and, a bytewise scan having stopped inside a code
point, the code point it stopped in, and unless it died above its floor
the code point before, whose kind the boundary there asks:

- **CodePoint**: they are well-formed UTF-8 (a byte DFA meets no stray byte;
  the Pike reads one as an element of its own).
- **Grapheme**: every cluster among them is one code point — or a CR-LF, to a
  pattern that cannot split one — checked forward (`egc_simple_from`) from a
  boundary that nothing before it can join: back past any pair that fuses,
  and past a left side that is `Extend` or `ZWJ`, the two rules (GB9c, GB11)
  that look further back. Then the byte program, and the code-point program
  that resolves groups in the span, see what the grapheme engine sees — so a
  Grapheme plan with groups is served over non-ASCII text too, which before
  went to the grapheme Pike over the whole subject.

Bytes that fail, or a DFA that gives up, hand the scan to `Classify` from the
cursor (`test_end_anchor` runs such tails against the Pike). A boolean stops
at the first accept. Over 4 MB of prose ending in a word, `\w+$` went from
6.6 ms to under a microsecond; `(\w+)$` in a Grapheme plan over text with an
`é` in it from 464 ms; a match that is the whole text, `(?s).*\z`, does one
reverse pass where it did a forward and a reverse one (14 ms → 7), and its
`test()` reads one code point. Of other engines only RE2 and Rust do this;
.NET, V8, Perl and Oniguruma jump the start to near the end when the match
length is bounded (`\d{3}$`), and PCRE2, Go, Python and Java scan from the
start.

### The table: byte classes, row offsets, a byte budget

What a step costs is decided by the table it reads, so the table is built to
be small and to be read once.

- **A column per byte class, not per byte.** Two bytes that no instruction of
  the program tells apart always take the same transition, so they share a
  column. The classes are the DFA's own to work out, of its own program,
  when its first scan starts (`byte_classes`, asked by `columns`), and
  without walking a byte automaton: the compiler lists
  the byte ranges it emits (`byte_ranges`), and a large class block — a
  Unicode `\w` is ~470 distinct ranges in 5,000 instructions — carries the
  classes of its own ranges, worked out once per process where the block is
  cached (`ClassBlock`); the program's are those, refined by each other and
  by the loose ranges (`refine_byte_classes`). A grapheme program is small
  and is walked, each distinct operand asked for the ASCII bytes it accepts
  (`ascii_mask`; that program is only ever stepped by bytes on an all-ASCII
  subject: `lazy_inst_matches`). What a program's classes cost is about
  half a microsecond, paid by the first scan of each DFA a thread steps: a
  plan builds none, and most plans never step most of the DFAs they could.
  (They were the plan's to build once, for every program a DFA might run
  over; a first construction of `Sherlock\s+Holmes` took 27 µs so, and
  takes 22.) `[a-zA-Z]+ing` has 6 classes, a pattern over a
  Unicode `\w` about 100; classes are numbered in byte order, so the ASCII
  ones are the first columns of every row and sit in one or two cache
  lines. A row used to be 256 entries — 1 KB — whatever the pattern.
- **A state's id is the offset of its row.** All rows live back to back in one
  array, and a step is `tr[s + cls[byte]]`: a load on the dependency chain,
  nothing to scale — and nothing to add, because the scans put the column
  into the table's address first, which waits on nothing, and keep the
  compiler from summing row and column between the two loads
  (`REGEXLIB_OPAQUE`; `[a-z]+[0-9]` tested over prose it does not match,
  746 → 894 MB/s). The entry in front of a row holds the state's flags
  (accept, the leftmost-first commit, dead, and "this is the start state");
  the scans load them off that chain and test them with one mask. They are
  deliberately not packed into the id (an AND on the chain measured ~12%
  slower). A look scan (below) reads them through the row's address, taken
  first (`walk_flags`): as `tr[s - 1]` they are a second load indexed by
  the state the moment it arrives, beside the next step's own, and on the
  machine measured the two got in each other's way for a cycle of every
  byte (a boolean scan over prose: 865 MB/s, 1,035 so) — in that
  instantiation of the scan and not in its twin without look, which has the
  same instructions, runs at full speed either way, and is 3–7% quicker
  over a short subject the plain way.
- **States are interned through a hash set into contiguous storage**, each
  state's program counters packed as byte-sized differences. A state of a
  Unicode-class pattern holds its program counters by the hundred, and they
  — not the rows — are most of what a big DFA weighs: `[a-q][^u-z]{13}x`,
  15,587 states, went from ~1,750 to ~300 bytes a state, and its first scan
  of a 595 KB text (which builds every one of them) from 301 ms to 48 ms.
- **The scan loops keep the prefilter out.** The start-state skip
  (`dfa_start_skip`) is a call the loop makes when a state's flags say so;
  inlined, the searchers behind it took the loop's registers and the loop
  kept its cursor and its table on the stack.

Stepping regexlib's own DFAs over the Sherlock text, before and after (MB/s;
the two-pass chain with no prefilter — matches are dense in the first row
and sparse or absent in the rest, where the forward scan is all of it): `\w+` 168 → 196, `[a-zA-Z]+ing` 337 → 792,
`[a-q][^u-z]{13}x` 109 → 392, `Holmes.{0,25}Watson|Watson.{0,25}Holmes`
617 → 887, `[a-z]+ [a-z]+ [a-z]+ \.` 490 → 889. A cold `search()` that has
to build its DFA first is typically 2–3× quicker (`/\*.*?\*/` in CodePoint
mode: 11.4 → 3.6 µs), up to 6× over Unicode classes.

### Look: assertions on the same table

A program with `\b`, `^`, `$`, `\A` or `\z` in it is not `dfa_ok_`, and
used to have DFAs of its own: four of them, over a table of 257- or
129-wide rows with a pair of words to an edge, and an uncached set
simulation for each to fall back to when its table filled. They are the
lazy DFA now, stepped with **look** — the arrangement RE2 and
`regex-automata` use.

Whether an assertion holds at a boundary depends on the code points on both
sides of it, so a transition cannot be a function of the state and the next
byte unless the state knows what stands behind it. A look state therefore
is a pc list **and a context**: the text's edge, or what the code point
just consumed is to a boundary (a word character, a line break). And its
pcs are held
*unclosed*: the step over the next code point closes them under the
assertions that hold between the context and that code point, notes whether
the boundary accepts, and only then consumes (`look_next`). So a state's
accept and front flags speak for the boundary *before* the code point that
led to it. A look scan sees a match one step late, and takes one more step
over the text's edge, which has a column of its own. That is all the scans
differ by: the two loops (`dfa_forward_lf_scan`, `dfa_reverse_scan`) take
`Look` as a template argument, and the plain instantiations are the code
they were.

- **Byte classes tell apart what an assertion asks.** The classes of a look
  program are refined by what its assertions ask of a byte — the word
  bytes, if it has a `\b` or a `\B`, and the line breaks, under (?m) — so
  that a transition is cached by the class of an ASCII byte there too — a row of `\b[a-z]+\d\b` is 10 entries, 40 bytes, where it was
  2,056 — and no ASCII byte shares a class with a byte of a longer code
  point.
- **A non-ASCII code point is a path through states inside it.** What it
  is to a boundary — its *kind*: a word character, a line break, neither —
  cannot be read off its first byte, so no column of the state the scan is
  in can hold the step. `look_next` decodes it and takes the step as a
  path instead: from the state, on its kind, to a state *inside* the code
  point (the pcs closed at the boundary, with the boundary's flags carried
  in its tag); from there one transition per byte, by the byte's class as
  any (with a closure between that follows no assertion: inside a code
  point is no boundary); and from the last, on its kind again, to the state
  after it, whose context that kind is. The kinds are three more columns of
  every look row (but a bytewise one, below), and the states inside (`kInside`) are interned, cached,
  budgeted and cleared with the rest; no scan stands on one. So every link
  is a table load once made, and a step over a code point seen before —
  or one that only shares the path, by its kind and the classes of its
  bytes — builds nothing. The scan advances by its length.

  It used to be one step, never cached: the miss path closed the state's
  pcs afresh at every non-ASCII code point. That made an assertion over
  text with any outside ASCII a hundred times the cost of the same scan
  without one — `\w+$` took 60 ms over 100 KB of Latin text that `\w+`
  takes under one, and seconds over CJK, where every code point is one.
  Now the one measures at most about three times the other, and
  `test_look_non_ascii` holds it under ten. (A cache keyed by the code
  point would have been a hash map beside the table, and of little help to
  text whose code points rarely repeat; the path is the same table, and its
  links are shared by every code point of a kind.)
- **A context holds only what the assertions ask; to edges alone, a byte
  is a step.** `side` reports a word character only to a program with a
  `\b` or a `\B`, and a line break only to one with a `^` or a `$` of
  (?m). A program with neither sees only the text's edges: every code point
  is of one kind to it, and a boundary inside one the same as a boundary
  between two. So the step over a code point is the steps over its bytes,
  each one transition by its class, as without look (`bytewise`): no
  decode, no path, and the scan's own loop takes them. (Not in a DFA that
  re-seeds, if a start re-seeded inside a code point could match there
  with no byte, as `\Aa|b*`'s can: that one keeps the path, so that no
  state it stands on claims a match inside a code point.) `\w+$` over CJK
  takes half the time the path took, and scans as fast as `\w+` does
  without look.
- **Direction is which side the context is on.** A reverse program's DFA
  carries what stands to the *right*, and its input is the code point to
  the left; the boundary's flags are the same function of the two sides
  (`bflags`).
- **A context does not say "half a CR-LF".** In a Grapheme plan the pair is
  one cluster with no line boundary inside, and the DFAs the tier had
  carried a bit for it. No subject they are given makes it matter: one that
  holds a CR-LF reaches them only with a pattern for which an anchor that
  fires inside the pair changes nothing (`crlf_byte_safe`), and CodePoint
  mode has no clusters. (Headers with the bit forced on, forced off or
  dropped passed every test and the fuzzer.) The literal-with-anchors
  verify, which is given any subject, still applies the rule
  (`empty_flags_cp`).

What it comes to, HEAD against the four DFAs (MB/s, GCC 11 and Clang 22):
`\b[a-z]+\d\b` tested over prose it does not match 1,089 → 1,088 and
781 → 1,090; the same over the non-ASCII Sherlock text 651 → 1,078 and
770 → 1,070; `(?m)^[A-Z][a-z]+ [a-z]+` found over prose 1,011 → 1,018 and
747 → 1,036; `t[a-z]+ly\b`, a literal and a verify to a candidate,
8.7 → 9.5 GB/s and 6.8 → 7.2. (GCC's old loop kept its state in a stack
slot the processor renamed away; Clang's kept it in a register behind an
AND.) Across the 32 assert rows measured the geometric mean is ×1.08 and
×1.18, the slowest row 0.99 and 0.97; across the 94 general rows, ×1.00.
The header is 1,026 lines shorter.

### Tier dispatch

Three tiers, picked structurally from the pattern:

| Tier | When | What runs |
| --- | --- | --- |
| **1** | capture-free ∧ DFA-able | Forward ordered+cut DFA finds the leftmost-first end `e`; the reverse scan finds the start `s`; return `[s, e)`. **No Pike.** Covers the ASCII grapheme tier, the UTF-8 byte tier (§4/§5), and `^ $ \b \A \z` via an assertion-aware DFA. Targets `\w+`, `[a-z]+`, literals, general alternation (`a\|ab`, `(?m)^…\|…$`). |
| **2** | captures ∧ DFA-able | The lf DFA locates `[s, e)`, then a capture engine resolves groups *bounded by `e`* (§6). A pattern whose every group wraps the whole match (`(\w+)`) never reaches this tier: it is planned as its capture-free twin (§3, *Root groups*). |
| **2a** | captures ∧ assertion-DFA-able (`^ $ \b \A \z` + groups, e.g. `(\w+)$`, `\.([a-z]+)$`) | The **assertion-aware** DFA locates `[s, e)` (capture-stripped); the bounded backtracker (`bitstate_bytes`, which evaluates the assert ops via `empty_flags_cp`) resolves groups on it — replacing the Pike, which dominated these patterns (`(\w+)$`: 5300→700 ns). The locate runs on the lazy DFA over the grapheme programs (ASCII subject) or over the **byte** programs (a non-ASCII EGC subject, or **US mode on any UTF-8 subject** — see below), stepped with look. |
| **3** | DFA-ineligible (lookaround / nested empty-loop), or a DFA that gave up on its cache | Pike VM over the whole subject, with the §7 prefilters. The fallback. |

`dfa_ok_` = "regular" program (no lookaround, no `Op::Loop`); `dfa_assert_ok_`
additionally admits empty-width assertions, served by the assertion DFA. Both
are purely structural. Tier 2a is the capture analogue of the Tier 1
assertion-DFA path: an assert-bearing capture pattern (not `dfa_ok_`) still gets
a DFA-located span instead of the Pike, because the backtracker now evaluates
assertions absolutely (`$` = real end-of-text, not the span end).

**The byte assert tier is shared by EGC non-ASCII and US mode.** The lazy
DFA over the UTF-8 byte programs, stepping with look, weighs every boundary
by the code points on its two sides — which is exactly what an EGC non-ASCII
subject (byte == grapheme) *and* US matching (code points, no graphemes) both
need. So US does not get a copied assert engine: a US `^ $ \b`-anchored pattern
(capture or not) reuses `assert_find_span` / `assert_prefix_find` on **any**
UTF-8 subject, with the same prefilters and the same
`cp_prog_` bitstate capture resolution. Only the gate is the unit's: a
CodePoint plan takes the tier on any subject its own UTF-8 check (`us_stray`)
lets through, a Grapheme plan on a non-ASCII one with no multi-code-point
cluster (`assert_byte_path_ok`).
On an ASCII subject an EGC plan steps its grapheme programs instead. Captures
whose span overflows the bitstate still fall back to the code-point Pike over
that span.

**Captures on this tier, in either unit.** The groups are resolved over
`cp_prog_`, a code-point program. On a subject `assert_byte_path_ok` admits for
an EGC plan every cluster is one code point — or a CR-LF pair that a
`crlf_byte_safe_` pattern cannot split, with a group boundary or otherwise
(`crlf_run_ends`) — so the groups it finds in the located span are the grapheme
engine's: the argument the `Dfa/EgcByte` tier's groups rest on. EGC groups were held off
this tier while the subject check let a stray byte through: a subject ending in
a lone UTF-8 lead byte gave `([^ ]+)$` two answers (the grapheme engine gives
the invalid byte its own cluster and matches; the byte automaton wants a
continuation byte and does not). `simple_from` and the cluster walk refuse a
stray byte now, so the subject alone decides. On 4 MB of
non-ASCII prose (Grapheme), `(\w+)$`'s `match()` went from 207 to 2.1 ms,
`(\w+)@(\w+)\b`'s `search()` from 512 to 11 ms and `\b(\w+)\b`'s `find_all`
from 628 to 59 ms — the grapheme Pike they ran on segments the whole subject.

### Canonical tier names (the `[Tier: …]` labels)

The numbered tiers above say *what engine runs*. Which of them serves a call
is decided in two places: the find entry points (`test` / `search` /
`find_all` / `find_iter` / `find_at`) climb one shared ladder (next section),
and `match` — anchored at 0, where no prefilter applies — takes one rung per
family of that ladder (`match_end`): the family's DFA anchored at 0 locates
the end, and `match_located` resolves any groups within it. Which family
answers is not decided by the gates up front but by trying them in turn (see
"Guessing the family" below). Every
branch carries a `[Tier: …]` label in the source, with one canonical name per
(pattern-class × subject-class) combination:

| Label | Gate | What runs |
| --- | --- | --- |
| `Literal` | `literal_only_` | memmem (+ grapheme-boundary check in Grapheme mode); no subject classification |
| `LiteralAlt` | `literal_alt_` non-empty | Teddy multi-literal scan, ordered verify of the literals behind the fingerprint found |
| `AssertAnchor` | `assert_.anchor_gatefree` | memmem + per-hit boundary & anchor-flag verify; any subject |
| `EndAnchor` | `end_anchor_ok` (`end_anchored_`, the byte assert programs, and for groups the capture program) | the reverse byte DFA from `n` to the cursor: the leftmost start; groups in `[s, n)`; vets only the bytes it read (`end_region_ok`), else `Classify` |
| `AnchoredOnePass` | `aop_.ok` (the `^body$` / `^body` validation shape: an assert-free body with captures stripped, plus — for bare `^body` only — the cut rules; see `onepass_body_ok`) | ONE compact deterministic walk from 0 (`anchored_onepass_try`, shared by search / match / test) — a state is the offset of its row (premultiplied, as the LazyDfa's), so each byte's one load waits on the load before it and nothing else; a row is 129 entries, the state's accept flag and then a column per ASCII byte — the flag is read off the dependency chain, and the odd width keeps one column of many rows out of one cache set (a 128-digit validator over varying subjects: 262 ns with 128-entry rows, 140 so); a trailing `$` is the accept-lands-at-n test (uncut table, so the end is forced and the body may alternate or be lazy: `^(a\|aa)+$`); bare `^body` uses the leftmost-first-cut table, whose last accept is the exact leftmost-first end only under the cut rules. Sound on ANY subject: the walk bails on a non-ASCII byte, and on `\r` when the pattern could split a CR-LF cluster (`onepass_walk_bails_cr`). With captures the walk still decides the span — `test()` and every no-match (`^(a+)+$` on its ReDoS input) — and a match's groups are resolved on it; `+cap` for `^body$` goes further: `onepass_anchored_start_` makes position 0 the sole candidate of the capture one-pass walk, so `^(\d{4})-(\d{2})-(\d{2})$` yields end and groups in one walk (a bail falls to the assert chain) |
| WordOnePass | `wop_.ok` (`\b body \b`, capture-free, word-only head/tail atoms; with a trailing `\b`, every accepting state's outgoing bytes must be word bytes; WITHOUT one the table carries the cut, so the body must satisfy the cut rules too — `onepass_body_ok`) | per-candidate compact walk: candidates = non-word-preceded viable start bytes, taken a block at a time (`word_start_block`, see the scan section) behind a short scalar entry ramp; the trailing `\b` is one next-byte test at the last accept (exact via the accepting-state admission: a passed-over accept is always followed by a word byte) |
| `Dfa/US` | `us_ ∧ dfa_ok_` | byte lazy DFA over `byte_prog_` (suffix/inner prefilters); then, at EVERY capture count (`onepass_unbounded_`), the candidate + unbounded one-pass walk — one walk per match yielding end + groups where there are groups and the span (saves 0/1, which the compiler emits at any `ncap`) where there are none, replacing the located-span chain's two passes. A non-ASCII byte in the walk's way is a *local* bail: the chain serves that one find and the driver resumes with the next (§2, Linearity). A subject with a stray byte (not RFC 3629 UTF-8) is the code-point Pike's — a byte automaton cannot match a byte that is no code point, and the Pike reads it as an element of its own: a scan that outlives its call starts there (`us_stray`), a one-step find once the bytes it read hold one ("Guessing the family") |
| `Dfa/EgcByte` | EGC ∧ `egc_byte_path(text)` | byte lazy DFA (icase-prefix / suffix / inner prefilters, fused EGC literal scan); the one-pass walk and `+cap` as above, except on a CRLF-collapse plan (`byte_walk_ok`: its byte programs count a CR-LF pair as one element and the walk's table counts two) |
| `Dfa/Ascii` | EGC ∧ `dfa_ok_` ∧ ASCII subject | lazy DFA over the grapheme program (byte == grapheme); `+cap` as above |
| `Assert/Ascii` | `dfa_assert_ok_` ∧ ASCII subject | the lazy DFAs over the grapheme programs, with look (forward, and reverse for the start) + assert literal/prefix/suffix/word prefilters; `+cap`: assert-aware bitstate |
| `Assert/Byte` | US: any UTF-8 subject (`us_stray`); EGC: `assert_byte_path_ok(text)` (non-ASCII simple) | the lazy DFAs over the byte programs, with look; same prefilters; `+cap`: assert-aware bitstate, in either unit (see above) |
| `Pike` / `Pike/cp` | always (the fallback) | grapheme Pike VM over `prog_`; US: code-point Pike over `cp_prog_` |

Both ladders try their eligible tiers top-down and fall through when a DFA
gives up on its cache; `Pike` is the proven baseline every other tier must
agree with (§9).

### The find ladder

`search`, `test`, `find_all`, `find_iter` and `find_at` used to have a dispatch
ladder each — five copies of the same decisions, kept in step by hand. They
were not in step. The one-pass walk was missing from the EGC byte tier (a
subject with one `é`, or with CR-LF line ends, ran `\w+` on the two-pass chain:
~160 MB/s where the ASCII tier did ~260); `test()` had no suffix or
interior-literal rung (`e[a-z]{3,}q` over 595 KB of prose: 0.56 GB/s as a
boolean, 33 as a find); only `search()` skipped to a candidate before running
the Pike, and only the iterator had the fused scans. Each was a capability
tied to the entry point that happened to get it. There is one ladder now, and
a rung exists at all of them or at none.

**Rungs** (`Rung`), and what each needs of a scan:

| Rung | What runs | Needs |
| --- | --- | --- |
| `Literal` / `LiteralAlt` / `AssertAnchor` | a plan that is its own locate; never falls | the cursor |
| `TextAnchor` | a text-anchored pattern matches at 0 or nowhere: the `AnchoredOnePass` walk from 0 is the whole find. For a caller that reads no groups — a capture-free plan, or `test()` | the cursor |
| `EndAnchor` | an end-anchored pattern matches at the end or nowhere: the reverse DFA from the end is the whole find, over the bytes it vets itself (§2, "The find from the end") | cache |
| `Classify` | looks at the subject and stands on the family that serves it; where a Grapheme plan starts unless a rung above is the whole plan | the subject's class |
| `FusedPrefix` / `FusedSuffix` | the fused EGC literal scans (§4) | cache |
| `IcasePrefix` / `Suffix` / `Inner` | the candidate + verify prefilters (§7) | cache, budget |
| `Walk` | candidate + unbounded one-pass walk: end and groups in one pass | budget, save slots |
| `Chain` / `AssertChain` | the located-span chain: forward to the end, reverse to the start, groups | cache |
| `Bool` | `test()` only: the boolean forward scan, which stops at the first accepting state | cache |
| `Pike` | the baseline; the grapheme Pike skips to a candidate first (literal prefix, Teddy, first-byte set) and tries the bounded backtracker there | segmentation |

**Families.** The subject decides exactly one thing: which engine *family*
serves it (`Family`: `Dfa/US`, `Assert/Byte` in CodePoint mode; `Dfa/EgcByte`
with or without the `(?i)` probe, `Dfa/Ascii`, `Assert/Ascii`, `Assert/Byte`
in Grapheme mode). Everything else about a family's ladder is the pattern's,
so it is worked out once, when the plan is built (`ladder_plan`): each
family's ladder for each kind of caller (`Plan::family_`; three kinds, see
`ladder_caller`: a find, a boolean, a boolean over a short subject), and where a scan
starts (`Plan::start_` — a CodePoint plan's family does not depend on the
subject at all, so its scan starts on the family's first rung outright).
`ladder_family` is the one place a family is defined, `ladder_classify` the
one place a find reads the subject gates (a guess asks them of what it
read — see below), and `ladder_pick` the one place the
order of a family's rungs is written (the rungs ahead of the families are
not a family's: a plan that is its own locate, or text-anchored, starts
there by `ladder_plan`, and the fused scans are where `ladder_classify`
puts a Grapheme scan whose subject is not ASCII). Within a family:

- `(?i)` prefix; then the suffix scan; then the interior literal — a
  capture-free find takes the rare-literal prefilters before the walk (they
  answer from a memmem hit, where the walk tries candidates until its
  profitability rule gives it up);
- the walk; then, with captures, the interior literal (it needs a capture
  pass per match, the walk yields the groups in its one pass);
- the chain. On the assert families: the walk, then the assert chain.

**Bails.** A rung that cannot go on says why (§2, Linearity). *Locally* — a
byte the one-pass table has no transition for: this one match comes from the
rung below (`Ladder::below`), and the next step asks the walk again.
*Globally* — its budget, its profitability rule: the rung is given up for the
rest of the scan (a flag in the ladder that nothing sets back), and
`ladder_pick` is asked again. A DFA that gives up downgrades to the Pike
from the cursor, and so does a fused scan that meets a cluster it cannot vet; the
fused scans re-classify instead (`ladder_unfused`) when their budget runs
out, and — the CRLF-collapse variant — on a subject it is not eligible for,
which the gated families usually serve.

The fused scans vet the subject as they go, so what they conclude holds only
over bytes they have vetted — and a candidate's verify walks ahead of that.
Its verdict stands, either way, only if the bytes it *examined* are
cluster-clean (`egc_match_clean` over the walk's reach): a match is yielded
then, and a failed candidate passed over then. Otherwise the Pike answers,
from the cursor — which only ever moves past a yielded match or a candidate
whose failure was vetted. The second half was missing until the ladder was
shared and the fuzzer, at ten times its default count, met it on every entry
point instead of the iterator alone: `q(?:a[a-z]+z|b)` over `qaqbcd́z` — the
verify at 0 dies on the combining mark, where the Pike takes `d́` for the
letter its base is — reported `qb` at 2 for the match at 0.

**What the caller wants** changes two things and not the ladder. `Want::Test`
(a boolean) takes the same prefilter rungs, but each stops at the first
accepting state it reaches instead of going on to the end a find reports
(`dfa_forward_first`; the suffix scan simply does not walk forward) — the
rest of a match can be as long as the subject (`[^?]+\?.*`: the answer is at
the `?`, and the leftmost-first end is the end of the line) — and where a
find would walk or chain, it scans (`Rung::Bool`): the assert chain too, on
either engine, in either unit, with groups or without (a CodePoint plan and a
capture plan used to chain — `(?s)(\w)\b(.*)` over 4 MB of prose, 19 ms to
1.9). Two limits keep a boolean
from paying for a skip it has no use for (`limits::kBoolSkipBytes`,
`kBoolFloorBytes`): under 64 bytes of subject it leaves the interior-literal
rung out and scans (`[^?]+\?.*` over a 23-byte path: 48 ns through the rung,
15 scanned), and on any subject that rung looks back 32 bytes for its floor
and no further — a pre-part still alive there would be walked back to its
start and then forward again, where the scan walks it once. (The boolean DFA
of CodePoint mode had no start-state skip at all: `zqj` as a boolean over
595 KB ran at 0.67 GB/s where the find did 89. It has the byte program's
now, taken only on a subject long enough to repay it:
`LazyDfa::kSkipByteLong`.) And the
match is handed to a *sink* (`RowSink`: a columnar row; `ResultSink`: the one `MatchResult`,
built in place; `NoSink`: nothing), so no entry point pays for another's
form: `search()` building its result out of a row it had just written cost it
a failed store-to-load forward, ~3 ns of a 20 ns call.

**The assert families' boolean skips to its leading literal.** It used to
step every byte: a leading literal is no bounded anchor for it (its verify
walks to the leftmost-first end, above), and a DFA stepped with look had no
start-state skip. Now the scan skips to the assert prefix
(`LazyDfa::kSkipAssert`). A look state is a context as well as its pcs, so the
skip is not the jump the other scans make from inside their loop: the scan
*stops* in a start state (`LazyDfa::kAtStart`), and `look_forward_skip`
starts it again at the prefix's next occurrence, in the start state of what
stands behind that — on any bytes, the left context the steps from 0 would
have seen (an occurrence begins with a byte that continues no code point,
and a byte that starts no code point is one element either way: `cp_at`,
`cp_before`). What one scan steps the next does not, the search for the
prefix never goes back, and the scan still stops at its first accept, so
`x[^?]+\?.*\b` costs one pass where the find's verify of each `x` walks on
to the end of the line. A dense prefix is stepped through, by the bar the
DFA tiers leave one to their scan at (`Plan::assert_prefix_skips`): a scan
restarted at every `e` costs more than one that steps through them. A
text-anchored pattern's boolean is the anchored DFA's from 0, whatever
literals it has: the find's verify from 0 goes on to the leftmost-first end
(`^.*foo\b`). Tested over a megabyte of prose with no match, in either
unit: `\bqzx\w*\b` and `(?m)^qzx.*` went from 1.5-1.9 ms to 41-43 µs, what
the find takes; `^qzx\b.*` to 12 µs; `\bq[a-z]+e\b` with a `q` every 61
bytes to ~0.3 ms. The fuzzer asks every subject of its layer for the
boolean four ways — with the skip, without it, of `search()` and of the
Pike — malformed bytes among them.

**... and takes the word scan where its start set is sparse.** The
`\b body \b` shapes the word scan serves (`Plan::wop_`) with no literal
priced below the scan — `\b\d+\b`, `\b[0-9]{3}\b`, `\b[xz]\w+\b` — had the
same gap, and nothing to skip to: the boolean stepped every byte, where the
find reads sixteen positions at a time for a candidate (`word_start_block`)
and walks the candidates alone. A walk ends where its word does, so the word
scan is a bounded anchor in the sense above: a boolean on the ASCII assert
family takes the find (`Ladder::kBoolFind`, `Plan::assert_bool_finds`) when
the plan holds the scan sparse (`Plan::word_scan_sparse`) — it leads (no
literal anchor priced below it, `wop_after_anchor_`) and its estimate
(`anchor_.scan_cost`) is under the same bar. A dense start set stays on the
scan: with `[a-z]` every word is a candidate, walked to its end, and once
the walks have spent their budget the find starts over on the unfiltered
scan. So do the byte family, where the walk has no byte form, and CodePoint,
which has no word scan. Where the walks give up, the boolean's own scan
answers (`assert_find_span` with `span` false), which stops at the first
accept, not what the find falls back to — the leftmost-first end, then the
reverse scan to its start. Over a megabyte of prose with no match the three
went from ~1.5 ms to ~0.1, what their finds take.

**One step, or every match.** `ladder_step<All, Out>` is the one
dispatch (the rungs that need only the cursor are `ladder_shallow`, the walk
`ladder_walk`, the rest `ladder_deep`). `find_iter` takes a step per `++`; `find_all` takes the same step
with `All` set, under which a rung goes on to its next match in place — its
DFAs resolved, the cursor at hand — and the ladder is consulted again only
when a rung stops. (Re-entering it per match cost dense `\w+` 12%; the walk
additionally keeps a loop of its own, `onepass_fill_run`.)

**A one-step find costs what its rung costs.** `search()` and `test()` on a
short subject are mostly set-up, and what runs ahead of the engine delays it.
Three things keep the shared ladder from costing them anything:

- The ladder's state is a *value* (`Ladder`: the rung, the one below the walk,
  what the caller wants, and a word of flags — six bytes), and every
  transition takes one and
  returns one. A one-step find (`find_once`) keeps it, and the cursor, in its
  own frame, where the compiler dissolves them. As an object the rungs
  reached through a pointer, the same ladder cost `search()` ~100
  instructions a call.
- The rungs that can answer alone are tried before what the others work with
  exists: the shallow rungs with a cursor and nothing else (`find_once`; the
  text-anchored walk is inlined there — a validator's whole call is that
  walk), then the walk (`find_rest`: the budget, and thread-local save slots
  — a walk whose driver reads no DFA runs without the thread's cache, which
  is 35 instructions to fetch, `scr_walk`), then the rest.
- Nothing about the pattern is decided per call (the plan's ladders, above),
  and a Grapheme scan's one look at its subject (`ladder_classify`) is
  inlined into the one-step find — as two calls handing the ladder back and
  forth it was 230 instructions of a 20 ns `test()`.

A scan that outlives the call (`Finder`: `find_iter`, `find_all`, `find_at`)
stores the same ladder and cursor and takes the same steps.

### Guessing the family, judged on what the scan read

A one-step call is often answered by the head of its subject: `match()`,
anchored at 0, from a few bytes for a validator or the token that starts a
line; `search()` and `test()` at the first match. They used to look at all of
the subject first anyway. The gates a family is chosen by (`first_nonascii`,
then `simple_from` or `contains_crlf`; `valid_from` in CodePoint mode,
`us_stray`) are passes over the whole of it, and a stray byte or a combining
mark anywhere sent the call to the Pike, which segmented all of it.

They guess now. A family runs as if the subject were one it serves, and its
answer stands if the subject is one *as far as the scan read*
(`guess_held`); else the next guess, and at the last the Pike.

- **`match()`** tries the families of `Plan::match_guesses_` (set by
  `ladder_plan`), each anchored at 0 (`match_end`): a CodePoint plan's one; a
  Grapheme plan's ASCII family, then its byte family — the byte family first
  for a pattern with a CR-LF literal, which the ASCII family cannot match
  (`ascii_grapheme_ok`), so that on the subjects where it matters the first
  scan is not thrown away. An ASCII family is not tried on a subject whose
  first byte is not ASCII: what it read would include that byte. Each scan
  reports how far it read: an anchored DFA scan (no start-state skip; a
  scan consumes the byte that ends it) and a one-pass walk
  (`OnePassWalk::reach`). A wrong guess costs its scan, to where it
  stopped: on a non-ASCII subject the ASCII family's anchored DFA dies at
  the first non-ASCII byte (`lazy_inst_matches` matches none), so it is the
  ASCII run before that.
- **A CodePoint `search()` / `test()`** (`find_rest`) runs the family its
  plan guesses (`Plan::us_ladder_`) with `Ladder::kSpec` set, and does not
  check for a stray byte first. A rung runs many scans, so each forward DFA
  scan raises its DFA's high-water mark instead (`LazyDfa::hi`, a
  start-state skip included), zeroed when the guess starts
  (`FindCache::reach_from_zero`). No walk needs to report: a walk — the
  one-pass one, the scalar chain, the suffix's scalar verify — gives up at
  any non-ASCII byte and the DFA reads on from there, so what it reads past
  the end holds no stray byte, the one thing a CodePoint subject can fail
  on. An answer that does not hold is the Pike's, from the start, with a
  fresh sink, cursor and budget (`find_pike`). The guess ends where the scan
  leaves the family's rungs, which only a DFA that gave up makes it do: at
  `Classify`, where a boolean hands over to the find's rungs, the subject is
  classified whole, as it was before; at the Pike, which a one-step find
  enters at 0 (its cursor moves only at a yield), the answer stands.

The rules the two share:

- **How far a scan read** (`reach`): one past the furthest byte any of its
  scans examined — at least the match's end; the whole subject when it found
  none (a literal prefilter reads to the end without a DFA).
- **What must hold**: the family's own gate, over the prefix of the subject
  that ends with the code point at `reach`. That code point is where the scan
  stopped, and whether it joins the one before it is what the stop meant:
  `\w` over `a` + U+0301 consumes the `a` and stops, and the cluster is
  three bytes. The prefix is extended over an LF after a CR there, so no
  pair is split. Nothing after it matters: the scan consumed none of it, and
  a cluster that starts at `reach` is judged by its first code point. The
  gates are split into the route and the soundness — `egc_byte_path` sends a
  pure-ASCII subject to the ASCII family, which is faster there, and
  `byte_sound` is whether the byte programs answer for it at all — and only
  the soundness is asked: `Regex::family_sound`, the one test of it, which
  the gates, the guesses and the end anchor's check (`end_region_ok`) all
  call. A CodePoint family's soundness fails only on a stray byte, and no
  code point joins another: its prefix is the bytes its scans read, to the
  end of the code point they stopped in, with the code point at `reach` only
  where a look read it for context (the assert family); the LF after a CR,
  no stray, changes nothing there (`guess_end`).
- **Why the Pike may answer**: it is the reference. And it is no more often
  the Pike than before: a gate that holds for the whole subject holds for
  each of its prefixes, so a subject no guess holds for is one no family
  served before either.

Measured on `match()` over 4 MB of prose with a match at 0, in both units:
`\w+`, `(\w+) (\w+)`, `\b\w+\b`, `(\w+)@(\w+)` went from 0.15–1.5 ms to
0.04–0.1 µs, and with a stray byte at 100 or at the end from 90–225 ms to the
same. On ~60-byte subjects they run at 0.51–0.96× of before — save `.*fox`
over one whose first non-ASCII byte follows 45 ASCII ones, 1.50× (+57 ns):
the wrong guess's scan. A pattern whose scan reads to the end (`.*fox`, no
line break) costs what it did (the same instructions, to 0.5%).

Measured on a CodePoint `search()` / `test()` over 4 MB of prose with a
match in its first words: `\w+`, `(\w+) (\w+)`, `[a-z]+ing`, `(\w+)@(\w+)`,
`\b\w+\b`, `\w+ \d+` went from 0.14–1.4 ms to 0.04–0.33 µs, and with a stray
byte at 100 or at the end from 98–121 ms to the same. A find with no match
reads to the end and costs what it did (to 0.001% of its instructions). On
~60-byte subjects a call takes 209 fewer to 1 more instructions (of
361–1341; the fewer where the subject is not ASCII), and 9 fewer to 29 more
(to 2.2%) where the match is near the subject's end or there is none, so
that the scan reads about what the old check did. A Grapheme find, which
does not guess yet, takes 20 fewer to 10 more (to 1.3%).

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
A scan owns ONE budget across all its steps (a per-step budget would reset
at every match and still admit O(matches × n)). The other
prefilters need no budget: their verifies are O(1)/pattern-bounded (literal,
Teddy, anchor flags) or shape-bounded by admission (the var-pre suffix's
one-atom rule, `assert_word_find`'s one-candidate-per-word).

The unbounded one-pass candidate drivers add a **profitability rule** to the
same budget (`WalkBudget::spend_profitable`): whether a candidate+verify
driver beats the single-pass chain depends on the subject, not the pattern
(`(\w+)\s+(\d+)` over key=value text: every candidate matches, one walk per
match; over prose: every word is a candidate and every walk fails after the
word). Each failed walk is charged an estimate of its cost in chain-bytes —
its SIMD run skips at `kRunCost` each (setup plus an exit mispredict; the
expensive part of a failure) and its table steps at half a byte (independent
candidate walks overlap in the pipeline, unlike the chain's one dependency
chain) — and the driver bails as soon as the charge exceeds the distance
scanned, after a `kMinScan` proving window so short subjects keep the
one-walk latency shape. The scan goes on from the bail point on the rungs
below, so the loss is bounded by that window, not a subject's worth.

The distance scanned is the right yardstick only when the chain would have
walked it. A driver led by a literal prefix or a sparse first-byte set shares
its candidates with the chain — the chain's forward DFA skips from its start
state with the very memchr the driver runs — and between candidates neither
does any work. Measured against the distance, such a driver's charge did not
trip where it should: `e[a-z]+s` over prose (one candidate in 13 a match, the
rest a failed run each) was charged 0.96 of the distance and ran at ~395 MB/s
where the chain does ~505. For those drivers both sides are counted *per
candidate* instead (`spend_at_candidate` / `matched_at_candidate`): a walk
call's fixed cost and half a chain-byte per byte, against the chain's much
smaller per-candidate cost plus a byte per byte on a failure and two on a
match (forward for the end, reverse for the start). The constants are
measured: an all-matching `e\w*` costs the walk 7 chain-bytes a candidate and
the chain 10.9, a failing `e[a-z]+s` candidate 6.5 and 4.5. (The rule was the
ASCII tier's before the ladder was shared, and the cost was that tier's alone;
with the walk on every family it showed on every subject.)

That bail is **global** — the driver is done for the rest of the scan
(`kWalkBail`). A non-ASCII byte in a walk's way is a different event and gets
a different code, `kWalkLocal`: the one-pass table has no transition for the
byte, which says nothing about the bytes after it. So it is **local**: the
rung below the walk serves that ONE find (`dfa_chain_step` /
`assert_chain_step`, or the interior-literal rung of a capture plan) and the
walk is asked again for the next. It used to be one code, so a single `é`
handed the rest of the subject to the chain: `\w+` in CodePoint mode over 512 KB of ASCII words with one `é` in the
middle ran at ~270 MB/s against ~410 without it, and runs at ~410 now (with an
`é` in one word of fifty: ~205 → ~390). A local bail is charged like a failed
walk plus `kBailCost` for the call that produced nothing, against the distance
the *driver* covered — what the chain covers after a bail is not the driver's
doing — so a subject where most finds bail (every word beginning with a
non-ASCII letter) trips the same rule and the bail turns global. It draws
nothing from the linearity allowance: the chain step that follows reads every
byte the bailing walk read, which bounds it by work the chain does anyway.

Where the driver sits among the rungs follows from the same accounting. A
capture-free find takes the suffix / ReverseInner prefilters (§7) *before*
it — they answer from a memmem hit, while the driver would walk candidates
until the rule gives it up — and a capture find takes the driver first (its
one walk yields the groups; the prefilter rungs need a capture pass). The
order is `ladder_pick`'s, for every entry point; when each had its own, the
iterator had the driver first for both, which on `[a-q][^u-z]{13}x` in
CodePoint mode spent half the find in the driver's proving window (~17 →
~33 GB/s with the suffix scan first).

Two exact
refinements keep the driver's own work down first: a failed walk reports
the end of its first restartable run (`CpOnePass::State::restart_ok`: every
looping byte also takes the start state there, so a walk begun inside the
run converges with the one that entered it — if that one failed, all of
them do), and the position scan resumes there instead of at the next byte.

### Safety net: the DFA cache budget

A regular pattern can still need exponentially many DFA states (`.*a.{18}`
needs 2¹⁸), so a lazy DFA's cache — its table and its interned states — is
bounded: `limits::kDfaCacheBytes`, 8 MiB per DFA (of contents; the vectors'
growth slack is on top). It used to be bounded in states, 65,536 of them,
which was 64 MB of table alone and over 100 MB once the states' own lists
were counted.

**A full cache is cleared and refilled**, not abandoned: the scan carries on
from the state it stands in, and the DFA keeps running on the states the
subject is using now. Clearing is invisible to a scan but for two things it
must re-read after any miss — the table's address, and, by way of the flags,
which state is the start state (it is made again at once).

**The DFA gives up only when refilling does not pay.** Scans report the
bytes they step; once a cache has been refilled `limits::kDfaMinClears` (3)
times, a fill that covered fewer than `limits::kDfaMinBytesPerState` (10)
bytes per state it built means states are being built about as fast as
bytes are read. The DFA then answers `kCap` on its next miss and for good
— what it has built still answers — and the rung downgrades to the Pike VM
from the cursor. (The rule is RE2's and `regex-automata`'s. What a refill
costs against the Pike depends on the pattern: for `[ae].{20}[ae]` in
CodePoint mode, building a state costs ~1.9 µs and the Pike ~50 ns a byte,
so the two break even near 40 bytes a state; for a small ASCII pattern,
nearer 7.)

An assert plan's DFAs are these DFAs, under this budget and this rule. (They
had tables of their own once, bounded in states and then in bytes, that were
kept when full and took no more states, the scan falling back to an uncached
set simulation that started over. `a[ab]*a[ab]{12}\d\b` over 524 KB of a's
and b's, every `a` a candidate: 110 ms so, 8.3 ms cleared and refilled.
`\b[ab]*a[ab]{12}\b` found over 64 KB subjects: 4.8 ms a scan and 12.8 MB
held, against 0.45 ms and 5.1 MB. A pattern that outgrows the cache however
it is refilled goes to the Pike, which is slower than the set simulation was
at finding every match: `\b[ab]*a[ab]{18}\b`, 4.9 → 6.7 ms a scan.)

---

## 3. Compiler & bytecode

The compiler lowers the AST to an NFA `Program`. Two pressures shaped it —
**compile time** and **program memory** — both dominated by Unicode classes
(`\w`, `\p{L}`), which expand to hundreds of UTF-8 byte-range sequences.

### Root groups

Before anything reads the AST, the groups that wrap the *whole* pattern are
peeled off its root (`peel_root_groups`). A group there adds nothing to what
the pattern matches:

- a non-capturing one — `(?:\w+ing)` — is pure syntax and always comes off;
- a capturing one records a span that is, by position, the match's own. It
  comes off only when *every* group of the pattern is such a wrapper —
  `(\w+)`, `((x))`, `(?:(\w+))`, `(?<n>\w+)` — and then `ncap_` is 0 and
  `alias_groups_` holds the count: the pattern is planned and run as its
  **capture-free twin**, and each group is reported as the whole match where a
  result is handed out (`finish_result` for a single result, `alias_rows` for
  `find_all`'s rows, one widened row per step in `MatchIter`). With any other
  group in the pattern the wrappers' slots are real work, and they stay.

A wrapper need not be the root's: one beside nothing but assertions —
`\b(\w+)\b`, `^((\w+))$`, `\b(?:\w+ing)\b` — spans the whole match all the
same, since an assertion consumes nothing (`wrapped_element`). Its groups come
out of the sequence and what they held is spliced into it (`unwrap_groups`),
so the twin is the pattern as written without them: `\b(\w+ing)\b` is planned
as the flat `\b\w+ing\b`, its literal suffix in view. Over 4 MB of prose
`\b(\w+)\b` went from 56 to 36 ms as a `find_all` (its twin's 33),
`\b(\w+ing)\b` from 15 to 4.6, and `\b(?:\w+ing)\b`, which had no groups to
pay for but hid its suffix, from 13 to 4.5. A lookaround is zero-width too but
is not counted: wrapping a pattern in lookarounds is how the test suites build
a Pike reference with real groups (`pike_only` checks that its groups are
not aliased), and a pattern with one would only save its groups' Saves on the
Pike.

It has to happen on the AST, ahead of every analysis, because the analyses
read the root's *shape* — a `Concat` ending in a literal, a bare literal run —
and a wrapper that survives to the plan hides it. Before this a wrapped pattern
was a different pattern to the planner: `([a-zA-Z]+ing)` and `(?:[a-zA-Z]+ing)`
ran at ~350 MB/s where `[a-zA-Z]+ing` runs at ~2700, `(Sherlock)` at half the
literal tier's speed, and `([a-q][^u-z]{13}x)` fell to the grapheme Pike on
CRLF text (the collapse path is capture-free only) at 9 MB/s against ~20000.
All of them now run at the twin's speed, in `find_iter` exactly; `find_all`
pays the widening pass over its rows (dense `(\w+)`: ~330 MB/s against ~395
for `\w+`).

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

A pool is a set: it holds each distinct literal or class once, however many
instructions read it (`Compiler::intern_lit` / `intern_cls`). A counted repeat
emits its body once per copy, and a pool entry per copy made `[ab]{20000}` hold
twenty thousand copies of one class — some 130 bytes an instruction against the
instruction's own 16; pooled once, what grows under expansion is the
instructions alone (`(?:[ab]{20000}){10}`: 132 → 36 MB), which is what the size
limit counts.

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

### Lookaround programs — one per lookaround, counted in the program

A lookaround is a program of its own, which `Look` runs: compiled to scan
*away* from the positions it answers for, and run by the Pike once over the
whole subject to settle the assertion at every position (`Regex::look_table`,
one table per program per subject). Its identity is its AST node: a counted
repeat `x{n}` emits its body `n` times, but every copy of a lookaround in it
is the same assertion, so `Compiler::sub_program` compiles it the first time
and hands later copies the same program (`sub_of_`). One lookaround is one
program to hold and one table to fill, however many copies the repeats make.

The size limit counts what a program *runs*: `Compiler::size()` is its own
instructions plus its lookaround programs', each counted once, and
`limits::kMaxProgramInsts` bounds that; a lookaround body compiles within what
the program around it has left. Before, each copy compiled its own program
outside the limit — 25 bytes of `(?:(?=[ab]{20000})a){400}` took a gigabyte
— and each filled its own table, so `(?:(?=[ab]{50})a){100}` settled one
assertion a hundred times over every subject.

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
occurrence). Two process-wide, mutex-guarded caches:

1. **`enum_cp_ranges`** — `\p{…}`/predicate → code-point ranges, by scanning
   `0..0x10FFFF` once (surrogates excluded), cached by predicate. Its keys are
   the predicates and Unicode properties, so it is bounded as it stands.
2. **`ClassBlockCache`** — the whole emitted `Inst` block of a class, keyed by
   the *source* class and direction (`class_key`, so the lookup is
   proportional to the predicate, not the expansion) or by a code-point set and
   direction; each later emission is a `memcpy`-append + target rebase.

Together these took Unicode-class compile from the dominant cost to a block
`memcpy` (~12–14× on the compile benchmark: `\w+` 0.44 → 0.037 ms).

The block cache is bounded in bytes (`limits::kClassBlockCacheBytes`, 8 MiB)
and drops the least recently used block. A compile holds the blocks it uses
until it is done (`Compiler::listed_`), and a program keeps nothing of them —
it copies the byte classes it needs (`Program::byte_blocks`) — so the bound is
what the blocks take, and a class compiled again is built anew. `.` and an
IgnoreCase literal's code point are classes too, so every block has one key
(`class_key`). It was
three unbounded maps — sets to byte sequences, sets to blocks, classes to
blocks — holding every distinct class a process had ever compiled: 20000
patterns with distinct Unicode classes grew a process by 3.8 GB, where it now
levels off near 90 MB.

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

Every DFA tier is a byte/code-point automaton, so historically a whole-subject
ASCII gate dropped *any* non-ASCII subject off every DFA tier onto the grapheme Pike —
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
→ fall back to the grapheme Pike. (`match()` asks the same of the prefix its
scan read, not of the whole subject: see §2, "Guessing the family".)

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
- a multiline `^`/`$` and `\B` only where they meet no CR-LF run (below). They
  consume nothing, but each holds **between** the two code points of a CR-LF —
  a multiline anchor binds at any line-break byte on the ASCII tier, and `\B`
  holds between two non-word code points — a position the grapheme engine,
  seeing one cluster, does not have. A thread can stand there only at a run's
  end (the run took the `\r`) or at a match's start (the next element takes
  the `\n`, which only a run can), so such an anchor is harmful exactly next
  to a run: `\s+\B` over `"\r\nE"` ends on the `\r` at `[0,1)` where the
  grapheme engine finds nothing, `(?m)(\s+)$` stops `\s+` inside a cluster,
  `\B\W+\w` starts on the `\n`. `crlf_run_ends` therefore counts these anchors
  as runs of nothing, which no run may meet. `\Bing\s+\w` and
  `(?m)^Holmes\s+\w+` keep the fast tiers. (Without Multiline `^`/`$` are text
  anchors and touch no interior position; `\b` never holds there.) `\Z` and
  lookarounds also see the interior, but no DFA tier admits them;
- transparency stops at group boundaries and at fixed-count / non-greedy structure.

`can_match_empty_` (nullable) additionally forces a **non-empty** match for CRLF
admission (an empty match could land on the LF interior to a cluster — a position
that exists in byte mode but not grapheme).

`simple_from_crlf_ok` is then `simple_from` plus "a CR×LF cluster is permitted",
SIMD-skipping whole ASCII runs (including the `\r\n` breaks) to the next
non-ASCII byte.

One caveat is the literal rule's own: the pair is byte-safe but **not**
grapheme-program-safe. The parser fuses `\r\n` into one grapheme
(`fuse_literal_graphemes`), and the *grapheme* programs (`prog_`,
`lf_prog_`, compiled `cp=false`) hold a literal as one `Op::Char`
interning the whole code-point string — so the pair is a two-code-point unit
there, and the DFAs over those programs step **bytes**: no byte matches it and
the walk dies. `crlf_byte_safe` admits it for the byte programs, which match it
as its own two bytes, so `ascii_grapheme_ok` — the one gate that pairs
`crlf_byte_safe_` with a grapheme program — additionally requires
`!crlf_fused_lit_`. Not `cp_prog_` and not the one-pass tables: those compile
`cp=true`, where `emit_cp_lit` splits the pair into one op per code point.
Without it, `\r\n$` over `"x\r\n"` was a no-match where the grapheme Pike matches
`[1,3)`, and `(\r\n)$` split the entry points: `search` / `find_all` /
`find_iter` matched `[1,3)` while `test` said no.

Both byte gates then carry the matching exception, so a disqualified pattern
lands on a byte tier instead of the Pike. `egc_byte_path` admits a pure-ASCII
CRLF subject for a `byte_path_` pattern, and `assert_byte_path_ok` does the same
for an assert pattern (which has no `byte_path_`, so it cannot use the first) —
same `crlf_byte_safe_ && !can_match_empty_` condition, same reason. Without the
second, an assert pattern with a `\r\n` literal fell all the way to the grapheme
Pike: over 512 KB of pure-ASCII HTTP headers, `\b\w+\r\n` `find_all` measured
14.0 MB/s and `\r\n$` `search` 550 ns, against 283 MB/s and 74 ns with it.

Together with the §7 prefilters this took `/Sherlock/` from ~24 to ~13000 MB/s.

### `crlf_collapse` — bounded `\r\n`-class repeats

`crlf_byte_safe` admits a both-`\r\n` class only as an *unbounded-greedy* atom
(a CR-LF *run*), and only one at a time: two runs side by side — directly, or
across elements that can match empty — give the byte programs a boundary
*inside* a pair that the grapheme engine does not have (`crlf_run_ends`;
`t[^.]+[^q]+\.` matched `t\r\n.`, and `([^.]*)[^.]+,` closed its group between
the two bytes), so such a pattern is not byte-safe either. A
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
plain predicate, and the subject is read once. (Every suffix rung that runs
the collapsed programs passes `collapse` to the candidate verify, the gated
one included: the scalar verifier counts bytes and must leave a
candidate whose walk meets a CR or LF to the DFA.) A disqualifying window (a lone
CR/LF — i.e. ordinary Unix-newline text — near a match) or a fusing cluster
bails to the families that classify the subject up front (`ladder_unfused`)
rather than downgrading to the Pike, so plain LF text still lands on the ASCII
DFA tier. A var-pre suffix is admitted when the scalar chain verifier serves
it (exact ends, no forward re-expansion past the vetted window). Took
`[a-q][^u-z]{13}x` on the CRLF Sherlock corpus from ~7.7 to ~11.8 GB/s (rure
~12.9), and the window localization lifted the negated-class quote pattern
~11.5 → ~14.8 GB/s.

### The assertion byte tier

`\b`/`^$`/`\A\z` patterns are `dfa_assert_ok_` (not `dfa_ok_`), served by an
assertion-aware DFA (the lazy DFA with look). The same EGC-byte-path idea is
built for them: over the byte programs it runs a non-ASCII subject, a code
point a step,
reusing the `crlf_byte_safe_` / `can_match_empty_` gate. The same DFA serves
CodePoint mode on any subject, and one of its rules is the grapheme engine's
alone: a multiline `^` / `$` does not fire *between* the `\r` and the `\n` of a
CR-LF (the pair is one cluster, with no position inside). In CodePoint mode the
pair is two characters and that position ends one line and starts the next, so
the exception is keyed on the unit (`bflags`).

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
byte DFA runs directly over raw UTF-8 with no segmentation and no ASCII
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
`case_extras` lists, for every orbit intersecting a literal/class, the members
it lacks, and they are added (`case_closed`) — so `prog_` accepts every case
variant directly, matching the same fold-equivalence the Pike applies at match
time on `cp_prog_`. (`ß`→`ss` full folding is out of scope, as in the grapheme
engine.)

DFA-based engines (byte DFA, one-pass) apply to US (any UTF-8 subject) and ASCII
grapheme mode, but to non-ASCII *grapheme* matching, where breaking is
stateful, only on a subject of one code point to a cluster (§4). So US is the
fast path for non-ASCII; grapheme captures on a subject with a
multi-code-point cluster stay on the grapheme Pike.

---

## 6. Capture engines

The ordered+cut DFA locates the leftmost-first `[s, e)`; groups are then resolved
*within that span* (bounded by `e`) by the cheapest capable engine over the
**code-point** program `cp_prog_`. Three engines, tried fastest-first:

| Engine | Runs when | How it works |
| --- | --- | --- |
| **CpOnePass** (`build_cp_onepass`) | the pattern is one-pass; span is all single-code-point | A deterministic capture-recording DFA: pc-set states, each transition carrying `(next state, bitmask of capture slots to set here)`. Group 0's two slots are never in a mask — a walk is anchored, so it begins the whole match where it starts and ends it at its accept, and writes the pair itself (`onepass_saves_span`); a capture-free table therefore writes no slot at all. The walks write the caller's slots in place. Records captures in one forward pass at ~DFA speed. Built in two flavours: *uncut* (the full accept set — a longest-match engine, run bounded by `e` or with an accept-at-`n` condition) and *leftmost-first cut* (each state's closure is explored in thread-priority order and truncated at its first `Match`, so an unbounded walk's last accept is the exact leftmost-first end; sound for Alt-free greedy-only programs, where priority order is ascending pc). The per-byte step is **one packed `u32` load** — the next state, a slot-write bit and a next-state-accepts bit in a single word — instead of three loads from separate arrays (three cache lines on the dependency chain); the next state is held as its offset in the state array, in bytes, so that a walk masks the flags off and adds, and multiplies nothing, between one step's load and the next (five groups of a UUID, searched: 117 → 80 ns); a state that self-loops on some ASCII bytes with no slot write (a repeat run like `\S+`, `\d+`, `[^"]*`) skips the whole run with one SIMD membership scan (`run_scan`) instead of a dependent load per byte — engaged once per state *entry*. The looping set is a 16-byte nibble table (low nibble → row, high nibble → bit; two table lookups test 16 bytes, exact for any ASCII set), built at construction: no exit-count cap and no per-call exit-list splat, which is what makes it pay on the dozen-byte tokens real data is made of (an exit-set `scan64` with a scalar pre-probe lost there — its per-call setup outweighed the skipped bytes). The step table has 256 entries with the non-ASCII half dead, so the per-byte loop carries no `≥ 0x80` test; a non-ASCII code point in the span aborts it (→ BitState). |
| **BitState** (`bitstate_bytes`) | not one-pass; span ≤ `kBitStateCap` | Bounded leftmost-first backtracking over `cp_prog_` on the located span, decoding code points on the fly (no segmentation), with a visited bitmap over `(pc, byte-pos)` so it stays O(prog × span); capture writes undo on backtrack. |
| **code-point Pike** (`run_saves` on `cp_prog_` + `segment_cp`) | span overflow, or a DFA giving up that drops the whole pattern | The universal fallback. |

All engines are leftmost-first over the same NFA, so they agree with the
grapheme engine. (A whole-match capture — every group == the whole match,
e.g. `(\w+)` — needs none of them: it has no groups by the time it is planned;
§3, *Root groups*.)

**Unbounded one-pass find (`cp_onepass_find`, `onepass_unbounded_`).** The
bounded chain walks each match three times (forward DFA for `e`, reverse DFA
for `s`, then the capture engine over `[s, e)`). When the AST has **no
alternation, no lazy repeat, and no capturing group under a repeat**, the
table is built with the leftmost-first cut, under which the walk's last
accept from a fixed start *is* the leftmost-first end (greediness alone is
not enough: adjacent nullable repeats like `x(?:ab)?(?:abc)?` commit before
the longest accept) and no capture slot is written after the final accepting
position — so, given the match START from a candidate source, ONE unbounded
one-pass walk yields the end and every capture. The cut prunes in pc order,
which is priority order only among threads that forked in the same step, so
two shapes are barred (`onepass_cut_ast_ok`): a repeat that can run more than
once over a variable-width body (both accepts lie on one thread's path), and
a skippable repeat of several instructions that threads can reach at
different times with something required after it — the earlier, lower-priority
arrival sits inside it at a *lower* pc than the later one that skipped it
(`[a-z]{3,}(?:\w{2}-)?s` over `hssys-s` reported `[0,7)` for `[0,5)`). Two
candidate
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
route through one front door (`onepass_driver_find`; which driver is
decided once, when the plan is built — `Plan::walk_driver_`: literal prefix →
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
stop-at-non-ASCII to any scan (it refers to the predicate it widens rather
than holding a copy: copying one just built was a quarter of
`[a-zA-Z]+ing`'s time). The `_visit` form drives candidate verification
*in place* — the verifier runs on each hit inside the stride and a rejected
candidate continues from the next ctz, not a loop restart — so the
candidate+verify prefilters below (the `find_substr` compare, the `(?i)` fold
compare, the fused-collapse verify) pay one bit-scan per false positive even
when the probe byte is common. `find_substr_if` hands a caller's own reject
to the same verifier (the assert tier's trailing `\b`, which most occurrences
of a letter fail).

**Nibble-table scans (`run_scan`, `word_start_block`).** A predicate over an
arbitrary ASCII *set* is two 16-lane table lookups (low nibble → row, high
nibble → bit: `PSHUFB`/`TBL`), exact whatever the set holds. These are loops
of their own beside `scan64` — its stride is shaped for sparse probes, and a
table lookup needs SSSE3, which it is not dispatched for: `run_scan` (the
one-pass walk's self-loop runs, which end within a block) and `word_start_block`
(WordOnePass's candidates — a byte of the body's start set after a byte that
is not a word byte, as a mask of sixteen positions with the previous block's
last lane carried in; ~14 GB/s where candidates are rare, against ~3.4 for
the byte-at-a-time loop it replaced). The find that takes those masks looks at
its first four positions one byte at a time first (`word_onepass_find`): right
after a match the next candidate is usually a byte or two on, and a predicted
branch hands the walk its start at once where a mask keeps it waiting.

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
  the **rarest** byte of the literal (chosen by an English-prose frequency table,
  `byte_commonness`: space and the common lowercase letters high, capitals low,
  digits / non-ASCII / most punctuation rare → good probes; the punctuation
  prose is full of — `,` `.` `"` `'` `-` and the line break — has its own
  entries, since the same table prices anchors against each other below), then
  compare the candidate in place to verify (`bytes_eq`: inline up to 16
  bytes, `memcmp` beyond; both legs ride `scan64_visit`; zero dependencies). An all-ASCII
  prefix (`prefix_.ascii`) is `memmem`-skippable on *any* UTF-8 subject. A
  needle of two bytes or more scans with a **two-byte pair probe**
  (`PredPair` — rure's memmem shape): stop only where *both* of the needle's
  two rarest bytes appear at their exact needle distance, multiplying the two
  densities — an order of magnitude fewer stops (`ing` on the Sherlock
  corpus: 8033 → 2934) for one extra load per block. (Always, not only when
  the frequency table calls the rarest byte common: the table describes
  English prose, and on any other subject a "rare" byte can stop the scan
  every few bytes — `fox` over a word list ran at 0.07x of the pair's rate,
  where the pair costs prose at most 0.70x.)
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
  `pike_candidate`) call `find_substr_icase` — a SIMD `memchr2` for both cases
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
  Hyperscan / Rust aho-corasick "slim" design; `Regex::Teddy`) looks for the
  leading `N` bytes of *all* alternatives — their fingerprints — a vector at a
  time. Each fingerprint belongs to one of eight buckets, a bit of a byte; per
  block a `PSHUFB`/`TBL` nibble lookup for each fingerprint position gives the
  buckets every byte could be that position of, and a lane where `N`
  consecutive bytes agree on a bucket is a candidate. `N` is the longest
  fingerprint the shortest literal allows (capped at 4).
  - *Where the fingerprints come from.* The program the plan's DFAs run
    (`teddy_collect` walks its start closure): an instruction that takes
    exactly one byte extends a fingerprint, anything else ends the attempt.
    In Grapheme mode that is a `Char` of one ASCII code point. In CodePoint
    mode the program is the UTF-8 byte automaton, and it is a `Byte` of one
    value — so the same alternation gets the same searcher in both modes
    (seven names, CodePoint: 3.3 → 13.4 GB/s; a lexer's nine operators, one
    search: 25 → 12 ns), a fingerprint may be non-ASCII bytes there
    (`café|naïve`), and a class of a few single bytes, which the byte
    automaton holds as a choice between them, reads as one
    (`[Hh]olmes|[Ww]atson`: 1.2 → 12 GB/s).
  - *Up to 64 fingerprints.* Past eight they share buckets, and a shared
    bucket lets through the strings that mix its members' nibbles. `build`
    deals each fingerprint, most common first, to the bucket whose estimated
    firing rate (`byte_commonness`) it raises least, and records which
    buckets are `shared` (more than one fingerprint) and which of those are
    `loose` (let through more than their own). A candidate in any other
    bucket IS its fingerprint; one in a shared bucket is looked up
    (`confirm`) — always for `find_print`, which reports which fingerprint
    is there, and only in loose buckets for `find`, which reports where.
    Sixteen names (`Sherlock|…|Stamford`) went from the DFA's 2.2 GB/s to
    ~12; sixteen keywords from 0.87 to 3.3.
  - *The scans.* One per vector type — 16 bytes (SSSE3, NEON) and 32 (AVX2) —
    each carrying a block's lookups into the next, so a fingerprint that
    straddles two blocks is found without re-reading and the scan advances
    a whole vector per step (three literals, no match: 8.5 → 18 GB/s). The
    last, partial block is put together zero-padded from overlapping word
    loads (`tail_words`; a copy through a stack buffer cost a
    store-forwarding stall on every short subject), and a range under six
    bytes is walked with the same tables (`scan_scalar`, also the fallback
    without SIMD): a lexer's nine operators on a three-byte token went from
    30 ns a search to 12.
  - *Dispatch.* SSSE3 (`_mm_shuffle_epi8`) is not part of the x86-64 baseline
    (SSE2 is), and AVX2 is nobody's: a plain `-O2` Release build defines
    neither, and once silently fell to the scalar scan — a ~10–18× cliff
    on literal-alternation patterns that hit every default Linux build (macOS
    is NEON; cl.exe assumes an SSSE3 baseline). The scans live in
    `target("ssse3")` / `target("avx2")` functions (`scan_ssse3`,
    `scan_avx2`) reached through cached runtime checks (`cpu_has_ssse3()`,
    `cpu_has_avx2()`; `__builtin_cpu_supports`, the `REGEXLIB_SSSE3_DYNAMIC` /
    `REGEXLIB_AVX2_DYNAMIC` tiers), so they compile at the SSE2 baseline and
    run whenever the CPU supports them — no build flag required. A build
    for AVX2 (`-mavx2`, `-march=native`, `/arch:AVX2`) takes the 32-byte scan
    at compile time. `REGEXLIB_DISABLE_AVX2` keeps a build on the 16-byte
    scan and `REGEXLIB_DISABLE_SSSE3` on the scalar one (exotic toolchains /
    A-B testing). The same dispatch shape was tried on `scan64_visit` for
    the VEX/AVX2 encoding win and **rejected on measurement**: an attributed
    wrapper cannot inline into baseline callers, and outlining the scan
    loses the caller fusion (probe + verify as one compiled unit), costing
    more than VEX gains — see the comment at `scan64_visit`. Host-tuned
    builds (`-march=native`, `REGEXLIB_ENABLE_NATIVE`) deliver that win
    instead.
  - *As the matcher.* When **every** alternative is a full ASCII literal
    (not just a shared prefix — `analyze_literal_alternation` →
    `literal_alt_`), Teddy is not a prefilter but the matcher itself:
    `literal_alt_locate` takes the fingerprint `find_print` names, tries the
    literals that begin with it in alternation order (`literal_alt_` keeps
    them grouped by fingerprint, `literal_alt_at_`), and returns the span
    directly with **no DFA verify** — a pure-literal-alternation tier, in
    both modes (`literal_occurrence_ok`). In Grapheme mode a grapheme-boundary check
    (`literal_boundary_ok`) keeps it sound on any subject; a CodePoint
    match is the bytes wherever they are. The short-literal compare is an inlined
    `bytes_eq` (the libc `memcmp` *call* was ~20% of the tier).
  - *As a start skip.* A *mixed* alternation (some branch not a bare literal)
    keeps Teddy as the candidate-finder of the lazy DFAs' start state, of
    the one-pass walk's position scan (`scan_onepass_find`) and of the
    grapheme Pike. What a start state skips with is one decision per program
    family (`StartSkip`: a literal prefix, Teddy, a first-byte set that is
    small and rare, or nothing), and Teddy goes ahead of the first-byte set
    — always, not by estimate. Teddy stops where a match very likely
    begins, at a pace that does not depend on the subject; the first-byte
    scan is faster only for two or three bytes that are rare in the subject,
    and several times slower when they turn out not to be. The walk's scan
    and the Pike's seed take their candidates by the same rule (`scan_skip`,
    which the anchor's pricing reads too); each says what it asks of the
    set — the walk, only that it be small.
- **First-byte (dead-byte) skip** — the generalization of a literal prefix to a
  leading first-byte *set* (`analyze_first_bytes` over the start ε-closure).
  `skip_to_first_byte` is tiered by set size (1 → `memchr`; ≤ 8 → NEON/SSE2 scan;
  else table lookup) and gated on `first_bytes_.sparse` (≤ 32): a dense set
  (`\w` ≈ 63 bytes) would fire rarely and only add overhead, so it pays nothing.
  The lazy DFA's start state asks for it only when the set is also *rare*
  (`dfa_skip`: the summed `byte_commonness` of its bytes under a bar). A
  stop of the skip costs what the DFA steps a dozen bytes in, and a small set
  of common letters stops every few bytes: the first letters of 16 keywords
  ran at 280 MB/s with the skip and 860 MB/s on the bare scan. The bar
  (`dfa_skip_bar`) follows the scan behind the skip: 72 per mille for a set
  the table scans (9 bytes or more: at ~45, the capitals, the skip is 1.6×
  the bare scan; near 85 they tie), and 172 down to 116 for the 1 to 8 bytes
  the SIMD scan takes (three letters still pay at 144 per mille, and no
  longer at 195).
- **ASCII-prefix skip on non-ASCII subjects** — a non-ASCII subject on the
  grapheme Pike still benefits if the pattern has an all-ASCII required prefix:
  `prefix_skip_nonascii` runs `find_substr` over raw UTF-8 with a
  grapheme-boundary guard (part of removing the `/Sherlock/` cliff).
- **Required-suffix-literal scan (`suffix_find`)** — the mirror of the literal
  prefix, for patterns whose best handle is their END: a fixed ASCII literal
  after a fixed-length body — e.g. `[a-q][^u-z]{13}x`, which begins with a
  class (the DFA's own first-byte skip is dense and useless) and whose trailing
  `x` is rare. The
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
  search), capture-free. A pattern that also begins with a literal offers both
  anchors, and which one drives is the *anchor choice* below. Lifted
  `[a-q][^u-z]{13}x` ~57 → ~1650 MB/s
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
- **Rare interior literal (`ReverseInner`)** — for a pattern whose rare fixed
  literal sits in the **middle** (`\w+ Holmes \w+`, `\w+@\w+`): with nothing
  usable at either end the DFA has no skip and walks every byte.
  `find_substr` the interior literal, recover a start floor with a
  reverse DFA over the prefix, then run the normal lf forward + reverse from there.
  Same **seed-not-answer** discipline as the suffix scan: the end is retaken by a
  full forward pass from the floor, because a greedy prefix can swallow the interior
  literal (`.{2,}c\d?`) and reading the span off the literal would be wrong (the
  inner analogue of the *singing* bug — the fuzzer caught it). A pre that can
  absorb the literal must also be step-1 prefix-closed, the suffix scan's own
  gate (`find_inner_run`): the floor comes from the *first* occurrence whose
  reverse(pre) succeeds, and with gaps in the pre's lengths that occurrence
  can be an absorbed one with a floor right of the leftmost match —
  `(?:..)*=x*` over `a==` took `[1,2)` over `[0,3)`. Lifted
  `\w+ Holmes \w+` ~386 → ~10300 MB/s, `\w+@\w+` ~275 → ~21400. (An interior-gap
  literal *alternation*, `Holmes.{0,25}Watson`, is left to Teddy, which already
  fires.) Capture patterns are admitted too — the prefilter only *locates* the
  span, and the capture engine resolves groups on it — but only with a
  **single-node pre** (`(\w+)=(\S+)`): the capture chain re-walks the located
  span anyway, so a long pre-part makes the extra reverse(pre) pass a net loss
  on dense matches (the 7-group access-log pattern regressed before this
  gate). Lifted `(\w+)=(\S+)` over a config corpus ~285 → ~830 MB/s (past RE2
  ~310).
- **Anchor choice (`plan_anchor`, `AnchorChoice`)** — a pattern can offer up to
  three literal anchors (its required prefix, its required suffix, an interior
  literal), and exactly one drives the find. The three used to be taken by
  position — a prefix switched the other two off — which is right for
  `Sherlock\s+Holmes` and 23-90× wrong for a common letter in front of a rare
  one: `e[a-z]{3,}q` verified every `e` in the subject (~0.4 GB/s) while its
  class-led twin `[eE][a-z]{3,}q` scanned for `q` (~34 GB/s). The choice is
  now by **estimated cost**: each anchor the pattern offers is priced from
  `byte_commonness` as *stops × the cost of a stop + occurrences × the cost
  of the verify that anchor needs* (`literal_cost`; ns per MB of prose — a
  single probe stops at every occurrence of the rarest byte, a pair probe
  where the two rarest sit at their distance), and:
  - the prefix is the incumbent — its occurrences are the match starts
    themselves — and keeps the find unless another anchor is at least twice
    as cheap (`kPrefixBias`);
  - a **dense** prefix (estimated ≥ 1 ns per byte, `kDenseNs`) has nothing to
    protect: any cheaper anchor takes over, and with none the fused prefix
    tier is skipped for the scan — the unanchored DFA meets every occurrence
    in one pass where an anchored verify per occurrence re-walks what the
    previous one read (`a[^.]*!`-shaped bodies ran 2× behind the scan);
  - a class-led pattern weighs the suffix / interior literal against its own
    start set, and takes the scan when the set is the rarer event
    (`[A-Z][a-z]+s`: a capital is rarer than an `s`, ~0.55 → ~1.4 GB/s). A
    pattern led by a literal alternation is priced as what its scan skips
    with instead — Teddy's own pace plus its estimated candidates
    (`teddy_cost`, `kTeddyScanNs`);
  - with captures the order stays prefix-first: the one-pass capture drivers
    take the prefix as their candidate source and yield the groups in the
    same walk.

  `suffix_` / `inner_` stay set only for the anchor chosen, so the ladder's
  rungs read the choice without knowing there was one; the record keeps each
  anchor's cost, and the tests pin choices through it (`PlanProbe`). The
  **assert tiers** choose the same way between their leading and trailing
  literal (`plan_assert_anchor`; there the order used to be suffix-first, so
  `Sherlock [a-z]+e\b` scanned for `e`: ~0.35 → ~30 GB/s), and order the word
  scan against the anchor chosen (`wop_after_anchor_`: `\bq[a-z]+e\b` is a
  memchr for `q`, ~29 GB/s where the word scan runs at ~14). Lifted, Sherlock
  corpus: `e[a-z]{3,}q` ~0.4 → ~34 GB/s, `a.{16}z` ~0.4 → ~35, `a[^.]*!`
  ~0.33 → ~9.3, `s[a-z]*\?` ~0.67 → ~16 — each within a few percent of its
  class-led twin.
- **Assertion-tier fixed-text literal** — an assertion pattern (`(?m)^X`, `X$`,
  `^X$`, `\bX\b`) is served by the assertion DFA, which otherwise scans every
  position. When stripping the zero-width assertions leaves a single **fixed
  literal** (`fixed_text`, extracted recursively), the engine `memmem`s that
  literal and confirms each hit with the anchored assertion DFA, shared through
  `assert_find_span`. Lifted
  `(?m)^Sherlock Holmes|Sherlock Holmes$` ~229 → ~12700 MB/s (≈ rure ~8000; RE2
  ~455). An assertion body that *ends* or *begins* in a literal is caught by
  the two prefilters below (which of them, when it does both, is the anchor
  choice above); one with no usable literal anchor keeps the full scan.
- **Assertion-tier required-suffix literal** (`assert_.suffix`,
  `analyze_assert_suffix`) — the suffix analogue of the leading-literal prefilter,
  for an assertion pattern that *ends* in a fixed ASCII literal (the whole
  trailing run of literal characters: `t[a-z]+ly\b` scans for `ly`, not for
  every `y` — ~1.7 → ~5.2 GB/s) after a
  fixed-length / one-code-point-repeat body. The assertion DFA would scan every
  position; instead `assert_suffix_find` `memmem`s the trailing literal and
  confirms each occurrence with the anchored assertion scan, recovering the
  variable start by reverse. A special **word-scan fast shape** handles the exact
  shape `\b \w{n,m} <lit> \b` (`\b\w+n\b`, `\b\w+ing\b`) — "a whole word ending in
  `<lit>`" — with **no DFA at all**: `memmem` the literal, confirm the trailing
  `\b` (the next code point is non-word — inside the scan, `find_substr_if`, as
  `assert_suffix_find` does its own cheap reject), then walk left over word code points to
  the run start (`assert_word_find`), checking the `\w` run length against
  `{n,m}`. Sound because the assert tier serves only single-code-point clusters
  (code point == grapheme) and the `\w` here is exactly the bare Word predicate,
  so the walk reproduces the regex. Lifted `\b\w+n\b` ~190 → ~1,100 MB/s (past
  rure/RE2).
- **Assertion-tier leading literal** (`assert_.prefix`) — when the assertion
  pattern is *not* a fixed text but its **first consuming atoms** are a fixed
  ASCII literal (only zero-width assertions before it: `\.([a-z]+)$`,
  `^foo(\w+)`, `\bID(\d+)`; the whole leading run of literal characters is
  taken), every match begins with that literal, so a `memmem` of it yields
  every candidate start; an **anchored** assert forward scan then verifies the
  whole match (leading + trailing assertions) and gives the variable end. Unlike
  the fixed-text and trailing-literal prefilters this is **not** gated
  capture-free — it drives the location for the assert-capture tier (2a) as well,
  so `\.([a-z]+)$` (capture) and `\.[a-z]+$` (capture-free) both skip the
  position-by-position assert scan (EGC ~640/~515 → ~220/~90 ns). memmem order is
  start order and every match starts with the prefix, so the first verifying hit
  is leftmost-first. A boolean verifies no occurrence: its scan skips to them
  and stops at the first accept (§2, the find ladder).
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
  The tier itself serves both modes: its needle is the byte program's
  leading literal (`byte_prefix_`, which `plan_literal` checks is the whole
  pattern), and what it asks of an occurrence is the alternation tier's
  question (`literal_occurrence_ok`) — cluster boundaries in Grapheme mode,
  nothing in CodePoint mode, where the literal used to be the start skip of
  a DFA scan (`Holmes` over prose 20 → 33 GB/s, `the` 1.5 → 2.1; a search of
  a three-byte token 29 → 18 ns, a `test()` over 60 bytes 52 → 18).

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
  matches up front as a Structure-of-Arrays of byte offsets (`SpanRows`:
  `uint32_t` cells, one `2*(ngroups+1)` row per match) plus one subject buffer;
  `str()`/`group()` are `string_view`s into it via a `Match` proxy. Random
  access, `size()`, multiple passes. A row's cells are handed out unwritten,
  and the block grows by `realloc`, which can extend or remap it in place: as
  a `std::vector` the rows moved to new pages at every doubling and were
  zero-filled before being written, which on dense matches was over 40% of the
  call (measured on glibc).

Both bulk forms are **view-based** — no per-match `std::string`/`std::vector`
allocation. (An owning `vector<MatchResult>` is just `find_iter()`/`find_all()` +
`to_owned()`.) This is deliberate: profiling dense `\w+` once found the per-match
materialization (allocs + reallocating a vector of heavy 120-byte objects)
dominating the run while the offsets-only scan already beat RE2. The columnar
container runs at the offsets-only scan rate (~2.7× over an owning vector on
dense matches) at ~15× less memory.

### Shared stepping

Every form is the find ladder (§2, *The find ladder*) with a different sink.
`search()` and `test()` take one step (`find_once`: a `MatchResult` built in
place, or nothing kept); `find_iter()` holds the scan (`Finder`) and takes one
step per `++`, a row at a time; `find_all()` takes the same step told to run
to the end, appending rows; `find_at()` is one step of a scan seeked to a
position. A DFA rung whose DFA gives up mid-scan (§2, the cache budget)
downgrades to the Pike VM and continues from the current cursor.

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
  std::optional<LazyDfa> dfas_[2][kDfaRoles]; // (segmentation is per-text and
  std::optional<LazyDfa> inrev_;            //  not cached)
  Scratch sc_;
};
MatchList find_all(std::string_view, FindCache&) const;
MatchIter find_iter(std::string_view, FindCache&) const;
```

The DFAs form one table, indexed by program set — the UTF-8 byte programs or
the grapheme / code-point ones — and by role (`DfaRole`: the re-seeding
boolean, the unanchored and the anchored leftmost-first, the reverse);
`inrev_` is the ReverseInner prefilter's own. Every rung fetches its DFAs
through the one accessor `FindCache::dfa`, which builds a missing one out of
line in `FindCache::make` — the one place a role's program and start-state
skip are chosen — so the accessor stays small enough to inline into the short
calls.

The no-cache `find_iter(s)`/`find_all(s)` reuse a **`thread_local` cache** bound by a
process-unique `Regex` id (the id avoids the ABA hazard of a raw-address key — a
destroyed `Regex` whose address is reused gets a different id, so a stale DFA is
never served). The mutable-cache-in-`Regex`-plus-mutex model (RE2's) was rejected
because it would serialize concurrent matching on a shared `Regex`; matching here
stays lock-free, the `Regex` stays `const` and shareable. **Lifetime/threading
contract**: one `FindCache` per thread (not shared between threads), destroyed
before the `Regex` it bound to. On one thread it may serve several Regexes —
the thread-local one does, and a caller's may: **a rung that reads a cached
DFA runs on a cache bound to its Regex**, and a scan that keeps a cache across
calls (`Finder`) binds it at the start of every step that can reach such a
rung, in one place (`Finder::scratch`); a one-step find gets its cache from
`thread_cache()`, which hands it out bound. A cache whose DFA has given up
(§2, the cache budget) simply keeps falling back at that DFA's next miss —
correct, just unaccelerated from there.

`MatchIter` additionally owns its **own** `Scratch` (Pike/backtracker state),
so it is safe across a suspension point (a `++` boundary where the caller
might run other matching on the same thread): another regex rebinding the
shared cache merely costs a rebuild. And the entry of the thread-local map
that such a scan fetched is *pinned* for as long as the scan lives
(`Finder::Pin`): the map evicts when it passes 1024 entries, sparing only
the Regex being called — which protects a frame further up the same call,
not an iterator whose loop body runs a thousand other Regexes. (That one's
cache was freed under it, and its next `++` read freed memory.)

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
ASan/UBSan) is layered. (Sanitizers multiply the run time — ASan about 7×, UBSan
5×, both 15× — so an ASan build draws a fifth of the iterations by default
(`kDefaultIters`); `--iters` sets it either way.)

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
  pike = Regex("(?=[\\s\\S]|$)(?:" + pat + ")(?=[\\s\\S]|$)");
  ```

  The always-true lookahead — the next cluster is anything, or the text ends —
  matches at every position and consumes nothing, and a lookaround is a
  construct neither DFA family compiles (`dfa_ok_`/`dfa_assert_ok_` bow out),
  so this `Regex` runs the Pike — while matching the exact same whole spans.
  It stands in front as well as behind because the Pike rung is not the bare
  VM: it skips to a candidate first (a literal prefix, Teddy, the first-byte
  set) and tries the bounded backtracker there — at every entry point, since
  they share one ladder. A reference that took those would share them with
  every pattern the Pike serves; behind a lookahead none is planned, and the
  VM starts at every position.
  The scan's full sequence is compared span-for-span **and
  capture-for-capture** against the forced-Pike result. This is the check
  that caught the CRLF soundness bugs: `gen_subject` deliberately emits `\r`
  and `\n`, and only a grapheme engine that *does* treat CR-LF as one cluster
  can expose a byte path that wrongly treats it as two.

  **The forcing is itself checked** (`pike_reference` in the fuzzer,
  `pike_twin` in the unit tests, both through `PlanProbe`): a reference whose
  plan holds any accelerated tier, or any of the Pike rung's own
  accelerators, fails the run. It was not always. The wrap
  used to be `(?:PAT)(?:\b|\B)`, chosen when an assertion meant "not
  DFA-able"; then the assert tiers were built to serve exactly `\b` and `\B`,
  and the reference quietly moved onto them — the tiers under test, behind the
  same gates. Two wrong answers sat behind it for as long: a CRLF gate both
  sides shared (`t[^.]+[^q]+\.` matching `t\r\n.`), and CodePoint-mode
  multiline anchors inside a CR-LF pair, which no layer compared against a
  Pike at all. A transformation "the accelerator cannot see through" is a
  claim about the accelerators as they are today; the only way to keep it
  true is to ask the plan.
- **Layer 3 — US-vs-EGC.** UnicodeScalar is a separate byte automaton; the
  reference it is checked against is the proven EGC engine, valid because on a
  subject of **single-code-point, single-grapheme** characters
  (`a b 1 ␣ é ñ α β 日 A É Α`) grapheme- and code-point-unit matching coincide. The alphabet includes case pairs so the
  `IgnoreCase` differential exercises folding (US folds at compile time, EGC at
  match time — they must agree).
- **Layer 4 — non-ASCII assertion byte tier** against the forced grapheme Pike,
  multiline on/off.
- **Layer 5 — `find_iter` vs `find_all`.** The lazy `find_iter()` full sequence must equal
  the eager `find_all()` (every whole span and capture). The two climb the
  same ladder and drive it differently — a step per `++`, against one step
  told to run to the end, under which each rung continues in place and the
  walk has a loop of its own. Plus a
  **`FindCache` reuse** check: a single cache reused across a subject sequence vs
  fresh per subject must agree, guarding cross-subject state accumulation.
- **The entry points share one ladder, which removes a check and asks for
  others.** When `search`, `test`, `find_all` and `find_iter` each had a
  dispatch of their own, comparing them was a cross-check of four
  implementations. It is not any more: what they share, they share. What
  differs between them is now narrow and named, and each has inputs drawn
  for it (`gen_ladder`, `gen_egc_onewalk`): the prefilter rungs as a
  *boolean* takes them (stopping at the first accepting state — subjects
  that lack the literal, hold it once, hold it in the other case, or with a
  combining mark planted inside a real match); the walk from 0 as a *find*
  takes it (a second step must find nothing, an empty match at 0 must not
  come back); the one-pass walk on the EGC byte tier (CR-LF pairs in a class
  that counts them as one element, classes of non-ASCII characters only, one
  non-ASCII character in kilobytes of ASCII).

A `std::regex` differential is kept but is **informational, never a gate** (its
semantics vary across standard libraries), and runs only when asked for
(`regexlib_fuzz --std-diff`): `std::regex` backtracks, and with the default
seed two of its searches — 44 s and 7 s over 9-byte subjects — were four
fifths of the fuzzer's run, 14 of its 17 minutes under ASan. A portable semantic-regression corpus
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

- **Linear time / ReDoS immunity** — single forward pass, reverse clamp, a
  bounded DFA cache; no engine backtracks unboundedly.
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
