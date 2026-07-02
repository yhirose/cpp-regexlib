# regexlib — reference

`regexlib.h` is a single-header regular-expression engine with no external
dependencies (the Unicode tables it needs are generated into the header from the
UCD by `tools/generate_ucd.py`).

This document is the reference for what the engine accepts and how it matches.
For the internals (the lazy DFA, the byte path, prefilters, capture engines, and
the verification strategy) see [design.md](design.md).

## Matching model

- **Unit of matching is the Unicode extended grapheme cluster**, not the code
  point. `.` consumes exactly one user-perceived character, so `/.+/` against
  `"👨‍👩‍👧‍👦"` matches a single element. A character class or `\d`/`\w`/`\s`
  classifies a grapheme by its **base (first) code point**, so it behaves like the
  single character the cluster displays as: `\w`/`\p{L}` match `é` whether written
  NFC (`U+00E9`) or NFD (`e`+`◌́`), and `\s` matches a `\r\n` cluster. (Under the
  `CodePoint` match unit the unit is the code point and the base-character rule
  does not apply — see below.)
- **Match offsets are byte offsets** into the original UTF-8 subject (Go-style
  indexing). They always fall on grapheme-cluster boundaries.
- **Matching is leftmost-first** (Perl-style alternative/quantifier priority),
  with the exceptions noted under *Semantics and known differences*.
- **Matching runs in linear time.** The primary engine is a leftmost-first lazy
  DFA, backed by a Thompson-NFA Pike VM as the semantic fallback; neither
  backtracks, so catastrophic backtracking cannot occur and the engine is immune
  to ReDoS. Backreferences are therefore not supported. (See
  [design.md](design.md) for the engine internals.)

## Match unit: grapheme cluster vs code point

By default the matching unit is the extended grapheme cluster (above). The
match unit is a **process-wide setting**, not a per-pattern flag:

```cpp
reg::set_default_match_unit(reg::MatchUnit::CodePoint); // or ::Grapheme (default)
reg::MatchUnit u = reg::default_match_unit();
```

`CodePoint` switches the unit to the **Unicode scalar value (code point)** — the
model used by RE2 and Rust `regex` — while keeping the same syntax,
leftmost-first semantics, linear-time guarantee, and byte-offset reporting
(offsets then fall on code-point boundaries).

It is read **once per `Regex` at construction and frozen into it**, so set it at
startup (before constructing patterns or spawning threads); it is not a per-match
runtime switch. It is `std::atomic` (a concurrent read during construction is not
a data race), but the intended use is set-once. Construct patterns under each
unit by setting the default around construction.

```cpp
reg::set_default_match_unit(reg::MatchUnit::CodePoint);
reg::Regex re("\\w+");
re.search("héllo").str();  // "héllo"  (é is one code point here)
```

What changes versus the default grapheme unit:

| | grapheme (default) | CodePoint |
| --- | --- | --- |
| `.` on `"e"+◌́` (e + combining acute) | the whole cluster (3 bytes) | just `"e"` (1 byte) |
| `\w` / `\p{L}` on `"e"+◌́` | the whole cluster (base `e` is a letter) | just `"e"` (combining mark stops it) |
| `\d \w \s [..] \p{…}` | classify a cluster by its base code point | match one code point |
| match offsets | byte offsets on grapheme boundaries | byte offsets on code-point boundaries |
| a lone/invalid UTF-8 byte | one fallback element | one code point (the byte value) |

Everything else is identical — literals, alternation, quantifiers, groups,
anchors, lookaround, named groups, the flags below (including `IgnoreCase`), and
all method APIs behave the same; only the unit of `.`/classes and the boundary
of offsets differ.

**Why it exists — no non-ASCII cliff.** In grapheme mode, grapheme breaking is
stateful, so any non-ASCII byte drops the whole subject off the lazy-DFA fast
path onto the (slower) grapheme Pike VM. The CodePoint unit compiles the pattern
to a **UTF-8 byte automaton** that the DFA runs directly over raw UTF-8 with no
segmentation, so non-ASCII text matches at the same speed as ASCII (≈RE2), with
no cliff. Captures / anchors / lookaround use a code-point engine stack (a
one-pass DFA, a bounded backtracker, and a code-point Pike) that is likewise
free of the cliff. See [design.md](design.md).

Choose `CodePoint` when you want code-point semantics or maximum throughput on
non-ASCII text; keep the default `Grapheme` when `.` should mean "one
user-perceived character" (emoji/ZWJ/combining-sequence correctness).

## Supported syntax

| Category | Syntax |
| --- | --- |
| Literal | any character; a base + combining marks form one literal grapheme |
| Any | `.` (excludes line breaks unless DotAll — see below) |
| Anchors | `^`, `$` (line-relative under Multiline) |
| Character class | `[abc]`, `[a-z]`, `[^…]`; `\p{…}` and `[:posix:]` may appear inside |
| Predefined class | `\d \w \s` and `\D \W \S` (Unicode-property aware) |
| POSIX class | `[[:alpha:]]`, `[[:digit:]]`, … inside a bracket (see below) |
| Unicode property | `\p{Name}`, `\P{Name}`, single-letter `\pL` |
| Quantifiers | `* + ?`, `{n}`, `{n,m}`, `{n,}`; lazy variants `*? +? ?? {n,m}?` |
| Alternation | `\|` |
| Group | `(…)` capturing, `(?:…)` non-capturing |
| Named group | `(?<name>…)`, `(?'name'…)` |
| Word boundary | `\b`, `\B` |
| Escapes | `\n \r \t \f \v \0`, `\xHH`, `\x{…}`, `\uHHHH`, escaped metacharacters |
| Lookahead | `(?=…)`, `(?!…)` — variable length |
| Lookbehind | `(?<=…)`, `(?<!…)` — variable length |
| Flags (inline) | `(?i)`, `(?m)`, `(?s)` |

`.` excludes the line-break graphemes `\n`, `\r`, `\v`, `\f`, NEL (U+0085),
LS (U+2028) and PS (U+2029). `DotAll` makes `.` match those too.

Supported `\p{…}` names: `L Lu Ll Lt Lm Lo N Nd Nl No P M S Z C` and
`White_Space`, plus the long aliases (`Letter`, `Number`, `Punctuation`,
`Mark`, `Symbol`, `Separator`, `Other`, `Uppercase_Letter`, …).

POSIX classes appear only inside a bracket expression (`[[:alpha:]]`, or combined
like `[A-F[:digit:]]`). `alpha alnum digit upper lower space punct word` are
**Unicode-aware** (the same sets as `\p{L}`/`\d`/`\s`/…); `blank xdigit cntrl
graph print` use the classic ASCII definitions. Inner negation `[:^alpha:]` is
unsupported and **throws** (rather than silently becoming a literal set) — negate
the whole bracket with `[^[:alpha:]]` instead.

## API

Three constructor overloads — flags, an explicit match-unit pin, or both:

```cpp
reg::Regex re(pattern);                       // flags = 0, unit = global default
reg::Regex re(pattern, flags);                // flags only
reg::Regex re(pattern, unit);                 // pin the match unit, flags = 0
reg::Regex re(pattern, flags, unit);          // both
```

Flags are an OR-combinable mask:

| Flag | Equivalent | Effect |
| --- | --- | --- |
| `reg::IgnoreCase` | `(?i)` | case-insensitive |
| `reg::Multiline` | `(?m)` | `^`/`$` match at line breaks |
| `reg::DotAll` | `(?s)` | `.` matches a line break |

Constructor flags and inline flags compose (either turns the flag on).

### Pinning the match unit per-Regex

`unit` is a `reg::MatchUnit` (`Grapheme` or `CodePoint`). Because it is a scoped
enum it never converts to the `unsigned` flags, so the unit-only overload is
selected purely by type — no flags placeholder is needed:

```cpp
reg::Regex re(pat, reg::MatchUnit::CodePoint);                 // unit only
reg::Regex re(pat, reg::IgnoreCase, reg::MatchUnit::CodePoint); // flags + unit
```

Unit resolution is: **passed → that unit (frozen into this Regex); omitted →
the process-wide `reg::default_match_unit()` read at construction.** Pinning the
unit per-Regex is the explicit, **thread-safe** alternative to
`set_default_match_unit` — its value does not depend on a global another thread
might change. Either way the unit is frozen at construction; changing the global
afterwards only affects later-constructed `Regex` objects.

Methods:

| Method | Result |
| --- | --- |
| `re.test(s)` | `bool` — does the pattern match anywhere |
| `re.search(s)` | `MatchResult` — leftmost match anywhere (owning) |
| `re.match(s)` | `MatchResult` — match anchored at the start (owning) |
| `re.find_iter(s)` | `Regex::MatchIter` — lazy range over all matches (see below) |
| `re.find_iter(s, cache)` | as above, reusing a `Regex::FindCache` |
| `re.find_all(s)` | `Regex::MatchList` — eager columnar container (see below) |
| `re.split(s)` | `Regex::SplitIter` — lazy range of the pieces between matches |
| `re.find_at(s, pos)` | `Regex::FindAt` — one stateless scan step at/after `pos` (see below) |
| `re.replace_all(s, repl)` | `std::string` — replace every match (`$`-grammar below) |
| `re.replace_first(s, repl)` | `std::string` — replace only the leftmost match |

#### One match type

A (sub)match is a **`Match`** — used for the whole match and for every capture
group alike, with a single accessor surface:

| call | result |
| --- | --- |
| `m.matched()` / `if (m)` | did it match |
| `m.begin()` / `m.end()` | byte offsets |
| `m.str()` | the matched text (a `std::string_view`) |
| `m.group(i)` / `m.group("name")` | a sub-group, as a `Match` (group 0 = the whole match) |
| `m.group_count()` | number of capture groups |
| `m.to_owned()` | copy into an owning `MatchResult` (views only) |

`group()` returns a `Match` recursively, so `m.group(1).str()`,
`m.group(1).begin()`, and `m.group("name").matched()` all read the same way. An
unmatched or out-of-range group reports `matched() == false` (`str() == ""`).

`search()`/`match()` return a single self-contained **`MatchResult`** — it copies
the matched text, so it outlives the subject — that exposes this **same** method
surface. A match-processing block therefore reads identically whether the match
came from `search()`, `find_iter()`, or `find_all()`; only the ownership
differs. For **all** matches there are two bulk APIs, split by role:

### `find_iter()` — lazy, single-pass

`re.find_iter(s)` returns a `Regex::MatchIter` range. The engine steps **one
match per `++`**, so breaking out of the loop stops scanning the rest of the
subject — the tool for early-exit, streaming, and range composition. Each
iteration yields a `Match` view that borrows the subject and is **valid only
until the next `++`** — copy out (or `to_owned()`) anything you need to keep. A
temporary `std::string` subject is rejected (`find_iter(std::string&&)` is
deleted), since the views would dangle; bind it to a variable first.

```cpp
for (auto m : re.find_iter(text)) {
  if (m.begin() > limit) break;          // remaining text is never scanned
  use(m.str(), m.group(1).str());        // views, valid until the next ++
}
auto owned = (*re.find_iter(text).begin()).to_owned();  // keep one past the loop
```

`Regex::FindCache` is a reusable scratch object that persists the lazy DFA
across calls. The plain `find_iter(s)`/`find_all(s)` reuse this thread's DFAs;
passing a `FindCache` keeps them warm across many small documents, skipping
per-call construction (≈6× on a many-document tokenize). A `FindCache` is used
by a single thread and must be destroyed before the `Regex` it was passed to
(the same contract as PCRE2's `pcre2_match_data` or Hyperscan's scratch); the
`Regex` itself stays shareable across threads.

### `split()` — lazy pieces between matches

`re.split(s)` returns a `Regex::SplitIter` range yielding the substrings
**between** matches as `std::string_view`s. `N` matches give `N+1` pieces (the
gap before each match, then the trailing remainder); a pattern that never
matches yields a single piece (the whole subject); an empty match yields an
empty piece on each side. Lazy and early-exitable like `find_iter`, with the
same deleted-rvalue rule.

```cpp
std::string csv = "a,bb,,ccc";
for (auto field : re_comma.split(csv)) use(field);   // "a", "bb", "", "ccc"
```

### `find_at()` — one stateless scan step

```cpp
struct Regex::FindAt {
  MatchResult m;   // unmatched when there is no match at/after pos
  size_t next_pos; // resume position; text.size() + 1 when scanning is done
};
FindAt Regex::find_at(std::string_view text, size_t pos) const;
FindAt Regex::find_at(std::string_view text, size_t pos, FindCache &cache) const;
```

`re.find_at(s, pos)` performs exactly one step of `find_iter()` without holding
an iterator: the leftmost match at or after byte offset `pos`, plus the
position the scan resumes from. It exists for **external steppers** — a
generator or coroutine that must persist a plain integer between calls instead
of a live `MatchIter`. Stepping `find_at` from 0 visits exactly the same
matches as `find_iter`.

`next_pos` follows the engine's empty-match advance rule for this `Regex`'s
match unit — the match end for a non-empty match, and one **grapheme cluster**
(Grapheme mode) or one **code point** (CodePoint mode) past an empty match — so
a scan always makes progress and never resumes mid-cluster (e.g. an empty match
before the `\r` of a CR-LF resumes after the `\n`, never between them). A
caller-side boundary computation cannot know the match unit; the engine does.

```cpp
size_t pos = 0;                        // the only state between calls
while (pos <= text.size()) {
  auto [m, next] = re.find_at(text, pos);
  if (!m.matched()) break;
  use(m);
  pos = next;                          // always > pos: guaranteed progress
}
```

Precondition: `pos` is `0` or a `next_pos` previously returned for the same
text (a valid scan position — this anchors left-context rules such as
regional-indicator parity). Anchors and word boundaries see the full subject:
`find_at(s, pos)` is a scan *positioned* at `pos`, not a search of
`s.substr(pos)`, so `^` does not match at a non-zero `pos` and `\b` sees the
real left context. Each call is an independent scan step (per-subject engine
state beyond the `FindCache` is rebuilt); for bulk iteration inside one call
frame, `find_iter()`/`find_all()` remain the right tools.

### `find_all()` — the eager columnar container

`re.find_all(s)` returns a `Regex::MatchList`: all matches computed up front and
stored as a compact columnar (Structure-of-Arrays) block of byte offsets plus a
single subject buffer. Unlike the single-pass `find_iter()`, it supports random
access (`ms[i]`), `size()`, and multiple passes. `str()` and `group()` return
views into the buffer (no per-match allocation), so it runs at the offsets-only
scan speed with far less memory than an owning vector, while still giving the
matched text and captures. Reach for `find_all()` when you need the whole result
set indexable; reach for `find_iter()` when one pass / early-exit / low peak
memory is what you want.

Access is through the same `Match` surface via range-for or `operator[]`:

```cpp
reg::Regex re(R"((\w+)@(?<host>\w+))");
for (auto m : re.find_all("a@b c@d")) {
  m.str();             // "a@b"        (string_view into the subject)
  m.begin(); m.end();                  // byte offsets
  m.group(1).str();    // "a"          (group 0 is the whole match)
  m.group("host").str();  // by name, "" if the group is unmatched
  m.group(2).matched();   // bool
}
auto ms = re.find_all(text);
ms.size(); ms[0].str();                // random access
```

**Ownership / lifetime** follows the argument, so the common cases are safe and
zero-copy:

| call | mode | lifetime |
| --- | --- | --- |
| `find_all(lvalue_string)` / `find_all(string_view)` / `find_all("literal")` | **borrow** (zero-copy) | the `MatchList` must not outlive the subject (the `string_view` contract); don't mutate/reallocate the subject while it is alive. A string literal is fine (static). |
| `find_all(rvalue_string)` e.g. `find_all(read_file())` | **move-own** (free move) | self-contained; safe for temporaries |
| `find_all_copy(string_view)` | **copy-own** | self-contained; one copy of the subject |

So a by-value-returned temporary is moved in (no dangling), and you can force a
self-contained result from a borrowed lvalue with `find_all_copy(s)` or
`find_all(std::string(s))`. A `FindCache` overload (`find_all(s, cache)`) reuses
the DFA across calls, as `find_iter(s, cache)` does. If you need an owning
`std::vector<MatchResult>`, collect it from either view with `to_owned()`.

```cpp
reg::Regex re(R"(\w+)");
reg::Regex::FindCache cache;          // one per thread
for (const auto &doc : docs)
  for (auto m : re.find_iter(doc, cache)) {   // docs 2..N pay no DFA rebuild
    /* ... */
  }
```

### Replacement `$`-grammar

`replace_all` / `replace_first` expand, in `repl`:

| token | expands to |
| --- | --- |
| `$&` | the whole match |
| `` $` `` / `$'` | the text before / after the match |
| `$1`–`$99` | capture group N (greedy two digits) |
| `$<name>` | the named capture group |
| `$$` | a literal `$` |

An unrecognized escape, or a group ref past the last group, leaves the `$`
literal. (This is the same grammar the std::regex-compat `regex_replace`
expands, except that facade does not interpret `$<name>` — see below.)

A pattern that cannot be parsed (or that exceeds a resource limit) throws
`reg::RegexError`, whose `what()` message carries the offending position and
a caret line. `RegexError::code()` additionally returns a structured
`RegexError::Code` (RE2-style: `TrailingBackslash`, `BadEscape`, `BadCharClass`,
`UnbalancedParen`, `BadGroup`, `BadInlineFlags`, `BadUnicodeProperty`,
`NestingTooDeep`, `NothingToRepeat`, `ProgramTooLarge`, `PatternTooLong`,
`StepBudgetExceeded`, `Internal`) for branching without parsing the message.

## std::regex-compatible API

Alongside the native `reg::Regex` API, `regexlib.h` ships a drop-in
`std::regex`-compatible facade in the **same `reg` namespace**. It mirrors the
`<regex>` surface so existing `std::regex` code ports by aliasing the namespace —
`namespace re = reg;` — and rewriting `std::` → `re::`:

```cpp
namespace re = reg;                       // was: namespace re = std;

re::regex pat(R"((\w+)=(\w+))");          // basic_regex
re::smatch m;
if (re::regex_search(line, m, pat))
  use(m[1].str(), m[2].str());            // sub_match::str()

std::string out = re::regex_replace(line, pat, "$2=$1");   // $-format
for (re::sregex_iterator it(line.begin(), line.end(), pat), end; it != end; ++it)
  use((*it)[1].str());
```

The native engine uses PascalCase names (`Regex`, `MatchResult`, `Match`) and
the compatible layer uses `std`-style snake_case (`regex`, `smatch`,
`regex_search`), so the two coexist in `reg` without clashing. `char` /
`std::string` only (no `wchar_t`).

### Provided names

| Kind | Names |
| --- | --- |
| Pattern | `basic_regex`, `regex` |
| Match objects | `sub_match`, `match_results`; `ssub_match`/`csub_match`, `smatch`/`cmatch`/`svmatch` |
| Algorithms | `regex_search`, `regex_match`, `regex_replace` |
| Iteration | `regex_iterator` (`sregex_iterator`/`cregex_iterator`), `regex_token_iterator` (`sregex_token_iterator`/`cregex_token_iterator`) |
| Constants | `regex_constants::syntax_option_type`, `match_flag_type`, `error_type` |
| Error | `regex_error` (derives from `RegexError`, adds `code()`) |

`regex_search` / `regex_match` / `regex_replace` take `std::string`, `const
char*`, `std::string_view`, or an iterator pair, with the same overload set as
the standard (the rvalue-`std::string` + `smatch` overload is deleted to avoid a
dangling match, matching `std::regex`). `match_results::format` and
`regex_replace` expand the ECMAScript `$` grammar (`$&`, `` $` ``, `$'`,
`$1`–`$99`, `$$`). `regex_token_iterator` supports the `-1` submatch index, so
the standard split idiom (`sregex_token_iterator(b, e, re, -1)`) works.

### Flags

`syntax_option_type` and `match_flag_type` are accepted for source compatibility;
those with a regexlib equivalent are honored, the rest are ignored (so existing
call sites still compile):

| Honored | Ignored (accepted, no effect) |
| --- | --- |
| `icase` → `IgnoreCase`, `multiline` → `Multiline` | `nosubs`, `optimize`, `collate`, the grammar selectors |
| `match_continuous` (anchor at start), `format_no_copy`, `format_first_only` | `match_not_bol/eol/bow/eow`, `match_any`, `match_not_null`, `match_prev_avail`, `format_sed` |

`reg::regex` follows the process-wide `reg::default_match_unit` (ships
`Grapheme`), so by default it is grapheme-aware like the native API. std::regex
over `std::string` is byte-oriented and already broken on UTF-8, so this loses no
meaningful parity (ASCII is identical); call
`reg::set_default_match_unit(reg::MatchUnit::CodePoint)` at startup for the
closest std::regex behaviour.

### Deliberate divergences from `std::regex`

Read these before porting; they do **not** all fail the same way:

- **Code-point `.`, not byte `.`.** Over a `std::string`, `std::regex`'s `.`
  matches one *byte* (splitting a multi-byte UTF-8 character); this facade's `.`
  matches one *code point*. On ASCII the two are identical; on UTF-8 this facade
  is *more* correct, not byte-for-byte identical to `std::regex`.
- **Linear-time, ReDoS-proof — backtracking-only constructs are rejected.**
  Atomic groups `(?>…)` and possessive quantifiers (`a++`, `a*+`) throw
  `regex_error` at construction; a pathological pattern such as `(a+)+$` runs in
  linear time instead of detonating.
- **A backreference becomes a literal, silently.** `\1` is parsed as the escaped
  digit `1`, not a back-reference (it does **not** throw), so `(\w)\1` matches
  `"a1"`, not `"aa"`. (POSIX classes such as `[[:alpha:]]`, on the other hand,
  *are* supported — unlike ECMAScript `std::regex` — see Supported syntax.)

`reg::regex_error` derives from `reg::RegexError`, so `catch (re::regex_error&)`,
`catch (reg::RegexError&)`, and `catch (std::runtime_error&)` all keep working
for ported code; `code()` returns the standard `regex_constants::error_type`,
translated from the engine's structured `RegexError::Code`.

## Semantics and known differences

- **Grapheme units** differ from PCRE / RE2 / Python `re`, which match by code
  point. A multi-code-point cluster (emoji, ZWJ sequences, base + combining
  marks) is one element: `.` consumes it whole, and a class is decided by the
  cluster's base (first) code point — `\w`/`\p{L}` match `é` in NFC or NFD form,
  `\s` matches a `\r\n` cluster, and `[a-z]` matches `e`+◌́ (base `e`). So a
  positive class can match a multi-code-point cluster (unlike code-point engines),
  and a negated predicate (`\D`, `[^…]`, `\S`) does *not* match a cluster whose
  base is in the set.
- **CR-LF is one cluster, on every subject.** `\r\n` is a single grapheme cluster
  (UAX #29 GB3), so it counts as one element for `.`, for a counted repeat
  (`[^"']{0,30}`, `.{0,4}`), and as one line break for multiline `^`/`$` (which do
  NOT fire between the `\r` and the `\n`) — uniformly, regardless of whether the
  subject is pure ASCII. (A lone `\r` or lone `\n` is its own cluster.) This
  differs from code-point engines (PCRE / RE2 / Python `re`), which treat `\r\n`
  as two characters; set the `CodePoint` match unit for that behavior.
- **Nullable quantifier corner.** An unbounded quantifier whose body can match
  the empty string stops after an empty iteration (the Perl rule), so `(.*?)*`
  matches the empty string. One sub-case differs from Perl: an alternation
  whose first branch is nullable, nested in an unbounded quantifier, yields the
  POSIX leftmost-longest result rather than Perl's leftmost-first — `(a*|b)*`
  against `"ab"` matches `"ab"` (POSIX) where Perl yields `"a"`. Reproducing
  Perl here would require backtracking, which is incompatible with the
  linear-time guarantee; RE2 documents the same class of divergence.
- **Captures inside a lookaround are not exported.** Groups inside `(?=…)` /
  `(?<=…)` are treated as non-capturing.
- **Inline flags apply globally.** `(?i)`, `(?m)`, `(?s)` set the flag for the
  whole pattern regardless of position; scoped flags `(?i:…)` are not scoped.
- **`\b` at the end of the subject matches**, as in Perl and Python.

## Resource limits

To keep a small adversarial pattern from exhausting memory or the stack, a
pattern that exceeds any of these raises `RegexError` at construction:

| Limit | Value |
| --- | --- |
| Pattern source length | 32 KiB |
| Compiled program size | 262144 instructions |
| Nesting depth | 200 |

These bound compile cost (e.g. `a{1000000}`, nested `(x{50}){50}…`) and parser
recursion (e.g. `((((…))))`). The nesting limit is kept conservative so the
recursive-descent parser stays within the smallest common thread stack
(Windows' 1 MiB main-thread stack); hand-written patterns nest far below it.

Match time is linear in the subject length, but the constant is the program
size, so a dense pattern (e.g. `(a?){9000}`) on a long subject is
bounded-but-slow. A match-time step budget, proportional to the subject length,
caps this: a match that exceeds it raises `RegexError` from the matching call
(`search`, `match`, `find_iter`, `find_all`, `test`, `replace_all`) rather than running for
many seconds. Real patterns stay far below the budget. The ε-closure is
iterative, so a long zero-width chain cannot overflow the stack.

## Not supported

| Feature | Reason / alternative |
| --- | --- |
| Backreferences `\1` | NP-hard; incompatible with the linear-time guarantee |
| Conditionals, atomic groups, possessive quantifiers | not implemented |
