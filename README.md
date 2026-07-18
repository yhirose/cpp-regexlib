cpp-regexlib
============

[![CI](https://github.com/yhirose/cpp-regexlib/actions/workflows/ci.yml/badge.svg)](https://github.com/yhirose/cpp-regexlib/actions/workflows/ci.yml)
[![Benchmark](https://github.com/yhirose/cpp-regexlib/actions/workflows/benchmark.yml/badge.svg)](https://github.com/yhirose/cpp-regexlib/actions/workflows/benchmark.yml)

C++17 single-header, grapheme-aware, linear-time (ReDoS-safe) regular-expression
engine. Just include `regexlib.h` in your project to start using it — there
are no external dependencies.

Four things distinguish it from a typical `std::regex`-style engine:

1. **A single self-contained header, no dependencies.** The whole engine —
   including the Unicode 17.0.0 tables it needs — is generated into `regexlib.h`,
   so there is nothing to link, fetch, or build separately; just include it.
   The API is ordinary C++ (`reg::Regex`, value types, range-based `for`), not a
   C-style or FFI surface.

2. **Matching runs in linear time.** Matching is leftmost-first (Perl
   alternation/quantifier priority), executed by a leftmost-first lazy DFA with a
   Thompson-NFA Pike VM as the semantic fallback. Neither backtracks, so
   catastrophic backtracking cannot occur by construction — the engine is immune
   to ReDoS. (Backtracking-only constructs such as backreferences are therefore
   not supported; see [Scope and status](#scope-and-status).)

3. **It is a drop-in `std::regex` replacement.** A `std::regex`-compatible API
   (`regex`, `smatch`, `regex_search`/`regex_match`/`regex_replace`, the
   iterators) ships in the same header, so most `std::regex` code ports by just
   aliasing the namespace (`namespace re = reg;`) — getting the linear-time,
   ReDoS-proof engine for free. Like the native API the compatible layer follows
   the process-wide match unit (a grapheme cluster by default); set the
   `CodePoint` unit for the closest `std::regex` behaviour — either way it is
   identical to `std::regex` on ASCII and more correct on UTF-8. (See
   [below](#stdregex-compatible-api).)

4. **The matching unit is the Unicode extended grapheme cluster** (Unicode
   17.0.0), not the code point. `.` consumes exactly one user-perceived
   character, so `.+` against `"👨‍👩‍👧‍👦"` matches a single element. Match
   offsets are byte offsets into the original UTF-8 subject and always fall on
   grapheme-cluster boundaries. Opt into matching by **Unicode scalar value
   (code point)** instead — the RE2/Rust model — process-wide with
   `reg::set_default_match_unit(reg::MatchUnit::CodePoint)`, or per-Regex by
   passing the unit to the constructor
   (`reg::Regex re(pat, reg::MatchUnit::CodePoint)`; see the docs).

Usage
-----

```cpp
#include "regexlib.h"
#include <iostream>

int main() {
  reg::Regex re(R"((\w+)@(\w+))", reg::IgnoreCase);

  if (re.test("contact alice@example"))
    std::cout << "matched\n";

  auto m = re.search("contact alice@example today");
  if (m) {
    std::cout << m.str()          << '\n';  // alice@example
    std::cout << m.group(1).str() << '\n';  // alice
    std::cout << m.group(2).str() << '\n';  // example
  }

  std::string text = "a@b c@d";
  for (auto hit : re.find_iter(text))  // lazy: break out early to stop scanning
    std::cout << hit.begin() << ".." << hit.end() << ' ' << hit.str() << '\n';

  // $&, $`/$', $1..$99, $<name> expand to the match/captures; $$ is a literal '$'.
  auto out = re.replace_all("a@b c@d", "$2/$1"); // "b/a d/c"
}
```

API
---

```cpp
namespace reg {

// Flags are OR-combinable.
enum Flag : unsigned { IgnoreCase, Multiline, DotAll };

// Match unit: grapheme cluster vs. code point. A process-wide default, set once
// at startup and frozen into each Regex at construction (or pinned per-Regex by
// passing a MatchUnit to the constructor below). A scoped enum, so it never
// collides with the unsigned flags in overload resolution.
enum class MatchUnit { Grapheme, CodePoint };  // default: Grapheme

void      set_default_match_unit(MatchUnit);
MatchUnit default_match_unit();

class Regex {
  // Throws RegexError on an invalid pattern. Three overloads: flags only, an
  // explicit per-Regex match-unit pin (selected by type — no flags placeholder),
  // or both. An omitted unit follows the process-wide default at construction.
  explicit Regex(std::string_view pattern, unsigned flags = 0);
  explicit Regex(std::string_view pattern, MatchUnit unit);
  Regex(std::string_view pattern, unsigned flags, MatchUnit unit);
  //   reg::Regex re(pat, reg::IgnoreCase | reg::Multiline);
  //   reg::Regex re(pat, reg::MatchUnit::CodePoint);
  //   reg::Regex re(pat, reg::IgnoreCase, reg::MatchUnit::CodePoint);

  bool        test(std::string_view text) const;    // is there any match?
  MatchResult match(std::string_view text) const;   // match anchored at start
  MatchResult search(std::string_view text) const;  // match anywhere

  std::string replace_all(std::string_view text, std::string_view repl) const;
  std::string replace_first(std::string_view text, std::string_view repl) const;

  // Two bulk flavors, both yielding lightweight Match views into the subject.
  MatchIter find_iter(std::string_view text) const;  // lazy, single-pass; break out early to stop
  MatchList find_all(std::string_view text) const;   // eager columnar container; random access, size()

  // Lazy iterator over the pieces between matches; N matches yield N+1 pieces.
  SplitIter split(std::string_view text) const;

  // One stateless scan step, for external steppers (generators/coroutines):
  // the leftmost match at/after pos, plus the resume position — the match
  // end, or one grapheme / code point (per the match unit) past an empty
  // match, so a scan always progresses and never resumes mid-cluster.
  struct FindAt { MatchResult m; size_t next_pos; };
  FindAt find_at(std::string_view text, size_t pos) const;

  // A FindCache reuses the compiled automaton across calls instead of
  // rebuilding it each time (~6x on a many-document tokenize):
  class FindCache;
  MatchIter find_iter(std::string_view text, FindCache &) const;
  MatchList find_all (std::string_view text, FindCache &) const;

  // find_all() can also own its subject, so matches outlive the input string:
  MatchList find_all     (std::string &&text) const;  // move the subject in
  MatchList find_all_copy(std::string_view text) const;  // copy the subject in
};

// One type for both the whole match and every group: group(0) is the whole
// match, and group() recurses. search()/match() return an owning MatchResult
// with this same surface.
class Match {  // a borrowing view into the subject
  bool             matched() const;
  explicit operator bool() const;

  size_t           begin() const, end() const;  // byte offsets
  std::string_view str() const;

  Match            group(size_t i) const;       // by index, or group("name")
  size_t           group_count() const;

  MatchResult      to_owned() const;
};

// Construction failures throw RegexError (a std::runtime_error): a caret-annotated
// what(), plus a structured RE2-style code() for programmatic handling.
struct RegexError : std::runtime_error {
  enum class Code { /* … */ };
  Code code() const noexcept;
};

}  // namespace reg
```

See [docs/reference.md](docs/reference.md) for the full reference: every overload,
the `RegexError::Code` taxonomy, supported syntax, semantics, and known
differences from Perl/RE2.

std::regex-compatible API
-------------------------

`regexlib.h` also ships a drop-in `std::regex`-compatible facade in the same
`reg` namespace. Existing `std::regex` code ports by aliasing the namespace and
rewriting `std::` → `re::`:

```cpp
namespace re = reg;                       // was: namespace re = std;

re::regex pat(R"((\w+)=(\w+))");
re::smatch m;
if (re::regex_search(line, m, pat))
  std::cout << m[1].str() << ' ' << m[2].str() << '\n';

std::string out = re::regex_replace(line, pat, "$2=$1");          // $-format
for (re::sregex_iterator it(line.begin(), line.end(), pat), end; it != end; ++it)
  std::cout << (*it)[1].str() << '\n';
```

It mirrors the `<regex>` surface — `basic_regex`/`regex`, `sub_match`,
`match_results`/`smatch`/`cmatch`, `regex_search`, `regex_match`,
`regex_replace`, `regex_iterator`, `regex_token_iterator`, and `regex_constants`.
The native API is PascalCase (`Regex`, `MatchResult`) and the compatible layer is
`std`-style snake_case (`regex`, `smatch`), so the two coexist in `reg` without
clashing.

A few deliberate divergences (the engine is linear-time and ReDoS-proof, so
backtracking-only features can't be supported as-is):

- **`.` is not byte-oriented.** It follows the process-wide match unit — a
  grapheme cluster by default (like the native API), or a code point under
  `reg::set_default_match_unit(reg::MatchUnit::CodePoint)`. Either way it is
  identical to `std::regex` on ASCII and more correct on UTF-8, where
  `std::regex`'s `.` splits a multi-byte character.
- **Atomic groups `(?>…)` and possessive quantifiers `a++` throw** at
  construction; a back-reference `\1` is read as the literal digit (so `(\w)\1`
  matches `"a1"`, not `"aa"`). (POSIX classes like `[[:alpha:]]` *are* supported,
  unlike ECMAScript `std::regex`.)
- `reg::regex_error` derives from `RegexError`, and `code()` returns the standard
  `regex_constants::error_type` taxonomy.

See [docs/reference.md](docs/reference.md#stdregex-compatible-api)
for the full compatible-API reference — provided names, honored vs ignored flags,
and the porting gotchas.

Scope and status
----------------

The linear-time guarantee is a deliberate trade-off, and a few of its
consequences are worth stating plainly:

- **It is not a full PCRE replacement.** Backreferences, atomic groups `(?>…)`,
  and possessive quantifiers (`a++`) are backtracking-only constructs and are not
  supported — the first is NP-hard, the rest are incompatible with the
  linear-time contract. If you need them, PCRE2 is the right tool. (Variable-length
  lookahead and lookbehind, named groups, Unicode properties, and inline flags
  *are* supported; see [docs/reference.md](docs/reference.md).)

- **It does not aim to be the fastest engine.** Throughput is broadly in the
  range of other linear-time engines (RE2, Rust's `regex`) — faster on some
  patterns, slower on others — and a JIT-compiled backtracker such as PCRE2-JIT is
  faster on many workloads. What it offers instead is the linear-time / ReDoS-safe
  guarantee with no external dependency in a single header. The
  [benchmark](https://github.com/yhirose/cpp-regexlib/actions/workflows/benchmark.yml)
  workflow tracks where it stands against `std::regex`, RE2, rure, and PCRE2-JIT.

- **SIMD is automatic; host-tuned builds are opt-in.** The hot scans use
  NEON/SSE2 (baseline on every target), and the SSSE3 Teddy multi-literal scan
  selects itself at runtime by CPU detection — a plain `-O2`/`Release` build
  already gets all of this. On top of that, compiling for the build machine's
  CPU (`-march=native` on GCC/Clang) adds roughly 15–50% on several pattern
  shapes on x86-64 through VEX/AVX2 code generation. Header consumers just add
  that flag to their own build; this repo's CMake exposes it as
  `-DREGEXLIB_ENABLE_NATIVE=ON` (default OFF — the resulting binary requires
  the build machine's CPU features and is not portable).

For the engine internals, please see [docs/design.md](docs/design.md).

License
-------

MIT license (© 2026 Yuji Hirose)
