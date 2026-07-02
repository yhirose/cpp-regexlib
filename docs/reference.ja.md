# regexlib — リファレンス

`regexlib.h` はヘッダオンリの正規表現エンジンで、外部依存はありません（必要な
Unicode テーブルは `tools/generate_ucd.py` が UCD から生成しヘッダに埋め込みます）。

この文書は、エンジンが受け付ける構文とマッチの挙動のリファレンスです。内部
（遅延 DFA・バイトパス・プレフィルタ・キャプチャエンジン・検証戦略）は
[design.md](design.md) を参照。

## マッチモデル

- **マッチの単位はコードポイントでなく Unicode 拡張書記素クラスタ**です。`.` は
  ユーザーが知覚する 1 文字をちょうど消費するので、`/.+/` を `"👨‍👩‍👧‍👦"` に当てると
  1 要素にマッチします。文字クラスや `\d`/`\w`/`\s` は、書記素をその**ベース（先頭）
  コードポイント**で判定します（その書記素が表す 1 文字として扱う）。たとえば
  `\w`/`\p{L}` は `é` を NFC（`U+00E9`）でも NFD（`e`+`◌́`）でもマッチし、`\s` は
  `\r\n` クラスタにマッチします。（`CodePoint` 単位ではコードポイント単位になり、
  このベース文字規則は適用されません。後述。）
- **マッチ位置は元の UTF-8 文字列のバイトオフセット**（Go 流のインデックス）で、
  常に書記素クラスタ境界に揃います。
- **マッチは leftmost-first**（Perl 流の選択・量化子の優先順）で、後述の
  *意味論と既知の差異* の例外があります。
- **マッチは線形時間**です。主エンジンは leftmost-first 遅延 DFA で、意味論上の
  フォールバックとして Thompson NFA の Pike VM を備えます。いずれもバックトラック
  しないため破滅的バックトラックが起きず、ReDoS に免疫です。したがって後方参照は
  非対応です。（エンジン内部は [design.md](design.md) を参照。）

## マッチ単位: 書記素クラスタ vs コードポイント

既定ではマッチ単位は拡張書記素クラスタ（上記）です。マッチ単位は**プロセス全体の
設定**で、パターンごとのフラグではありません:

```cpp
reg::set_default_match_unit(reg::MatchUnit::CodePoint); // または ::Grapheme（既定）
reg::MatchUnit u = reg::default_match_unit();
```

`CodePoint` は単位を **Unicode スカラ値（コードポイント）** ——RE2 や Rust `regex`
と同じモデル——に切り替えます。構文・leftmost-first 意味論・線形時間保証・バイト
オフセット報告（オフセットはコードポイント境界に揃う）はそのままです。

この設定は **`Regex` 構築時に一度読まれ、その Regex に焼き込まれます**。したがって
起動時（パターン構築やスレッド生成の前）に設定してください——マッチ実行時の切替では
ありません。`std::atomic` です（構築中の並行読み取りはデータ競合になりません）が、
意図する使い方は一度だけ設定。各単位でパターンを作るには構築の前後で既定を切り替えます。

```cpp
reg::set_default_match_unit(reg::MatchUnit::CodePoint);
reg::Regex re("\\w+");
re.search("héllo").str();  // "héllo"（ここでは é は 1 コードポイント）
```

既定の書記素単位との違い:

| | 書記素（既定） | CodePoint |
| --- | --- | --- |
| `"e"+◌́`（e + 結合アクセント）に対する `.` | クラスタ全体（3 バイト） | `"e"` だけ（1 バイト） |
| `"e"+◌́` に対する `\w`/`\p{L}` | クラスタ全体（ベース `e` は文字） | `"e"` だけ（結合文字で停止） |
| `\d \w \s [..] \p{…}` | クラスタをベースコードポイントで判定 | 1 コードポイントにマッチ |
| マッチ位置 | 書記素境界のバイトオフセット | コードポイント境界のバイトオフセット |
| 単独/不正な UTF-8 バイト | 1 つのフォールバック要素 | 1 コードポイント（そのバイト値） |

これ以外は同一です——リテラル・選択・量化子・グループ・アンカー・後読み/先読み・
名前付きグループ・下記フラグ（`IgnoreCase` を含む）・全メソッド API は同じ挙動で、
変わるのは `.`/クラスの単位とオフセット境界だけです。

**存在理由——非ASCII の崖が無い。** 書記素モードでは書記素分割が状態依存のため、
非ASCII バイトが 1 つでもあると文字列全体が遅延 DFA の高速パスから（より遅い）
書記素 Pike VM に落ちます。CodePoint 単位はパターンを **UTF-8 バイト
オートマトン**にコンパイルし、DFA が生の UTF-8 を分割なしで直接走査するので、
非ASCII テキストでも ASCII と同速（≈RE2）で崖がありません。キャプチャ/アンカー/
後読みは同じく崖の無いコードポイント・エンジン群（one-pass DFA・bounded
backtracker・code-point Pike）で処理します。[design.md](design.md)
を参照。

コードポイント意味論が欲しい、または非ASCII テキストで最大スループットが欲しい
場合は `CodePoint` を、`.` を「ユーザーが知覚する 1 文字」とみなしたい（絵文字・
ZWJ・結合列の正しさ）場合は既定の `Grapheme` を選んでください。

## 対応構文

| 種別 | 構文 |
| --- | --- |
| リテラル | 任意の文字。基底 + 結合文字は 1 つのリテラル書記素になる |
| 任意 | `.`（DotAll でない限り改行を除く。下記参照） |
| アンカー | `^`, `$`（Multiline では行基準） |
| 文字クラス | `[abc]`, `[a-z]`, `[^…]`。内部に `\p{…}` と `[:posix:]` 可 |
| 定義済みクラス | `\d \w \s` と `\D \W \S`（Unicode プロパティ準拠） |
| POSIX クラス | `[[:alpha:]]`, `[[:digit:]]`, … （ブラケット内・下記参照） |
| Unicode プロパティ | `\p{Name}`, `\P{Name}`, 1 文字形 `\pL` |
| 量化子 | `* + ?`, `{n}`, `{n,m}`, `{n,}`。lazy 形 `*? +? ?? {n,m}?` |
| 選択 | `\|` |
| グループ | `(…)` キャプチャ, `(?:…)` 非キャプチャ |
| 名前付きグループ | `(?<name>…)`, `(?'name'…)` |
| 単語境界 | `\b`, `\B` |
| エスケープ | `\n \r \t \f \v \0`, `\xHH`, `\x{…}`, `\uHHHH`, エスケープしたメタ文字 |
| 先読み | `(?=…)`, `(?!…)` — 可変長 |
| 後読み | `(?<=…)`, `(?<!…)` — 可変長 |
| フラグ（インライン） | `(?i)`, `(?m)`, `(?s)` |

`.` は改行書記素 `\n`, `\r`, `\v`, `\f`, NEL (U+0085), LS (U+2028), PS (U+2029)
を除きます。`DotAll` ではこれらにもマッチします。

対応する `\p{…}` 名: `L Lu Ll Lt Lm Lo N Nd Nl No P M S Z C` と `White_Space`、
および長い別名（`Letter`, `Number`, `Punctuation`, `Mark`, `Symbol`,
`Separator`, `Other`, `Uppercase_Letter` …）。

POSIX クラスはブラケット式の中だけに現れます（`[[:alpha:]]`、`[A-F[:digit:]]` の
ように併用も可）。`alpha alnum digit upper lower space punct word` は **Unicode 対応**
（`\p{L}`/`\d`/`\s`/… と同じ集合）、`blank xdigit cntrl graph print` は古典的な
ASCII 定義です。内側の否定 `[:^alpha:]` は非対応で、（黙ってリテラル集合になるのを
避けるため）**エラーを投げます**——ブラケット全体を `[^[:alpha:]]` で否定してください。

## API

コンストラクタは3つのオーバーロード ―― フラグ、マッチ単位の明示固定、その両方:

```cpp
reg::Regex re(pattern);                 // flags = 0, 単位 = グローバル既定
reg::Regex re(pattern, flags);          // フラグのみ
reg::Regex re(pattern, unit);           // マッチ単位を固定、flags = 0
reg::Regex re(pattern, flags, unit);    // 両方
```

フラグは OR 結合可能なマスクです。

| フラグ | 等価 | 効果 |
| --- | --- | --- |
| `reg::IgnoreCase` | `(?i)` | 大文字小文字を無視 |
| `reg::Multiline` | `(?m)` | `^`/`$` が改行でもマッチ |
| `reg::DotAll` | `(?s)` | `.` が改行にもマッチ |

コンストラクタフラグとインラインフラグは合成されます（どちらかが ON にする）。

### per-Regex でマッチ単位を固定する

`unit` は `reg::MatchUnit`（`Grapheme` または `CodePoint`）です。スコープ付き enum
なので `unsigned` フラグへ暗黙変換されず、単位のみのオーバーロードは**型だけで**
選択されます ―― フラグのプレースホルダ（`0`）は不要です:

```cpp
reg::Regex re(pat, reg::MatchUnit::CodePoint);                  // 単位のみ
reg::Regex re(pat, reg::IgnoreCase, reg::MatchUnit::CodePoint); // フラグ＋単位
```

単位の解決は: **渡した → その単位（この Regex に凍結）；省略 → 構築時に読む
プロセス全体の `reg::default_match_unit()`**。per-Regex で単位を固定するのは
`set_default_match_unit` に対する明示的・**スレッドセーフ**な代替で、別スレッドが
変えうる global state に依存しません。いずれにせよ単位は構築時に凍結され、その後
グローバルを変えても以後に構築する `Regex` にしか影響しません。

メソッド:

| メソッド | 戻り値 |
| --- | --- |
| `re.test(s)` | `bool` — どこかにマッチするか |
| `re.search(s)` | `MatchResult` — どこかの最左マッチ（所有） |
| `re.match(s)` | `MatchResult` — 先頭アンカーのマッチ（所有） |
| `re.find_iter(s)` | `Regex::MatchIter` — 全マッチを巡る遅延レンジ（下記） |
| `re.find_iter(s, cache)` | 上と同じだが `Regex::FindCache` を再利用 |
| `re.find_all(s)` | `Regex::MatchList` — eager columnar コンテナ（下記） |
| `re.split(s)` | `Regex::SplitIter` — マッチの間の断片を巡る遅延レンジ |
| `re.find_at(s, pos)` | `Regex::FindAt` — `pos` 以降のステートレスな1スキャンステップ（下記） |
| `re.replace_all(s, repl)` | `std::string` — 全マッチを置換（`$`-文法は下記） |
| `re.replace_first(s, repl)` | `std::string` — 最左マッチのみ置換 |

#### 唯一のマッチ型

（サブ）マッチは **`Match`** 一つ —— 全体マッチもキャプチャグループも同じ型で、
アクセサも一本化されています:

| 呼び方 | 戻り値 |
| --- | --- |
| `m.matched()` / `if (m)` | マッチしたか |
| `m.begin()` / `m.end()` | バイトオフセット |
| `m.str()` | マッチ文字列（`std::string_view`） |
| `m.group(i)` / `m.group("name")` | サブグループ（`Match`。グループ 0 = 全体マッチ） |
| `m.group_count()` | キャプチャグループ数 |
| `m.to_owned()` | 所有 `MatchResult` へコピー（view のみ） |

`group()` は再帰的に `Match` を返すので、`m.group(1).str()`・`m.group(1).begin()`・
`m.group("name").matched()` が同じ書き味になります。未マッチ／範囲外のグループは
`matched() == false`（`str() == ""`）。

`search()`/`match()` は自己完結の **`MatchResult`**（マッチ文字列をコピーするので
subject より長生きできる）を返し、この**同じ**メソッドサーフェスを公開します。
つまりマッチ処理ブロックは `search()`・`find_iter()`・`find_all()` のどれ由来でも
同じに書けます（違うのは所有権だけ）。**全マッチ**には役割の異なる2つの bulk API:

### `find_iter()` — 遅延・単一パス

`re.find_iter(s)` は `Regex::MatchIter` レンジを返します。エンジンは **`++` ごとに1
マッチずつ**進めるので、ループを途中で抜ければ残りの subject は走査しません ——
早期打ち切り・ストリーミング・レンジ合成のための道具です。各反復は `Match` の view
を yield します。これは subject を借用し**次の `++` まで有効**なので、残したいものは
コピー（または `to_owned()`）してください。一時 `std::string` の subject は拒否
されます（`find_iter(std::string&&)` は delete。view が dangle するため）。先に変数へ
束ねてください。

```cpp
for (auto m : re.find_iter(text)) {
  if (m.begin() > limit) break;          // 残りの text は走査されない
  use(m.str(), m.group(1).str());        // view、次の ++ まで有効
}
auto owned = (*re.find_iter(text).begin()).to_owned();  // ループ後も保持したい時
```

`Regex::FindCache` は遅延 DFA を呼び出し間で保持する再利用スクラッチです。素の
`find_iter(s)`/`find_all(s)` はそのスレッドの DFA を再利用しますが、`FindCache` を
多数の小さな文書で使い回すと per-call 構築を省けます（多文書トークナイズで約 6 倍）。
`FindCache` は単一スレッドで使い、渡した `Regex` より先に破棄します（PCRE2 の
`pcre2_match_data` や Hyperscan の scratch と同じ契約）。`Regex` 自体は従来どおり
スレッド間で共有可能です。

### `split()` — マッチの間の断片

`re.split(s)` は `Regex::SplitIter` レンジを返し、マッチの**間**の部分文字列を
`std::string_view` で yield します。`N` 個のマッチで `N+1` 個の断片（各マッチ前の
ギャップ＋末尾の残り）、まったくマッチしなければ 1 個（subject 全体）、空マッチは
両側に空断片を生みます。`find_iter` と同じく遅延・早期打ち切り可能で、rvalue 文字列
を拒否する規則も同じです。

```cpp
std::string csv = "a,bb,,ccc";
for (auto field : re_comma.split(csv)) use(field);   // "a", "bb", "", "ccc"
```

### `find_at()` — ステートレスな1スキャンステップ

```cpp
struct Regex::FindAt {
  MatchResult m;   // pos 以降にマッチが無ければ unmatched
  size_t next_pos; // 再開位置。走査終了時は text.size() + 1
};
FindAt Regex::find_at(std::string_view text, size_t pos) const;
FindAt Regex::find_at(std::string_view text, size_t pos, FindCache &cache) const;
```

`re.find_at(s, pos)` は、イテレータを保持せずに `find_iter()` を**ちょうど1
ステップ**実行します: バイトオフセット `pos` 以降の最左マッチと、走査の再開
位置を返します。**外部ステッパー**のための API です —— 呼び出し間に生きた
`MatchIter` ではなく単なる整数しか持てないジェネレータやコルーチンなど。
`find_at` を 0 からステップすると `find_iter` と完全に同じマッチ列を辿ります。

`next_pos` はこの `Regex` のマッチ単位に対するエンジンの空マッチ前進規則に
従います —— 非空マッチならその終端、空マッチなら **1書記素クラスタ**
（Grapheme mode）／**1コードポイント**（CodePoint mode）先 —— ので、走査は
必ず前進し、クラスタ内部で再開することはありません（例: CR-LF の `\r` 直前の
空マッチは `\n` の後で再開し、決して両者の間には落ちません）。マッチ単位は
呼び手側の境界計算では原理的に知り得ず、エンジンだけが知っています。

```cpp
size_t pos = 0;                        // 呼び出し間の状態はこれだけ
while (pos <= text.size()) {
  auto [m, next] = re.find_at(text, pos);
  if (!m.matched()) break;
  use(m);
  pos = next;                          // 常に > pos: 前進が保証される
}
```

事前条件: `pos` は `0` か、同じ text に対して以前返された `next_pos` である
こと（有効なスキャン位置 —— これが regional-indicator の偶奇など左文脈規則の
アンカーになります）。アンカーと語境界は subject 全体を見ます:
`find_at(s, pos)` は `pos` に**位置づけた**スキャンであり `s.substr(pos)` の
検索ではないので、`^` は非ゼロの `pos` ではマッチせず、`\b` は実際の左文脈を
見ます。各呼び出しは独立したスキャンステップです（`FindCache` が温存する分を
超える per-subject のエンジン状態は毎回再構築されます）。1つの呼び出し枠内で
の一括走査には引き続き `find_iter()`/`find_all()` が適しています。

### `find_all()` — eager columnar コンテナ

`re.find_all(s)` は `Regex::MatchList` を返します。全マッチを先に計算し、**バイト
オフセットの columnar（SoA）ブロック＋subject バッファ1個**として保持します。
単一パスの `find_iter()` と違い、ランダムアクセス（`ms[i]`）・`size()`・複数パスが
可能です。`str()`/`group()` はそのバッファへの view（マッチごとの確保なし）なので、
所有 vector より大幅省メモリかつオフセットのみのスキャン速度で、マッチ文字列も
キャプチャも取れます。結果集合全体をインデックスしたいなら `find_all()`、単一パス／
早期打ち切り／低ピークメモリが欲しいなら `find_iter()` を選びます。

アクセスは同じ `Match` サーフェス経由（range-for / `operator[]`）:

```cpp
reg::Regex re(R"((\w+)@(?<host>\w+))");
for (auto m : re.find_all("a@b c@d")) {
  m.str();             // "a@b"        (subject への view)
  m.begin(); m.end();                  // バイトオフセット
  m.group(1).str();    // "a"          (グループ 0 は全体マッチ)
  m.group("host").str();  // 名前指定。未マッチなら ""
  m.group(2).matched();   // bool
}
auto ms = re.find_all(text);
ms.size(); ms[0].str();                // ランダムアクセス
```

**所有権／寿命**は引数の型に追従し、よくある場面は安全かつゼロコピー:

| 呼び方 | モード | 寿命 |
| --- | --- | --- |
| `find_all(lvalue_string)` / `find_all(string_view)` / `find_all("リテラル")` | **借用**（ゼロコピー） | `MatchList` を subject より長生きさせない（string_view と同じ契約）。借用中に subject を変更/再確保しない。リテラルは静的なので安全 |
| `find_all(rvalue_string)` 例 `find_all(read_file())` | **ムーブ所有**（タダ） | 自己完結・一時オブジェクトでも安全 |
| `find_all_copy(string_view)` | **コピー所有** | 自己完結・subject を1回コピー |

値返しの一時オブジェクトは自動でムーブ所有に回る（dangle しない）。借用 lvalue
から自己完結が欲しければ `find_all_copy(s)` か `find_all(std::string(s))`。`FindCache`
版（`find_all(s, cache)`）で DFA を再利用できます（`find_iter(s, cache)` も同様）。所有
`std::vector<MatchResult>` が必要なら、どちらの view からでも `to_owned()` で集めます。

```cpp
reg::Regex re(R"(\w+)");
reg::Regex::FindCache cache;          // スレッドごとに1個
for (const auto &doc : docs)
  for (auto m : re.find_iter(doc, cache)) {   // 文書 2..N は DFA 再構築なし
    /* ... */
  }
```

### 置換の `$`-文法

`replace_all` / `replace_first` は `repl` 内で以下を展開します:

| トークン | 展開 |
| --- | --- |
| `$&` | 全体マッチ |
| `` $` `` / `$'` | マッチの前／後のテキスト |
| `$1`–`$99` | キャプチャグループ N（2桁を貪欲に） |
| `$<name>` | 名前付きキャプチャグループ |
| `$$` | リテラルの `$` |

認識できないエスケープや最終グループを超える参照は `$` をそのまま残します。
（std::regex 互換の `regex_replace` も同じ文法を展開しますが、そちらは `$<name>`
を解釈しません —— 下記参照。）

パースできないパターン（または資源上限を超えたパターン）は
`reg::RegexError` を投げます。`what()` メッセージには該当位置とキャレット行が
含まれます。加えて `RegexError::code()` が構造化された `RegexError::Code`（RE2 流：
`TrailingBackslash`, `BadEscape`, `BadCharClass`, `UnbalancedParen`, `BadGroup`,
`BadInlineFlags`, `BadUnicodeProperty`, `NestingTooDeep`, `NothingToRepeat`,
`ProgramTooLarge`, `PatternTooLong`, `StepBudgetExceeded`, `Internal`）を返し、
メッセージを解析せず分岐できます。

## std::regex 互換 API

ネイティブの `reg::Regex` API に加えて、`regexlib.h` は **同じ `reg` 名前空間**に
ドロップイン可能な `std::regex` 互換ファサードを同梱しています。`<regex>` の
インターフェースを模しているので、既存の `std::regex` コードは名前空間を
エイリアスし（`namespace re = reg;`）、`std::` を `re::` に書き換えるだけで移行
できます。

```cpp
namespace re = reg;                       // 旧: namespace re = std;

re::regex pat(R"((\w+)=(\w+))");          // basic_regex
re::smatch m;
if (re::regex_search(line, m, pat))
  use(m[1].str(), m[2].str());            // sub_match::str()

std::string out = re::regex_replace(line, pat, "$2=$1");   // $ フォーマット
for (re::sregex_iterator it(line.begin(), line.end(), pat), end; it != end; ++it)
  use((*it)[1].str());
```

ネイティブエンジンは PascalCase（`Regex`, `MatchResult`, `Match`）、互換層は
`std` 流の snake_case（`regex`, `smatch`, `regex_search`）を使うので、両者は
`reg` の中で衝突せず共存します。対象は `char` / `std::string` のみ（`wchar_t`
非対応）。

### 提供される名前

| 種別 | 名前 |
| --- | --- |
| パターン | `basic_regex`, `regex` |
| マッチ結果 | `sub_match`, `match_results`; `ssub_match`/`csub_match`, `smatch`/`cmatch`/`svmatch` |
| アルゴリズム | `regex_search`, `regex_match`, `regex_replace` |
| 反復 | `regex_iterator`（`sregex_iterator`/`cregex_iterator`）、`regex_token_iterator`（`sregex_token_iterator`/`cregex_token_iterator`） |
| 定数 | `regex_constants::syntax_option_type`, `match_flag_type`, `error_type` |
| 例外 | `regex_error`（`RegexError` を継承し `code()` を追加） |

`regex_search` / `regex_match` / `regex_replace` は `std::string`・`const
char*`・`std::string_view`・イテレータ対を受け取り、標準と同じオーバーロード群を
備えます（右辺値 `std::string` + `smatch` のオーバーロードは dangling 回避のため
`delete`、これも `std::regex` と同じ）。`match_results::format` と `regex_replace`
は ECMAScript の `$` 文法（`$&`, `` $` ``, `$'`, `$1`–`$99`, `$$`）を展開します。
`regex_token_iterator` は submatch 添字 `-1` に対応するので、標準の分割イディオム
（`sregex_token_iterator(b, e, re, -1)`）が使えます。

### フラグ

`syntax_option_type` と `match_flag_type` はソース互換のため受理されます。
regexlib に対応のあるものは反映、それ以外は無視されます（既存の呼び出し箇所が
そのままコンパイルできるように）。

| 反映される | 無視される（受理のみ・無効果） |
| --- | --- |
| `icase` → `IgnoreCase`、`multiline` → `Multiline` | `nosubs`, `optimize`, `collate`, 文法セレクタ各種 |
| `match_continuous`（先頭にアンカー）、`format_no_copy`、`format_first_only` | `match_not_bol/eol/bow/eow`, `match_any`, `match_not_null`, `match_prev_avail`, `format_sed` |

`reg::regex` はプロセス全体の `reg::default_match_unit`（既定は `Grapheme`）に
従うので、既定ではネイティブ API と同じく書記素対応です。std::regex は
`std::string` をバイト指向で扱い UTF-8 では元々壊れているため、これで失う実質的な
互換性はありません（ASCII は同一）。std::regex に最も近い挙動が欲しい場合は起動時に
`reg::set_default_match_unit(reg::MatchUnit::CodePoint)` を呼んでください。

### `std::regex` との意図的な差異

移行前に読んでください。失敗の仕方はそれぞれ異なります。

- **`.` はバイトでなくコードポイント単位**。`std::string` に対して `std::regex`
  の `.` は 1 *バイト*にマッチします（マルチバイト UTF-8 文字を分断する）。本
  ファサードの `.` は 1 *コードポイント*にマッチします。ASCII では同一、UTF-8 では
  本ファサードの方が*より正しく*、`std::regex` とバイト単位で同一ではありません。
- **線形時間・ReDoS 耐性 — バックトラック専用構文は拒否**。atomic group `(?>…)`
  と所有量化子（`a++`, `a*+`）は構築時に `regex_error` を投げます。`(a+)+$` のような
  病的パターンも爆発せず線形時間で走ります。
- **後方参照は暗黙にリテラル化**。`\1` は後方参照ではなくエスケープされた数字 `1`
  として解釈されます（例外は**投げません**）。よって `(\w)\1` は `"aa"` でなく
  `"a1"` にマッチします。（一方で POSIX クラス `[[:alpha:]]` などは——ECMAScript の
  `std::regex` と違い——**対応しています**。Supported syntax 参照。）

`reg::regex_error` は `reg::RegexError` を継承するので、移行コードの
`catch (re::regex_error&)`・`catch (reg::RegexError&)`・`catch (std::runtime_error&)`
はいずれもそのまま動きます。`code()` はエンジンの構造化 `RegexError::Code` から
変換した標準の `regex_constants::error_type` を返します。

## 意味論と既知の差異

- **書記素単位**は、コードポイント単位の PCRE / RE2 / Python `re` と異なります。
  複数コードポイントのクラスタ（絵文字、ZWJ 列、基底 + 結合文字）は 1 要素で、`.`
  はそれを丸ごと消費し、文字クラスはクラスタのベース（先頭）コードポイントで判定
  します。`\w`/`\p{L}` は `é` を NFC/NFD いずれでもマッチ、`\s` は `\r\n` クラスタに
  マッチ、`[a-z]` は `e`+◌́（ベース `e`）にマッチします。よって肯定クラスも複数
  コードポイントのクラスタにマッチしえ（コードポイント系エンジンと異なる）、否定
  述語（`\D`, `[^…]`, `\S`）はベースが集合に含まれるクラスタにはマッチしません。
- **CR-LF は、あらゆる subject で 1 クラスタ**。`\r\n` は単一の書記素クラスタ
  （UAX #29 GB3）なので、`.` にとっても、回数指定反復（`[^"']{0,30}`、`.{0,4}`）に
  とっても 1 要素として数え、multiline `^`/`$` にとっては 1 つの改行として扱われます
  （`\r` と `\n` の間では発火しません）——subject が純 ASCII かどうかに関わらず一様に
  です。（孤立した `\r` や `\n` はそれ自身で 1 クラスタ。）これは `\r\n` を 2 文字として
  扱うコードポイント系エンジン（PCRE / RE2 / Python `re`）と異なります。その
  コードポイント挙動が欲しい場合は `CodePoint` マッチ単位を設定してください。
- **nullable 量化子のコーナー**。空文字列にマッチしうる body を持つ無限量化子は、
  空反復のあとで停止します（Perl の規則）。よって `(.*?)*` は空文字列にマッチ
  します。1 つの下位ケースだけ Perl と異なります: 先頭枝が nullable な選択を
  無限量化子に入れた形は、Perl の leftmost-first でなく POSIX の leftmost-longest
  の結果になります — `(a*|b)*` を `"ab"` に当てると `"ab"`（POSIX）で、Perl では
  `"a"` です。ここで Perl を再現するにはバックトラックが必要で、線形時間保証と
  両立しません。RE2 も同じクラスの差異を文書化しています。
- **後読み・先読み内のキャプチャは外部に公開しません**。`(?=…)` / `(?<=…)` の中の
  グループは非キャプチャ扱いです。
- **インラインフラグは全体に適用されます**。`(?i)`, `(?m)`, `(?s)` は位置に
  関係なくパターン全体にフラグを設定します。スコープ付きフラグ `(?i:…)` は
  スコープになりません。
- **文字列末尾の `\b` はマッチします**（Perl・Python と同じ）。

## 資源上限

小さな悪意あるパターンがメモリやスタックを枯渇させないよう、いずれかを超える
パターンは構築時に `RegexError` を投げます。

| 上限 | 値 |
| --- | --- |
| パターン長 | 32 KiB |
| コンパイル後のプログラムサイズ | 262144 命令 |
| ネスト深さ | 200 |

これらはコンパイルコスト（例 `a{1000000}`、入れ子 `(x{50}){50}…`）とパーサの
再帰（例 `((((…))))`）を抑えます。ネスト上限は控えめに設定してあり、再帰下降パーサが
最小の共通スレッドスタック（Windows のメインスレッド 1 MiB スタック）に収まるようにして
います。手書きのパターンはこれを大きく下回ります。

マッチ時間は対象の長さに対し線形ですが、定数がプログラムサイズなので、密な
パターン（例 `(a?){9000}`）を長い対象に当てると有界だが遅くなります。対象長に
比例した match-time step budget がこれを抑え、超過したマッチはマッチ呼び出し
（`search`, `match`, `scan`, `matches`, `test`, `replace_all`）から `RegexError` を投げます
（数秒走り続ける代わりに）。実際のパターンは budget を大きく下回ります。ε
クロージャは反復実装なので、長いゼロ幅チェーンでもスタックを溢れさせません。

## 非対応

| 機能 | 理由 / 代替 |
| --- | --- |
| 後方参照 `\1` | NP 困難。線形時間保証と両立しない |
| 条件分岐、atomic group、所有量化子 | 未実装 |
