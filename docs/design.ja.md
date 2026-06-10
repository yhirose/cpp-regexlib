# regexlib — 内部設計

`regexlib.h` の内部の仕組み。ユーザー向けリファレンス（構文・意味論・公開 API）は
[`reference.md`](reference.md)、本書はエンジン本体を扱います。

実装は**1つの実証済みベースライン**の上に重ねたアクセラレータ群です。**書記素
Pike VM**（subject を Unicode 拡張書記素クラスタに分割する Thompson NFA 仮想機械）
は正しいが遅い。より速い経路——leftmost-first 遅延 DFA、非ASCII 用 UTF-8 バイト
パス、bounded キャプチャエンジン、SIMD プレフィルタ、view ベース結果コンテナ——は
すべて、そのベースラインと**まったく同じ**結果を出さねばなりません。設計全体は、
証明可能に安全な場面では Pike よりはるかに速い経路で走らせつつ、この等価性を保つ、
という方針で組まれています。

譲れない2つの契約がすべてを形作ります:

- **線形時間 / ReDoS 免疫。** どのエンジンも無制限にバックトラックしない。非アンカー
  検索は単一前進パスで、候補ごとに再シードしない。
- **leftmost-first（Perl）意味論**を、全経路・全パターンで。

---

## 全体像（ひと目で）

パターンは一度だけバイトコードにコンパイルされ、各マッチ要求は、そのパターンと
subject に対してベースラインと等価だと証明できる範囲で最も安い経路に振り分けられます。
（図中ラベルは整列維持のため英語のまま）

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

**実際にどのエンジンが動くか**は、パターンの形と subject の内容の両方で決まります:

| パターン | subject | 動くエンジン |
| --- | --- | --- |
| キャプチャ無し・DFA 可能 | ASCII（UnicodeScalar なら*任意*の subject） | 遅延 **DFA** — 高速パス（§2） |
| キャプチャ無し・DFA 可能 | 非 ASCII だが全クラスタが単一コードポイント | **EGC バイトパス** DFA（§4） |
| キャプチャ無し・DFA 可能 | 非 ASCII で実際に複数コードポイントのクラスタを含む | 書記素 **Pike**（§4） |
| キャプチャあり・DFA 可能 | （任意） | DFA が span を特定 → **キャプチャエンジン**（§6） |
| 後読み/先読み・入れ子の空ループ・DFA 状態上限超過 | （任意） | 書記素 **Pike** — フォールバック（§2） |

書記素 Pike VM（§1）が唯一の実証済みベースラインで、他の行はすべて、Pike と
*まったく同じ*結果を返さねばならないアクセラレータです。§9 がその等価性の担保です。

### 決定の置き場所：`Plan` と呼び出しごとの状態

*パターンごと*に一度だけ決まるもの — コンパイル済みプログラム、tier 適格フラグ
（`dfa_ok_`、`byte_path_` など）、prefilter 状態（§7）— は、不変 struct
`Regex::Plan` に集約されています。Plan のコンストラクタが名前付きステージ
（`compile_core`、`analyze_core`、`plan_egc_byte_path`、`plan_assert_tiers` など）
で構築し、マッチ時のコードは `plan_.…` として読むだけです（マッチ系エントリ
ポイントはすべて `const`）。補助プログラムは `Plan::Compiled`（プログラムと
その `Match` pc の束。`ok()` が「このプログラムは構築済みか」に答える）として
保持します。呼び出しごとに変化する状態はすべて別の場所 — スレッドごとの
`FindCache`（§8）が持つ遅延 DFA キャッシュとスクラッチバッファ — にあります。

---

## 1. マッチモデル：書記素クラスタ

決定的な選択：**マッチの単位は Unicode 拡張書記素クラスタ（EGC）**（UAX #29）で
あり、コードポイントではありません。`.` はユーザーが知覚する 1 文字をちょうど消費
するので、`/.+/` を `"👨‍👩‍👧‍👦"` に当てると 1 要素にマッチします。マッチ位置は元の
UTF-8 subject への**バイトオフセット**で、常にクラスタ境界に揃います。

書記素分割は**状態依存**です——2つのコードポイント間に境界があるかは、その
`Grapheme_Cluster_Break` プロパティと周囲の並びに依存します。これがエンジンの独自性
と唯一の性能崖（§4）の両方の源です：バイトオートマトンはクラスタでなくバイトしか
見えません。

### セグメント化（`Segmented`）

```cpp
struct Segmented {
  std::vector<std::u32string> graphemes;  // 各クラスタのコードポイント
  std::vector<size_t> byte_begin;         // size == graphemes.size() + 1（末尾=終端）
  std::string_view source;                // 元の UTF-8 subject
  bool ascii = false;  // 全バイト < 0x80 → 書記素 index == バイト index
};
```

`segment()` には **ASCII 高速パス**（全バイト `< 0x80` → 各バイトが自身のクラスタ、
`byte_begin[i] == i`、デコード/分割なし）と**一般パス**（コードポイントへデコードし
各バイトオフセットを保持、`unicode::grapheme_length` でクラスタにまとめる）があり
ます。`segment_cp()` は UnicodeScalar 用：1 コードポイント1エントリ——素の UTF-8
デコードで**書記素分割ではない**。Pike VM はどちらの `Segmented` でも変更なく走り
ます。

### クラス所属はベースコードポイントで判定

クラス / `\d\w\s\p{…}` はクラスタを**ベース（先頭）コードポイント**で分類します
——クラスタは表示上の 1 文字として振る舞います:

```cpp
bool matches(const std::u32string &g, bool icase) const {
  return g.empty() ? negate : matches_cp(g[0], icase);
}
```

よって `\w`/`\p{L}` は `é` を NFC（`U+00E9`）でも NFD（`e` + `◌́`）でもマッチし、
`\s` は CR-LF クラスタにマッチします。単一コードポイントのクラスタは自身がベース
なので、そこでは `matches_cp` と同一です——これが、`matches_cp` を直接呼ぶ
バイト/コードポイントエンジンが単一コードポイント入力で書記素エンジンと一致する
理由です。（このベースコードポイント規則は意図的な意味論選択で、旧「クラスは単一
コードポイントのクラスタのみにマッチ」規則は誤りでした。）

### パターン中のリテラルも書記素分割される

パターン中のリテラルはクラスタにコードポイントの**完全一致**（`lit_match`）でのみ
マッチし、ベースコードポイントでは判定しません——つまり厳密リテラルはクラスより
厳しい。これが予測どおりに振る舞うには、パターンのリテラルテキストも subject と
まったく同じようにクラスタへ分割される必要があります。タイプされたリテラルは既に
そうなっています（トークナイザがパーサにクラスタ単位で渡す）が、**エスケープ——
`\r`・`\n`・`\uXXXX`——はそれぞれ単一コードポイントのリテラルとして解析される**ため、
`\r\n` のようなエスケープ列は2つのリテラルのままとなり、subject が提示する分割不可能な
CR-LF クラスタ（UAX #29 GB3）に決してマッチできません。そこで `parse_concat` は
融合パス（`fuse_literal_graphemes`）を走らせ、隣接する未量化リテラルの最大連続を
書記素境界で再分割します。これにより `\r\n` は単一の `U"\r\n"` クラスタリテラルに
コンパイルされ——タイプされた等価テキストが生成するノードと同一になります。
（`\r\n?` の `\n?` のように量化されたエスケープは独立した atom で、融合されません。）
CodePoint モードではこのパスは no-op です——複数コードポイントのリテラルは、分離した
リテラルと同じコードポイント単位のマッチ列を発行します。

---

## 2. leftmost-first 遅延 DFA

**一言で：** 全スレッド同時実行の Pike VM の代わりに、決定性の状態機械（DFA）を
subject 走査に合わせて遅延構築する。ただしスレッドの*優先度*を保持するので、最長
ではなく Perl の leftmost-first マッチを返す。

Pike VM のホットコストは `add_thread` の ε-閉包（入力を消費せず到達できる状態集合）
＋キャプチャの copy-on-write で、Pike VM に構造的なもの——密マッチで RE2 に 1〜2 桁
劣ります。対策：**leftmost-first マッチを直接生む DFA**（RE2 / Rust `regex-automata`
の設計）。

これは**優先度順・match-cut** の遅延 DFA です。DFA 状態は NFA プログラムカウンタの
**順序付き**（優先度）ベクタで、**ソートせず** intern します（順序が状態同一性の
一部）。ε-閉包は Pike の `add_thread`（DFS 先行順、`Split.x` を `Split.y` より先）
を写しますが、キャプチャは持たず、**最初の `Match` で cut** します：到達した
`Match` より低優先のプログラムカウンタは捨てる（生きたマッチが後続の選択肢を殺す）。
あとは素朴な「最後の accept を記録」前進スキャンで leftmost-first 終端が出ます：
貪欲 `a+` は高優先の継続スレッド（最長 run）を保ち、lazy `a+?` や `a|ab` は cut で
止まります。

**longest-safe 述語はありません。** 旧 DFA は leftmost-*longest*（POSIX）なのに契約
は leftmost-*first*（Perl）だったため、静的述語が DFA で扱えるパターンを制限して
いました——不完全（DFA 可能な選択を弾く）かつ不健全（一部の可変オプショナル前置を
誤分類）。順序付き+cut DFA はスレッド優先度を表現するので、述語なしで任意パターンに
対し leftmost-first です。

**非アンカー性はプログラム内に**あり、位置ごとの再シード（開始位置間で優先度が
壊れる）ではありません：前進プログラムは `lf_prog_ = (?s:.)*? + pattern`、最低優先の
lazy 前置1つで、いずれかのパターンマッチが生きると match cut が除去します。バイト
オートマトン（US モード、バイト各 tier）では前置は**任意 BYTE**——任意コード
ポイントでは UTF-8 継続バイト単独を飛ばせないため。

### 開始位置の復元（逆 DFA）

DFA 状態は占有するプログラムカウンタの*集合*で、「どこで始まったか」を持ちません
（持たせると状態数が入力長に比例して増え DFA でなくなる）。だから前進スキャンは
マッチの*終端*は言えても開始は言えません。開始は、`e` から逆方向プログラムを左へ
走らせ最小の accept する `s` を記録する**逆バイト DFA** で復元します。逆 DFA は
**順序なし**（ソート）：「`[s, e)` はマッチか？」はブール到達性問題です。逆 *Pike*
は書記素 `Segmented` が必要で tier-1 の「分割なし」の利点を潰すため、バイト DFA に
します。

### tier ディスパッチ

パターンから構造的に選ぶ 3 つの tier:

| tier | 条件 | 動作 |
| --- | --- | --- |
| **1** | キャプチャなし ∧ DFA 可能 | 前進順序付き+cut DFA が leftmost-first 終端 `e` を、逆スキャンが開始 `s` を見つけ `[s, e)` を返す。**Pike なし。** ASCII 書記素 tier・UTF-8 バイト tier（§4/§5）・assert 対応 DFA 経由の `^ $ \b \A \z` を担当。対象：`\w+`、`[a-z]+`、リテラル、一般選択（`a\|ab`、`(?m)^…\|…$`）。 |
| **2** | キャプチャ ∧ DFA 可能 | lf DFA が `[s, e)` を特定し、キャプチャエンジンが群を `e` で**境界付けて**解決（§6）。whole-match キャプチャ（全群=全体マッチ、例 `(\w+)`）はエンジンを完全にスキップ。 |
| **2a** | キャプチャ ∧ assert-DFA 可能（`^ $ \b \A \z` + 群、例 `(\w+)$`、`\.([a-z]+)$`） | **assert 対応** DFA が `[s, e)` を特定（capture を剥がした版）、bounded バックトラッカ（`bitstate_bytes`、assert op を `empty_flags_cp` で評価）が群を解決 ―― これらを支配していた Pike を置換（`(\w+)$`: 5300→700 ns）。特定は書記素 assert DFA（ASCII subject）または**バイト** assert DFA（`ByteAssertDfa`：非ASCII EGC subject、または**US モードの任意 subject**――下記）で行う。 |
| **3** | DFA 不可（後読み/入れ子空ループ）または状態上限超過 | subject 全体の Pike VM ＋ §7 プレフィルタ。フォールバック。 |

`dfa_ok_` =「regular」プログラム（後読みなし、`Op::Loop` なし）；`dfa_assert_ok_`
は加えて空幅アサーションを許可し assert DFA が処理。どちらも純粋に構造的。Tier 2a
は Tier 1 の assert-DFA 経路のキャプチャ版：assert を含むキャプチャパターン
（`dfa_ok_` でない）も Pike でなく DFA 特定の span を得る ―― バックトラッカが
アサーションを絶対位置で評価する（`$` = span 端でなく真の終端）ようになったため。

**バイト assert tier は EGC 非ASCII と US モードで共有。** `ByteAssertDfa` は
UTF-8 バイトプログラムを1コードポイントずつデコードし assert をコードポイント単位で
評価する ―― これは EGC 非ASCII subject（バイト == 書記素）と US マッチング
（コードポイント、書記素なし）の両方が必要とするもの。よって US は assert エンジンの
コピーを得ない：US の `^ $ \b` パターン（capture 有無問わず）は**任意**の subject で
`assert_byte_find_span` / `assert_prefix_find` / `ByteAssertDfa` を再利用し、同じ
prefilter・同じ `cp_prog_` bitstate capture 解決を使う。モード依存は
`assert_byte_path_ok` のゲートのみ（US: 任意 subject；EGC: 非ASCII かつ複数CP
クラスタ無し）。EGC-ASCII の書記素 assert DFA は別の高速路として残る。US で span が
bitstate を溢れる場合はコードポイント Pike へフォールバック。

### tier の正式名（ソース中の `[Tier: …]` ラベル）

上の番号付き tier は「どのエンジンが走るか」を表す。各公開エントリポイント
（`test` / `search` / `match` / `fill_matches` / `find_iter`）はそれぞれ独自の
ディスパッチ階段を持つ。階段は本質的に異なる（アンカー・capture 解決・
ストリーミング状態）ため統一せず、代わりにソースの各分岐へ `[Tier: …]`
ラベルを付け、（パターン分類 × subject 分類）の組ごとに正式名を1つ定める：

| ラベル | ゲート | 動作 |
| --- | --- | --- |
| `Literal` | `literal_only_` | memmem（+ 書記素境界チェック）；subject 分類なし |
| `LiteralAlt` | `literal_alt_` 非空 | Teddy / 先頭バイト複数リテラルスキャン、順序付き verify |
| `AssertAnchor` | `assert_.anchor_gatefree` | memmem + ヒットごとの境界 & アンカーフラグ verify；任意 subject |
| `AnchoredOnePass` | `aop_.ok`（`^body$` / `^body` の検証形：assert なし・貪欲のみの body） | 位置 0 からの**1 回**のコンパクト決定的歩行（`anchored_onepass_try`、search / match / test で共有）——u16 行、accept バイトは依存チェーン外。末尾 `$` は「accept==n」比較（uncut テーブル）。素の `^body` は leftmost-first cut テーブルを使い、最終 accept が leftmost-first 終端そのもの。**任意 subject で健全**：歩行は非 ASCII バイトで、また CR-LF クラスタを分割し得るパターンでは `\r` でも bail する（`onepass_walk_bails_cr`） |
| WordOnePass | `wop_.ok`（`\b body \b`、capture なし、先頭/末尾 atom が語のみ。末尾 `\b` 付きはさらに全 accepting 状態の出バイトが語バイトであること） | 候補ごとのコンパクト歩行：候補=非単語が先行する開始可能バイト。末尾 `\b` は最終 accept での次バイト 1 判定（accepting 状態 admission により厳密：通過した accept の直後は必ず語バイト） |
| `Dfa/US` | `us_ ∧ dfa_ok_` | `byte_prog_` 上のバイト lazy DFA（suffix/inner prefilter）；`+cap`: 有界 cp エンジンでグループ解決 |
| `Dfa/EgcByte` | EGC ∧ `egc_byte_path(text)` | バイト lazy DFA（icase-prefix / suffix / inner prefilter、融合 EGC リテラルスキャン）；`+cap` 同上 |
| `Dfa/Ascii` | EGC ∧ `dfa_ok_` ∧ ASCII subject | 書記素プログラム上の lazy DFA（バイト == 書記素）；`+cap` 同上 |
| `Assert/Ascii` | `dfa_assert_ok_` ∧ ASCII subject | `AssertDfa`（開始復元はキャッシュ済 `AssertRevDfa`）+ assert literal/prefix/suffix/word prefilter；`+cap`: assert 対応 bitstate |
| `Assert/Byte` | `assert_byte_path_ok(text)`（US: 任意 subject；EGC: 非ASCII simple） | `ByteAssertDfa` / `ByteAssertRevDfa`、同じ prefilter |
| `Pike` / `Pike/cp` | 常時（フォールバック） | `prog_` 上の書記素 Pike VM；US: `cp_prog_` 上のコードポイント Pike |

どの階段も適格な tier を上から試し、DFA state cap で次へフォールスルーする。
`Pike` は全 tier が一致すべき証明済みベースライン（§9）。1つの tier が全
エントリポイントでどう振る舞うかは、ラベルを grep すれば追える。

### 線形性（O(n²) の罠）

非アンカー検索は候補ごとに再開してはなりません（候補ごとアンカー再試行は O(n²) で
長い subject で数百秒ハングしうる）。よって：前進 DFA スキャンは**単一パス**で中断
位置から再開；逆スキャンは**直前マッチ終端より左へ行かないようクランプ**（逆作業の
総和はマッチ長の総和で抑えられる）；マッチ後は確定した Perl 終端から前進再開。正味：
前進は各バイト1回、逆はマッチ長の総和、tier-2 キャプチャパスはマッチ窓内のみ。
線形。

候補+検証型の**プレフィルタ**（§7）は公認の例外で、リテラル候補ごとに検証をやり直し
ます——パターンの反復が自分の候補バイトを吸収できると二次的になります（`a[a-z]+0` ×
`aaaa…`：全 `a` が候補で、失敗検証のたびに重なる尾を再歩行）。よって該当サイトは
すべて**失敗歩行バイト予算**（`WalkBudget` 型；尽きると `kWalkBail`）を持ちます：
成功した検証はカーソルを
終端まで進めるので重ならず、控除されるのは**失敗**歩行のみ。予算（≈subject 1 本分）
が尽きたらその呼び出し/イテレータでは当該プレフィルタを恒久的に放棄し、上記の
単一パス機構へフォールバック——最悪でも subject 1 本分の無駄歩行が一度きり＝合計
O(n)。ガード済みサイト：融合 EGC 前置スキャン、ReverseInner 非吸収検証、(?i) 前置
プローブ検証、assert リテラル前置/接尾 finder、unbounded one-pass 候補ドライバ、
suffix tier の候補ループ（scalar 検証の absorb ベイルが候補毎 O(n) の DFA 逆走査に
再入する）、そして chain-capture 歩行（アンカー右の要素がアンカーバイトを吸収し得る
ため失敗歩行が重なり得る）。
fill/イテレータのループは全呼び出しで**1 つの予算**を共有します（呼び出し毎の予算は
マッチのたびにリセットされ O(マッチ数 × n) を許してしまう）。それ以外のプレフィルタに
予算は不要：検証が O(1)/パターン長で頭打ち（literal、Teddy、アンカーフラグ）か、
admission の形状ゲートが構造的に抑える（var-pre 接尾の 1 atom 規則、語
スキャンの語ごと候補 1 つ）ためです。

### セーフティネット：DFA 状態上限

intern する状態は上限付き。超過時は DFA を諦め Pike VM（無影響）へ。病的な
`dfa_ok_` パターン（`.*a.{18}` は 2¹⁸ 状態）のメモリ枯渇を防ぎます。

---

## 3. コンパイラとバイトコード

コンパイラは AST を NFA `Program` に下げます。形を決めた2つの圧力——**コンパイル
時間**と**プログラムメモリ**——はどちらも Unicode クラス（`\w`、`\p{L}`、数百の
UTF-8 バイト範囲列に展開）が支配します。

### 命令（`Inst`）——16 バイト・自由に再配置可能

```
Char  Class  Any  Byte        // 消費
Split Jmp  Save  Loop         // 制御フロー（Loop = 空ガード後退辺）
Look                          // 零幅後読み（subs[x]）
AssertBOL AssertEOL AssertWB AssertNWB AssertBeginText AssertEndText AssertEndTextNL
Match
```

`Inst` は**16 バイトかつ trivially copyable** です。重いオペランド——リテラル文字列
（`std::u32string`）、文字クラス（`CharClass`）、後読み本体（`Program`）——は命令に
**入れず**、所有する `Program` の out-of-line プールに置きます:

```cpp
struct Program {
  std::vector<Inst> insts;
  std::vector<std::u32string> lits;            // Char リテラル
  std::vector<CharClass> classes;              // Class オペランド
  std::vector<std::shared_ptr<Program>> subs;  // 後読み本体
  int nslots = 2;                              // 群あたり2、群0=全体マッチ
};
```

命令は小さな index のみを持ち、どのオペランド index も制御フロー先と共存しないため、
すべて **`x` スロットに重ねます**（op が意味を選ぶ）：`lit_idx()`/`cls_idx()`/
`sub_idx()` は `x` を読み、`Byte` は `[lo,hi]` 境界を `x` にパック。`op` を `uint8_t`
にし所有メンバを持たないので、構造体は 16 バイトの POD です。これが、大きな Unicode
クラスのバイトオートマトン構築を、命令ごとの構築/移動/破棄なしの **`memcpy`** に
する鍵です。定常スループットは `Inst` サイズに鈍感（バイト DFA は遷移表で走り、
ホットループで `Inst` を読まない）なので、効くのは必要だった所——コンパイル時間と
メモリです（`\w+` バイトプログラム：160→32→16 バイト縮小で 359 → 159 KiB）。

### UTF-8 範囲コンパイル

US モードとバイトパスでは、クラス / `.` / `\d\w\s\p{…}` は**バイト副オートマトン**
です。コードポイント範囲 `[lo, hi]` は UTF-8 バイト範囲*列*の集合へコンパイル
（Russ Cox の `utf8_ranges`：UTF-8 長境界で分割、次に先頭バイトが変わる所で分割）。
あるコードポイントが `[lo, hi]` に入るのは、その UTF-8 バイト列がちょうど1つの列に
一致するとき——よってバイト DFA は Unicode クラスを**デコードなし**でバイトを進める
だけでマッチします。`build_class_block` は1集合を `Byte` 連鎖の選択として出力し、
**`Split`/`Jmp` のみが先を持つ**（`Op::Byte` は fall-through で進む）ので、base 0 で
組んだブロックは `Split`/`Jmp` 先を再ベースするだけで*任意*オフセットに追加可能——
16 バイト `Inst` が買う再配置可能性です。

### クラスコンパイルのキャッシュ

Unicode クラスは現れるたび同じ数百範囲に展開され、1つの `Regex` が各クラスを複数回
出力します（前進+逆プログラム、出現ごと）。*ソース*クラスをキーにする `static`・
mutex 保護の3層メモ（ルックアップは展開でなく述語に比例）:

1. **`enum_cp_ranges`** — `\p{…}`/述語 → コードポイント範囲。`0..0x10FFFF` を一度
   走査（サロゲート除外）、述語でキャッシュ。
2. **`utf8_ranges_cached`** — コードポイント集合 → UTF-8 バイト範囲列。正規化集合で
   メモ化、方向独立。
3. **`class_block_cached`** — 出力済み `Inst` ブロック全体を `(集合, 方向)` でメモ化。
   以降の出力は `memcpy` 追加＋先の再ベース。

合わせて Unicode クラスのコンパイルを支配的コストからブロック `memcpy` に
（コンパイルベンチで ~12〜14×、`\w+` 0.44 → 0.037 ms）。

### 2プログラム分割

Unicode モードのパターンは1つの AST から最大2プログラムを出力:

- **バイトプログラム**（`Op::Byte` 副オートマトン）バイト DFA 用——大きい（クラスが
  UTF-8 副オートマトン）が文字ごとに再走査しない；
- **コードポイントプログラム**（`cp_prog_`、`Op::Char`/`Class`/`Any`）Pike 系
  エンジン用。Unicode クラスは*単一*の `Op::Class`（1 コードポイントをデコードして
  判定）——小さく、backtracker / one-pass キャプチャエンジンがバイトオートマトンの
  サイズを払わない。

オペランドプール分割により両者がまったく同じ `Inst`/`Program` 型を共有します。

---

## 4. 非ASCII の崖と EGC バイトパス

どの DFA tier もバイト/コードポイントオートマトンなので、歴史的に `is_ascii()` ゲートが
*あらゆる*非ASCII subject を全 DFA tier から書記素 Pike へ落としていました——~6× の崖
（密 `\w+`：`é` 1つで 58 → 9 MB/s）。実世界の散文では引き金はより微妙で、**CRLF 改行**
——各 `\r\n` が1クラスタ（UAX #29 GB3）——が subject 全体を書記素 Pike（~24 MB/s）へ
押しやっていました。

**鍵となる観察：subject 内の全クラスタが単一コードポイントのとき、書記素単位と
コードポイント単位のマッチは一致する**——よって UTF-8 バイト DFA は分割なしで書記素
エンジンとまったく同じ結果を出します。regular（`dfa_ok_`）パターンでは、書記素
プログラムと並べてバイトプログラム（`byte_prog_`、`byte_rev_prog_`、`byte_lf_prog_`）
をコンパイルし `byte_path_` を立てます。順序付き+cut バイト DFA は任意 `dfa_ok_`
パターンに対し leftmost-first——longest-safe 述語なし、ASCII と同様。

### `simple_from` — subject ごとのゲート

`egc_byte_path(text)` が subject ごとに判定。最初の非ASCII バイトまで（ベクトル化）
スキャンし、純 ASCII subject は安い ASCII tier へ抜け、非ASCII subject は残りだけ
チェックを払う。`simple_from(s8, start)` は subject に**多コードポイントクラスタが
ない**（=コードポイント≡書記素、バイト DFA の答えが書記素エンジンと一致）とき true。
単一前進パスで：ASCII 前置を `CR×LF` 融合についてチェック；`start` から、隣接2
コードポイントが融合した瞬間に棄却（`gb_fuses`）；**印字可能 ASCII ラン を SIMD で
スキップ**（印字可能 ASCII ランは多コードポイントクラスタを含めない）。融合があれば
書記素 Pike へフォールバック。

### CRLF — 崖と `crlf_byte_safe`

`simple_from` は全 `\r\n` を棄却するので CRLF 散文はバイトパスに乗りませんでした。
しかし CR-LF クラスタが問題になるのは、*パターン*が1クラスタ CR-LF と2バイト
`\r``\n` を区別できるときだけ。多くは区別できません。`crlf_byte_safe(node)` は構造的
述語——どの要素も差を観測しなければ安全:

- リテラルは `\r`/`\n` を含まない；
- クラスは `\r` も `\n` も**どちらもマッチしない**、または**両方**マッチするが
  無制限貪欲反復の直接被反復 atom としてのみ（貪欲 run は `\r` を `\n` を2バイト
  ステップで、書記素エンジンが1クラスタで消費するのとちょうど同じ位置で消費——
  同じ span、間に境界なし）。`\r`/`\n` の**ちょうど一方**にマッチするクラスは
  乖離し不安全；
- `.` は dotall 時のみ `\r`/`\n` に触れ、そのとき透過的のみ；
- 透過性は群境界、固定回数/非貪欲構造で止まる。

`can_match_empty_`（nullable）は CRLF 許容に**非空**マッチを追加要求します（空マッチ
がクラスタ内部の LF に落ちうる——バイトモードには在るが書記素モードには無い位置）。
`simple_from_crlf_ok` は `simple_from` ＋「CR×LF クラスタを許可」で、ASCII ラン全体
（`\r\n` 改行を含む）を次の非ASCII バイトまで SIMD スキップします。

§7 のプレフィルタと合わせ、`/Sherlock/` を ~24 → ~13000 MB/s にしました。

### `crlf_collapse` — bounded な `\r\n` クラス反復

`crlf_byte_safe` は両方マッチ（`\r`/`\n`）クラスを*無制限貪欲*反復の atom としてのみ
許容し、**bounded / lazy** 反復（`[^"']{0,30}`、`[^u-z]{13}`）は CR-LF を 1 クラスタ vs
2 バイトと数えるため棄却します——これが（CRLF の）Sherlock corpus で最も負けた
パターン（`["'][^"']{0,30}[?!.]["']` が ~15 MB/s）です。**キャプチャ無し**かつ
`\r\n` に触れるクラスがすべて**否定クラス**なら、各クラス `C` を `(?:\r\n | C')` に
書き換えます（`C'` は `C` から `\r`/`\n` を除外＝否定レンジ集合に追加）。`\r\n` 枝が
CR-LF ペアを 1 要素として消費し（書記素エンジンの 1 クラスタ歩進に一致）、CR-LF を
消費する**唯一**の枝なので分割パースが存在せず、collapsed バイトプログラム
（`byte_prog_` / `byte_rev_prog_` / `byte_lf_prog_`、collapsed AST からコンパイル）は
ペア CRLF subject 上で書記素エンジンを再現します。`egc_byte_path` はこの subject を
`no_lone_crlf` でゲートして許可：lone な `\r`/`\n` は collapsed プログラムでマッチ
不能なので、全 `\r\n` がペアである必要があります。

キャプチャ無し限定——キャプチャありだとバイト DFA は span を書記素単位（CR-LF=1）で
確定しますが、グループは `cp_prog_`（コードポイントプログラム、CR-LF=2）で解決する
ため、CR-LF をまたぐ bounded グループは span を再マッチできずマッチ脱落します。
よってその種は書記素 Pike に留めます。これで `["'][^"']{0,30}[?!.]["']` は ~15 →
~740 MB/s（RE2 超え）。`[a-q][^u-z]{13}x` も崖を脱します（~7 → ~50 MB/s）が、残余の差は
`.{13}` の DFA 状態爆発であって崖ではありません。

collapse パターンが**必須の接尾アンカー**を持つ場合、per-call のゲート
（`simple_from_crlf_ok` + `no_lone_crlf`、接尾 prefilter 自身のパスに先立つ 2 回の
O(n) パス）を接尾スキャン自体に融合します（`egc_fused_collapse_ok` →
`egc_literal_fused_find` の `collapse=true`）。クラスタ条件はスキャンの非ASCII停止に
相乗りします。lone CR/LF 条件はそもそも**スキャンしません**：lone な CR/LF が問題に
なるのは collapsed バイトプログラムが実際に*歩く*場所だけなので、候補ごとの検証が
踏査した窓だけを調べます（`crlf_pairs_ok_window`——DFA 逆走査は踏査した床を、前方
再展開は到達点を報告し、窓は 1 バイト広げて縁をまたぐペアを実際の隣接バイトで判定）。
候補間のギャップは lone CR/LF を無害に含んでよく、ギャップスキャンは安い素の述語の
まま、subject は 1 回しか読みません。不適格な窓（lone CR/LF＝ごく普通の Unix 改行
テキストがマッチ近傍にある）や融合クラスタは非融合 ladder に bail し、イテレータは
Pike へ降格せず再 prime（`reprime_unfused`）するため、素の LF テキストは従来通り
ASCII DFA tier に乗ります。var-pre の接尾は scalar chain 検証が担う場合に許可されます
（終端を正確に計算し、検証済み窓の外への前方再展開が無い）。CRLF Sherlock corpus の
`[a-q][^u-z]{13}x` を ~7.7 → ~11.8 GB/s に（rure ~12.9）、窓の局所化で否定クラスの
引用パターンを ~11.5 → ~14.8 GB/s に。

### assert バイト tier

`\b`/`^$`/`\A\z` パターンは `dfa_assert_ok_`（`dfa_ok_` でない）で assert 対応 DFA が
処理。同じ EGC バイトパスを構築：コードポイント対応 `ByteAssertDfa` が非ASCII subject
を assert DFA に通し、`crlf_byte_safe_` / `can_match_empty_` ゲートを再利用します。

### 書記素 Pike に残るもの

真に多コードポイントクラスタ——結合マーク、ZWJ 絵文字、ハングル jamo、地域指標旗、
`Prepend` ラン——を含む subject は `simple_from` で落ち、分割が状態依存で正しい書記素
Pike で走ります。この残余崖は本質的（状態依存の書記素 `.` のバイトオートマトンは
存在しない）；§5 が逃げ道です。

**pure-ASCII subject の CR-LF。** ASCII 高速路は「バイト ≡ コードポイント ≡
クラスタ」を前提にしますが、これは CR-LF ペア（GB3 で 1 クラスタだが 2 バイト）を除く
全 ASCII バイトで成立します。ASCII を書記素モデルと一貫させるため、`segment()` は
`\r` を含む ASCII subject を書記素経路に回し（ペアを融合）、`ascii_grapheme_ok()` が
非ASCII byte path と同じ `crlf_byte_safe_ && !can_match_empty_` 述語で ASCII DFA /
assert tier をゲートします：CRLF 敏感パターン（計数付き `\r\n` クラス反復・dotall
`.{n}`・nullable 本体・multiline `^`/`$`）は ASCII-CRLF subject で CR-LF 融合する Pike
に委譲。`.` の特別扱いは不要です——非dotall `.` は元々 `\r\n` を除外するので byte path
も書記素エンジンも CR-LF の手前で止まり一致し、`Holmes.{0,25}Watson` 等の近接パターンは
byte DFA に残って全速。唯一の食い違いは CR-LF 内部 LF 位置の空マッチで、`!can_match_empty_`
で除外されます。

---

## 5. UnicodeScalar モード（バイトオートマトン）

`CodePoint` マッチ単位（`reg::set_default_match_unit`）はマッチ単位を **Unicode
スカラ（コードポイント）**——RE2 / Rust `regex` のモデル——に切り替え、崖を完全に
除去：バイト DFA が生の UTF-8 を分割
なし・`is_ascii` ゲートなしで直接走ります。構文・leftmost-first 意味論・線形時間・
バイトオフセット報告は不変；変わるのは `.`/クラスの単位とオフセット境界だけ。

§3 の**2プログラム**（`prog_`/バイト + `cp_prog_`/コードポイント）を保ちます。
`run()`/`run_saves()` はプログラムでパラメタ化され、実証済み書記素 Pike が `cp_prog_`
を変更なくコードポイント意味論・バイトオフセットで走らせ、subject は `segment_cp`
（素の UTF-8 デコード）で供給します。

### コンパイル時の大文字小文字畳み込み

バイト DFA はバイト単位で畳めないので、icase はコンパイル時にバイトプログラムへ焼き
込みます。`case_fold_groups` が `0..0x10FFFF` を一度走査（キャッシュ）し
`simple_case_folding` でサイズ≥2 の軌道（`{a,A}`、`{k,K,U+212A}`）にグループ化；
`case_expand` がリテラル/クラスと交わる軌道の全メンバを追加——`prog_` が全大小変種を
直接受理し、Pike が `cp_prog_` 上でマッチ時に適用するのと同じ畳み込み等価
（`fold(a)==fold(b)`、軌道含む）に一致します。（`ß`→`ss` の完全畳み込みは書記素
エンジン同様 対象外。）

DFA ベースのエンジン（バイト DFA、one-pass）は US（任意 subject）と ASCII 書記素
モードに適用できますが、分割が状態依存の非ASCII *書記素*マッチには適用できません。
よって US が非ASCII の高速パスで、非ASCII 書記素キャプチャは書記素 Pike に残ります。

---

## 6. キャプチャエンジン

順序付き+cut DFA が leftmost-first `[s, e)` を特定し、群はその span 内（`e` で境界
付け）を**コードポイント**プログラム `cp_prog_` 上で最も安い能力あるエンジンが解決。
速い順に 3 つ:

| エンジン | 発動条件 | 仕組み |
| --- | --- | --- |
| **CpOnePass**（`build_cp_onepass`） | パターンが one-pass・span が全て単一コードポイント | 決定的キャプチャ記録 DFA：pc 集合状態、各遷移が `(次状態, 現在位置にセットするスロットのビットマスク)` を持つ。単一前進パス・~DFA 速度で記録。構築は 2 フレーバー：*uncut*（完全 accept 集合＝最長マッチエンジン。`e` で境界付けるか accept==n 条件で使う）と *leftmost-first cut*（各状態のクロージャを優先度順に探索し最初の `Match` で打ち切る。unbounded 歩行の最終 accept が leftmost-first 終端そのものになる。Alt 無し・貪欲のみのプログラム＝優先度順が pc 昇順のときのみ健全）。バイト毎のステップは**1 回の packed `u32` ロード**——次状態 id・キャプチャ書き込みマスク id・次状態が accept かのビットを 1 ワードに格納——で、別配列からの 3 ロード（依存チェーン上の 3 キャッシュライン）を置き換える。自己ループの出口が ≤ 8 ASCII バイトでスロット書き込みの無い状態（`\S+` のような反復ラン）は、バイト毎の依存ロードでなく出口集合への 1 回の `scan64` でラン全体をスキップ——状態*エントリー*時に 4 バイトのスカラプローブを経て一度だけ起動（短いランは SIMD のセットアップよりバイト毎ループの方が安い）。span 内に非ASCII コードポイントがあると中断（→ BitState）。 |
| **BitState**（`bitstate_bytes`） | one-pass でない・span ≤ `kBitStateCap` | 特定 span 上の `cp_prog_` を bounded leftmost-first バックトラック。コードポイントを逐次デコード（分割なし）、`(pc, バイト位置)` の visited ビットマップで O(prog × span) を保ち、キャプチャ書き込みは巻き戻す。 |
| **コードポイント Pike**（`cp_prog_` + `segment_cp` 上の `run_saves`） | span 超過、または DFA 状態上限でパターン全体が落ちたとき | 万能フォールバック。 |

whole-match キャプチャ（全群=全体マッチ、例 `(\w+)`）は3つすべてをスキップ：各群の
span が `[s, e)`。全エンジンが同じ NFA 上で leftmost-first なので書記素エンジンと
一致します。

**unbounded one-pass find（`cp_onepass_find`、`onepass_unbounded_`）。**
bounded 連鎖はマッチ毎に 3 回歩きます（前方 DFA で `e`、逆 DFA で `s`、その上で
capture エンジン）。AST に**選択肢が無く、lazy 反復が無く、反復下に捕獲グループが
無い**とき、テーブルは leftmost-first cut 付きで構築され、その下では固定開始位置
からの歩行の最終 accept が leftmost-first 終端**そのもの**になり（貪欲性だけでは
不十分：`x(?:ab)?(?:abc)?` のような隣接 nullable 反復は最長 accept より手前で
コミットする）、最終 accept 位置より後にスロット書き込みは発生しません——よって
マッチ**開始**さえ候補源から得れば、**1 回**の unbounded one-pass 歩行で終端と
全キャプチャが出ます。ASCII tier の候補源は 2 つ：必須 ASCII
リテラル前置（`\{\{\s*(\w+)\s*\}\}`、`/users/(\d+)`。全マッチが前置で始まるので
最初に完走した候補が leftmost）と、非吸収 ReverseInner の床（`(\w+)=(\S+)`。床が
正確な開始）。失敗歩行のバイト予算が線形性を守ります（前置バイトを自身の反復が
吸収できる `a([a-z]+)0` × `aaaa…` は重なる尾を二次的に再歩行し得る）——予算切れは
located-span 連鎖へフォールバック。mustache `\{\{\s*(\w+)\s*\}\}` を
~0.69 → ~1.3 GB/s、markdown `\[([^\]]+)\]\(([^)]+)\)` を ~0.18 → ~0.52 GB/s
（いずれも rure 超え）、key=value を ~0.85 → ~1.1 GB/s に。`match()` も同じ歩行を
0 アンカーで使います。ドライバ群は 1 つの玄関（`onepass_driver_find`：リテラル前置 →
非吸収 ReverseInner → 位置スキャン。位置スキャンでは全位置が候補ですが、外れ候補は
たいてい最初のバイトで死にます——access-log ~0.13 → ~0.31 GB/s、RE2 超え）を通り、
唯一の assert が末尾 `$` のパターンも accept==n 条件でこの族に加わります
（`\.([a-zA-Z0-9]+)$`：73 → 50 ns）。

**anchored scalar-chain capture find（`chain_capture_find`、
`analyze_chain_capture`）。** one-pass 歩行のさらに一歩先：パターン*全体*が ASCII
リテラル文字と単一コードポイントクラス反復の連結で、固定の中間/端リテラルの周りの
パースがアンカー出現に対して**強制**されるとき、マッチも*全*グループも素朴なバイト
歩行から出ます——オートマトンは一切走りません。`(\w+)=(\S+)`：`=` を探し
（rare-byte / pair-probe スキャン）、`\w` を左へ、`\S` を右へ歩く；グループ span は
ランの境界そのもの。強制の条件：アンカーの左（右から左へ歩く）は、隣接要素の ASCII
集合が互いに素——または左の全要素が固定回数——で、各可変要素は `min ≥ 1` の貪欲、
かつ左のどの要素もアンカーバイトを消費できないこと（このとき歩行は先行するアンカー
出現を決して越えず、leftmost 開始が固定され候補の順序が保たれる）；アンカーの右
（前方へ歩く）は、各可変要素が後続と ASCII 互いに素（貪欲な最大ランがバックトラック
を要しない）で、最終要素は無条件（貪欲）；そして各キャプチャはちょうど 1 要素を包み、
全グループがカバーされること。候補近傍の非ASCIIバイトはオートマトンドライバへ
ベイルし、歩行は共有の失敗歩行予算を消費します（アンカー右の要素がアンカーバイトを
吸収し得るため、失敗候補は重なり得ます）。key=value `(\w+)=(\S+)` を
~944 → ~2160 MB/s に。

---

## 7. プレフィルタ

プレフィルタは「次にマッチが始まりうる位置は？」を、生バイト上の安い SIMD 向け
スキャンで答え、エンジンを候補でのみ走らせます。制約：**健全性**（偽陽性は可、偽陰性
は不可——各はプログラムから導出）、**線形性**（単一パス、候補ごと再シードなし）、
**外部依存なし**（`memchr`/`memcmp` ＋手書き NEON/SSE；高速プラットフォーム `memmem`
に依存しない）。

**スキャンループは1つ（`scan64` / `scan64_visit`）。** プレフィルタのバイトスキャンは
すべて同じ形——「`[off, n)` で 16 レーン述語を満たす最初のインデックス」——なので、
速いループは1箇所にだけ存在します：8ブロックのエントリーランプ（ヒット後に再開する
呼び出し元が、ヒット密度が高い領域では安い1ブロックコストで済む）、続いて1イテレー
ションあたり 16 バイト×4ブロック＋64 バイトごとに1回の any-hit テスト。停止なしの
スキャンを ~25 GB/s（libc `memchr`：16 バイト/イテレーション＋停止毎の call）から
~65 GB/s へ引き上げるのはこの 64 バイト/イテレーションで、このプリミティブで表現
されたスキャンはすべてそのレートを得ます。述語はプラットフォームのレーンマスクと
対応するスカラテストを供給する小さな struct（`PredEq`、`PredPair`、`PredInList`、
`PredSetPair`、…）で、**合成**できます：`PredOrNonAscii<P>` は任意のスキャンに
バイトパス tier の非ASCII停止を加えます。`_visit` 形は候補検証を*その場で*駆動——
検証はストライド内の各ヒットで走り、棄却された候補は次の ctz から続行（ループ再起動
なし）——なので、以下の候補+検証型プレフィルタ（`find_substr` の比較、`(?i)` fold
比較、融合 collapse 検証）は probe バイトが頻出でも偽陽性1つにつきビットスキャン
1回しか払いません。

**どこで走るか。** DFA tier は前進スキャンの開始状態にスキップを畳み込む：まず
リテラル接頭 **memmem**（`find_substr`、`prefix_` / `byte_prefix_`）、無ければ
first-byte 集合スキップ。memmem は冗長でなく必須——非アンカー lf プログラムは
`(?s:.)*?` + 本体で、開始 ε-閉包に接頭の `.`（全バイト）が入るため first-byte 集合が
全バイト化しリテラル先頭パターンでは決して skip しない。memmem 無しだと pure-ASCII
subject のリテラル走査がバイト毎 DFA に落ちる（memmem を元から持つバイト tier より
≈7倍遅い）。単体プレフィルタは Pike フォールバック（後読み等）でも生きる。ディスパッチ
は排他：`dfa_ok_ && ascii` → DFA、それ以外 → Pike ＋ プレフィルタ。2系統は異なる
アルファベットで推論：書記素プログラム（`prefix_`、`first_bytes_.set`）は ASCII バイト上；
バイトプログラム（`byte_prefix_` 等、`byte_prog_` から）はバイト tier で任意 UTF-8 上
（自己区切りなので健全）。なお per-subject の byte-path ゲート（`first_nonascii`＝最初の
非ASCIIバイトへの SIMD 走査）は**呼び出しごとに1回だけ**計算し、`egc_byte_path` と
`ascii_grapheme_ok`（両者が precomputed index を取る）で共有する。ゲート毎に O(n) パスを
やり直さず subject を1回だけ分類＝でないと pure-ASCII の速いリテラル find はゲートが律速になる。

- **リテラル前置部分文字列検索（`find_substr`）** — **rare-byte トリック**。`memmem`
  は確実に速くない（macOS で ~1.3 GB/s の床）ので、代わりにリテラルの**最も稀な**
  バイトを `memchr`（英語散文頻度表で選択：空白は頻出、句読点/数字/非ASCII は稀で
  良い probe）し、`memcmp` で検証（両脚とも `scan64_visit` 上を走る；依存ゼロ）。
  全 ASCII 前置（`prefix_.ascii`）は*任意*の UTF-8 subject で `memmem` スキップ可能。
  最稀バイト自体が**頻出**のとき（パーミル頻度 ≥ 16＝本当に頻出な小文字：`ing`、
  `Holmes`）、スキャンは**2バイト pair probe**（`PredPair`——rure の memmem の形）に
  格上げ：needle の最稀2バイトが*両方*、needle 上の正確な距離で現れる位置でのみ
  停止し、2つの密度が掛け合わさって停止が一桁減ります（Sherlock corpus 上の `ing`：
  8033 → 2934）。コストはブロックあたり追加ロード1回。pair 距離には上限（48）が
  あり追加先読みがベクトルループに収まる範囲に留め、相方は**plan 時**に選びます
  （`pair_probe` → `probe2` フィールド群）——find 毎の再計算はマッチ毎に効いてくる
  ためです。
- **短い (?i) リテラル → ケース軌道の選択肢化（`decase_ascii_literal`）** — 純粋な
  印字可能 ASCII の `(?i)` リテラルで、全文字が *clean*（fold の前像が自分の ASCII
  大小文字のみ。live fold テーブルで判定）かつ cased 文字 ≤ 4 のものは、plan 時に
  明示的な case-sensitive 選択肢（`(?i)the` → 8 分岐）へ書き換えて `icase_` を落とす
  ——以後は通常のリテラル選択肢として Teddy/LiteralAlt tier が担う。軌道は icase
  リテラルがマッチするバイト列を任意 subject 上で**厳密に**列挙するので、下流の全
  tier が自動的に正しい。dense な `(?i)the` を ~0.73 → ~1.7 GB/s（rure ~1.4・
  PCRE2-JIT ~1.6 超え）。unclean な文字（`k`、`s`）や長いリテラル（`(?i)Sherlock`
  は 256 分岐）は下の前置 prefilter 経路のまま。cased 文字が無いリテラルは inert な
  `icase_` を落とすだけで素の Literal tier に乗る。
- **大文字小文字無視のリテラル前置（`find_substr_icase`）** — `IgnoreCase` でも
  全 ASCII 必須前置はフィルタとして有用だが、**ASCII subject 限定**。ASCII の
  case fold はそこでは厳密だが、UTF-8 上では fold 原像（Kelvin K→k、long-s ſ→s）
  が複数バイトで、バイト単位の fold 走査がクラスタ内部に着地し得る。よって
  `prefix_.icase` は前置が全 ASCII かつ非 US モードのときのみ立ち（前置は小文字化
  して保持）、*全ての*前置スキップ地点を分岐する。**ASCII subject** の地点（DFA scan、
  `search_at_or_after`）は `find_substr_icase`——最も稀な**case-fold 後**バイトの
  両ケースを SIMD `memchr2`（小文字 `'s'` は頻出なので `'k'` を選ぶ）した後に ASCII
  fold 検証——を呼ぶ。`(?i)Sherlock` を ~1000 → ~8000 MB/s（≈ rure；RE2 ~440）に。
  **非 ASCII subject** ではバイト単位の fold 走査がクラスタ内部に着地し得るため、
  代わりに生 UTF-8 上で動く：**2 つの稀な case-fold プローブバイト**——*unclean*
  fold orbit から1つ、*clean*（単一バイト）orbit から1つ——を `memchr2` し、複数バイトの
  fold 原像（Kelvin `K`、long-s `ſ`、先頭バイトは `0xE2`）を取り逃がさないよう各々を
  刈り込み/ガードした上で、特定された窓を bounded anchored verify で確認する。候補開始は
  バイト first-byte 集合（`byte_first_bytes_.set`）で事前に刈り、orbit は `case_fold_groups()`
  由来。非 ASCII `(?i)Sherlock` を ~1035 → ~6316 MB/s（≈ rure 0.82×；従来は無フィルタ）に。
  両者とも健全：verify はエンジン自身の fold 対応マッチ。pair probe には `(?i)`
  版があります（`PredFoldPair`）：fast プローブの文字がそれでも頻出で（`(?i)Sherlock`
  の `k`）、*かつ* subject が前置の**どの**文字の fold 原像先頭バイトも含まないとき
  （`pair_leads` ガード——このとき全前置文字はこの subject 上で正確に1バイト）、
  最稀2文字の case ペアが前置上の正確な距離に並ぶ位置でのみ停止します。バイト距離が
  固定なので、ヒットは単一の候補開始を特定——窓歩行は不要。CRLF Sherlock corpus 上の
  停止 3681 → 771；`(?i)Sherlock` ~6.3 → ~8.6 GB/s、`(?i)Holmes` ~2.7 → ~9.0。
- **Teddy — SIMD 複数リテラル。** リテラル選択（`fox|dog|cat`）は単一前置を持たず
  first-byte スキップは毎 `f`/`d`/`c` で止まる。Teddy（Hyperscan / Rust-regex の
  "slim" 設計）は*全*候補の先頭 `N` バイトを 16 位置同時に照合：各 fingerprint が
  8 ビットマスクの1ビットを持ち、16 バイトチャンクごとに `PSHUFB`/`TBL` ニブル
  ルックアップ＋シフト重ね AND で、いずれかのリテラルの `N` バイト前置が現れる lane
  だけ非零になる。`N` は最短リテラルが許す最長 fingerprint（最大4）。NEON と SSSE3 は
  手書き、scalar `teddy_hit` が末尾/フォールバック。`fox|dog|cat` を ~19 → ~390 MB/s。
  **全**候補が完全な ASCII リテラル（共有前置だけでなく――`analyze_literal_alternation`
  → `literal_alt_`）のときは、Teddy は prefilter ではなくマッチャそのものになる：
  `literal_alt_locate` が Teddy ヒットを取り、リテラルを選択順に試して span を
  **DFA 検証なし**で直接返す（グラフェム境界チェックでどの subject でも健全）――
  純リテラル選択 tier。*混在*選択（素のリテラルでない枝を含む）では Teddy は従来どおり
  DFA に候補を供給する候補発見器のまま。`teddy_next` は実行時の fingerprint 長を
  コンパイル時 `N` の `teddy_scan<N>` にディスパッチします：ニブル表が呼び出し毎に
  スタック配列へコピーされる（128 バイトの memmove——イテレータはマッチ毎に呼ぶので
  tier の ~10%）代わりにレジスタに住み、短リテラル検証はインライン `bytes_eq`
  （libc `memcmp` の *call* がさらに ~20% だった）。
- **first-byte（dead-byte）スキップ** — リテラル前置の先頭 first-byte *集合* への
  一般化（`analyze_first_bytes` が開始 ε-閉包から収集）。`skip_to_first_byte` は集合
  サイズで階層化（1 → `memchr`；≤8 → NEON/SSE2 スキャン；それ以上 → 表引き）、
  `first_bytes_.sparse`（≤32）でゲート：密な集合（`\w` ≈ 63 バイト）は稀にしか発火
  せずオーバヘッドだけなので、何も払わない。
- **非ASCII subject での ASCII 前置スキップ** — 書記素 Pike に乗る非ASCII subject も、
  パターンが全 ASCII 必須前置を持てば恩恵：`prefix_skip_nonascii` が生 UTF-8 上で
  `find_substr` を走らせ書記素境界ガードを掛ける（`/Sherlock/` 崖除去の一部）。
- **必須接尾リテラルスキャン（`suffix_find`）** — リテラル前置の鏡像。クラス/`.` で
  *始まる*（＝DFA の first-byte skip が密で無効）が、固定長本体の後に固定 ASCII
  リテラルで*終わる*パターン（例 `[a-q][^u-z]{13}x`、末尾 `x` が稀）向け。前方 DFA は
  全バイトを舐めてしまうので、代わりに稀な接尾を `find_substr` する。リテラルは
  **種であって答えではない**：ヒットは開始の*床*を復元する（接尾からの逆 DFA スキャンを
  非重複下限で floor）が、末尾は常にそこからの anchored **前方** DFA で取り直す——貪欲な
  可変長本体はリテラルをマッチ中間に置き得る（`singing` 内の `...ing`）ので、末尾を接尾から
  読むと切れてしまう。前置が*固定長*（`analyze_byte_suffix`）なら各接尾出現は一意の
  leftmost-first 候補になり、memmem カーソルは失敗候補を越えて進むが floor は据え置くので、
  失敗候補より前で始まるマッチも後続の接尾で拾える。*可変長*前置（`suffix_.var_pre`、
  rure の *ReverseSuffix*）は `[a-zA-Z]+ing` 等へ拡張するが、本体が **step-1 prefix-closed**
  （無限反復下の単一コードポイント atom）のときに**限る**。一般の可変長前置は leftmost-first
  を壊す：より長いマッチが先行する接尾ヒットの左で始まりつつ後続の接尾で終わり得る（fuzzer が
  `(?:[^a-c].\w+)?b` で正解 `[0,4)` でなく `[1,2)` を採用するのを捕捉）ので、それらは素の DFA に
  フォールバック。他と違い **DFA tier 上**（find_all/find_iter/search）で動き、capture 無し
  限定、リテラル前置があれば無効化（前置 memmem が最適）。`[a-q][^u-z]{13}x` を
  ~57 → ~1650 MB/s（RE2 ~260；rure はより平坦な verify で ~12000）、`[a-zA-Z]+ing` を
  ~258 → ~1640（RE2 ~389 超え）に。残りのギャップは2つの改良で閉じます。
  (1) **scalar forced-parse 検証**（`Verify::Scalar`、`analyze_suffix_scalar_verify`）：
  接尾前の本体が ASCII リテラル文字と単一コードポイントクラス反復の鎖で、その
  パースが*強制*されるとき——隣接しうる要素対のバイト集合が互いに素（直接の隣接、
  および `min=0` 要素は空になり得るので空要素を跨ぐ推移閉包まで）、または全要素が
  固定回数（位置だけで配置が強制される）——各候補を逆DFA＋前方取り直しのペア
  （各 ~2.2 ns/B）でなく素朴な表引き歩行（~0.3 ns/B）で確認します。`absorb_last` は
  `[a-zA-Z]+ing` の形——クラスラン内の**最後**の出現がマッチ終端（重なり周期性の
  論法で強制される）——をカバー。候補近傍の非ASCIIバイト（collapse tier では CR/LF
  も）はその候補1つだけを DFA 検証へベイルします。(2) **class-tail アンカー**
  （`suffix_.cls`、`PredSetPair`）：アンカーはリテラルでなくてもよい——パターン*末尾*
  が2つの固定小クラス（`["'][^"']{0,30}[?!.]["']`）なら、クラスペアの隣接として
  スキャンします。2クラスは**互いに素**であること：重なるペアはアンカーの1バイト
  スライドを許し（`[ab]+[bc][cd]` は `abcd` 上で切れたマッチを報告してしまう）、
  admission は chain-or-nothing——scalar 検証の条件が成立必須で、DFA は候補ごとの
  ベイル先専用。CRLF corpus 上の引用文字列 ~1.25 → ~2.5 GB/s。
- **希少な中間リテラル（`ReverseInner`）** — 前置にも接尾にもリテラルが**無く**、
  クラス始まりの形（`\w+ Holmes \w+`、`\w+@\w+`）の**中間**に稀な固定リテラルを持つ
  パターン向け：両端に何も無いと DFA は skip を持たず全バイトを舐める。中間リテラルを
  `find_substr` し、前置を逆 DFA で走らせて開始の床を復元し、そこから通常の lf 前方＋逆を
  走らせる。接尾スキャンと同じ **種であって答えではない**規律：末尾は床からの全体前方パスで
  取り直す——貪欲な前置が中間リテラルを飲み込み得る（`.{2,}c\d?`）ので、スパンをリテラルから
  読むと誤る（*singing* バグの inner 版——fuzzer が捕捉）。`\w+ Holmes \w+` を
  ~386 → ~10300 MB/s、`\w+@\w+` を ~275 → ~21400 に。（中間ギャップを持つリテラル*選択*
  `Holmes.{0,25}Watson` は既に発火する Teddy に委ねる。）capture パターンも許可する——
  prefilter はスパンの**位置特定**だけを行い、グループは capture エンジンがその上で
  解決する——ただし **pre が単一ノード**（`(\w+)=(\S+)`）の場合のみ：capture 連鎖は
  どのみち確定スパンを再走査するため、pre 部が長いと追加の reverse(pre) パスが密マッチで
  純損になる（7 グループの access-log パターンはこのゲート導入前に回帰した）。
  `(\w+)=(\S+)` を config コーパスで ~285 → ~830 MB/s（RE2 ~310 超え）に。ドライバは
1 つの入口（`onepass_driver_find`：リテラル前置 → 非吸収 ReverseInner → 位置スキャン。
全位置が候補で、外れはほぼ先頭バイトで死ぬ——access-log ~0.13 → ~0.31 GB/s、RE2 超え）
を通り、唯一の assert が末尾 `$` のパターンも「accept==n」条件で同じ族に乗る
（`\.([a-zA-Z0-9]+)$`：73 → 50 ns）。
- **assert tier 固定text リテラル** — assertion パターン（`(?m)^X`、`X$`、`^X$`、
  `\bX\b`）は assertion DFA が担うが、これは本来全位置を走査する。ゼロ幅 assertion を
  剥がした後が単一の**固定リテラル**（`fixed_text`、再帰抽出）になるとき、エンジンはその
  リテラルを `memmem` し、各ヒットを anchored assertion DFA で確認する（`assert_find_span` /
  `assert_byte_find_span` 共有）。`(?m)^Sherlock Holmes|Sherlock Holmes$` を
  ~229 → ~12700 MB/s（≈ rure ~8000；RE2 ~455）に。リテラルで*終わる* assertion 本体は
  下の必須接尾 prefilter が拾う。使えるリテラルの錨が無いものだけ全走査のまま。
- **assert tier 必須接尾リテラル**（`assert_.suffix`、`analyze_assert_suffix`）—
  先頭リテラル prefilter の接尾版。固定長／1コードポイント反復の本体の後に固定 ASCII
  リテラルで*終わる* assertion パターン向け。assertion DFA は全位置を走査してしまうので、
  代わりに `assert_suffix_find` が末尾リテラルを `memmem` し、各出現を anchored assert
  スキャンで確認、可変長の開始を逆走査で復元する。さらに `\b \w{n,m} <lit> \b`
  （`\b\w+n\b`、`\b\w+ing\b`）という厳密形には **DFA を一切使わない**語スキャン高速形：
  リテラルを `memmem` し、末尾 `\b`（次のコードポイントが非word）を確認、word コードポイント
  を左へ歩いて run の開始を求め（`assert_word_find`）、`\w` の run 長が `{n,m}` に収まるか
  検査する。assert tier は単一コードポイントクラスタ（コードポイント == グラフェム）しか
  扱わず、ここの `\w` は素の Word 述語ちょうどなので、この歩きは正規表現を再現する（健全）。
  `\b\w+n\b` を ~190 → ~776 MB/s（rure/RE2 超え）に。
- **assert tier 先頭リテラル**（`assert_.prefix`）— assertion パターンが固定text では
  ないが**最初の消費アトム**が固定 ASCII リテラル（その前はゼロ幅 assertion のみ：
  `\.([a-z]+)$`、`^foo(\w+)`、`\bID(\d+)`）のとき、全マッチはそのリテラルで始まるので
  リテラルの `memmem` が全候補開始を与える。続いて **anchored** assert 前進スキャンが
  マッチ全体（先頭+末尾の assertion）を検証し可変長の終端を返す。固定text/末尾リテラル
  prefilter と違い**capture-free に限定しない** ―― assert-capture tier(2a) の位置特定も
  駆動するので、`\.([a-z]+)$`（capture）も `\.[a-z]+$`（capture-free）も位置ごとの assert
  走査を回避（EGC ~640/~515 → ~220/~90 ns）。memmem 順＝開始順、全マッチは prefix で始まる
  ので最初に検証成功したヒットが leftmost-first。
- **純リテラル find の単一パス化** — 素の printable-ASCII リテラルパターン
  （`literal_only_`）は従来*2*パス払っていた：バイトパスゲート用の subject 分類、そして
  `memmem`。printable ASCII は `Grapheme_Cluster_Break=Other` なので、リテラルヒットが偽の
  クラスタ境界になり得るのは局所判定可能な2通りだけ（直前の `Prepend`、直後の
  `Extend`/`ZWJ`/`SpacingMark`）。リテラル tier はそれだけを判定して subject 全体分類を
  飛ばし、**単一**パスでマッチする。`zqj` を ~20000 → ~38600 MB/s、`/Sherlock/` を
  ~13500 → ~23800（RE2 超え）に。同じバイト単位リテラルプリフィルタは **UnicodeScalar**
  モードにも配線済み——従来は EGC 限定で、US `zqj` を ~450 MB/s に留めていた欠落穴。

各プレフィルタは正しい scalar フォールバックを持ち、ディスパッチは排他なので、どの
プレフィルタを無効にしても速度が変わるだけで結果は変わりません。

---

## 8. 結果の引き渡し：`search`/`find_iter`/`find_all`

マッチが*どこにあるか*（上のエンジン）と、結果を*どう引き渡すか*は別問題。API は
アリティと遅延性で分かれます:

- **`search()` / `match()`** — 1マッチ。自己完結の所有 `MatchResult`（マッチ文字列＋
  群文字列をコピー）。1回のコピーは安く寿命安全で、所有コピーのコストは bulk でのみ
  効きます。
- **`find_iter()`** — *遅延* bulk。`MatchIter` レンジがエンジンを **`++` ごとに1マッチ**
  進める（スレッドの warm DFA を再利用）ので、早く抜ければ残りは走査しません。各
  反復は `Match` の **view**（オフセット＋subject への view、保持は
  `to_owned()`）を yield、次の `++` まで有効。一時 subject は拒否（view が dangle）。
- **`find_all()`** — *先行* bulk。`Regex::MatchList` columnar コンテナ：全マッチを先に、
  バイトオフセットの Structure-of-Arrays（`vector<uint32_t>`、マッチごと
  `2*(ngroups+1)` 行）＋subject バッファ1個として保持；`str()`/`group()` は `Match`
  プロキシ経由でそこへの `string_view`。ランダムアクセス・`size()`・複数パス可。

両 bulk 形式は **view ベース**——マッチごとの `std::string`/`std::vector` 確保なし。
（所有 `vector<MatchResult>` は `find_iter()`/`find_all()` ＋ `to_owned()` で得る。）これは
意図的：密 `\w+` のプロファイルで、オフセットのみのスキャン自体は既に RE2 を上回る
一方、マッチごとの実体化（確保＋重い 120 バイトオブジェクトの vector 再確保）が実行
時間を支配していました。columnar コンテナはオフセットのみのスキャン速度（密マッチで
所有 vector の ~2.7×）・~15× 省メモリで走ります。

### 共有ステッピング

両 bulk 形式は、エンジンが既に持つ tier 別の単発プリミティブで同じくマッチを巡り
ます：`dfa_forward_lf` + `dfa_reverse_scan`（キャプチャなし）、`+ capture_saves_bytes`
（キャプチャ、バイトオフセット、文字列なし）、`assert_find_span`（assert tier）、
`run_saves` + `append_match_spans`（Pike）。`find_all()` は tier ループを完走して行を
追加；`find_iter()` は `++` ごとに1ステップ。`find_iter` 途中で状態上限に当たった DFA tier は
現在の cursor から Pike VM に降格して継続します。

### 呼び出し間 DFA 再利用（`FindCache`）

そうしないと各呼び出しが `LazyDfa` を毎回ゼロから再構築します——`\w+` の全 Unicode
バイト DFA は構築 ~4 ms なので、1つの `Regex` で多数の小文書をトークナイズすると毎回
同じ状態を再発見します（ベンチで 1 文書 ~57 vs 8000 小文書 ~11 MB/s——5× の差は
*スキャン*でなく*構築*）。**呼び出し側が持つ `FindCache`**（PCRE2 `match_data` /
Hyperscan scratch / `regex-automata` `Cache` のイディオム）が DFA を呼び出し間で保持
します:

```cpp
class Regex::FindCache {       // opaque。テキスト非依存の状態のみ保持：
  const Regex *owner_;         //   DFA 遷移表 ＋ Scratch 容量
  std::optional<LazyDfa> ...;  // （セグメント化はテキストごとでキャッシュしない）
  Scratch sc_;
};
MatchList find_all(std::string_view, FindCache&) const;
MatchIter find_iter(std::string_view, FindCache&) const;
```

キャッシュなしの `find_iter(s)`/`find_all(s)` は、プロセス一意の `Regex` id で束ねた
**`thread_local` キャッシュ**を再利用します（id は生アドレスキーの ABA ハザードを
回避——破棄された `Regex` のアドレスが再利用されても id が違うので stale DFA は出さ
ない）。`Regex` 内ミュータブルキャッシュ＋mutex（RE2 のモデル）は共有 `Regex` 上の
並行マッチを直列化するため不採用；ここのマッチは lock-free のまま、`Regex` は `const`
で共有可能です。**寿命/スレッド契約**：1 `FindCache` は1スレッドで（共有しない）、
束ねた `Regex` より先に破棄。状態上限に当たったキャッシュは単に後退し続ける——正しく、
ただ非加速。

`MatchIter` は加えて**自身の** `Scratch`（Pike/backtracker 状態）を所有し、共有 warm
DFA を毎ステップ取り直すので、サスペンド点（`++` の境界で呼び出し側が同スレッドで他の
マッチを走らせうる）を跨いでも安全です：別の regex が `thread_local` キャッシュを
束ね直しても再構築のコストで済み、dangling 読みは起きません。

---

## 9. 検証 — 信頼できる正解参照を持たない差分ファジング

正規表現エンジンには**出力の正否を判定できる外部基準（信頼できる正解参照）がありません**。
素直な参照——正しいと信じる別エンジン——が存在しないからです（`std::regex`
は標準ライブラリ間で文字列末尾の `\b` や複雑度上限が異なる；PCRE/RE2 は POSIX vs Perl、
Unicode レベル、空マッチ処理が異なる）。さらに、効くバグは**等価性バグ**——ベース
ラインと食い違うアクセラレータ——で、誘惑的なチェック（エンジン自身の別経路と一致を
assert）は罠：両者が同じディスパッチ・同じコンパイル済みプログラムを通るため**同じ
誤った前提を共有**しうる。

戦略（`test/regexlib_fuzz.cc`、固定 seed `0xC0FFEE`、ASan/UBSan 下で実行）は階層的:

- **層1 — 正解を知らずに検査できる不変条件ゲート（CI を落とす）。** ランダムなパターン/subject は
  クラッシュ/ハング/構築時 `RegexError` 以外の throw をせず、各マッチは自己整合：
  `m.str == subject.substr(m.begin, len)`（と各群）；マッチ時 `scan()[0] == search`；
  マッチは順序付き非重複；`test == search().matched`。これらは*正しいエンジンなら必ず*
  成り立つので、参照無しで検査できる。
- **層2 — DFA-vs-Pike 差分（実際に信頼する正解参照）。** 加速経路を、*同じ*意味論の書記素 Pike
  と照合。Pike はアクセラレータが見通せない変換で**強制**:

  ```cpp
  pike = Regex("(?:" + pat + ")(?:\\b|\\B)");
  ```

  常真の零幅 `(?:\b|\B)` は全位置でマッチし何も消費しないので、プログラムを非
  DFA 可能（`dfa_ok_`/`dfa_assert_ok_` が降りる）にし、この `Regex` は Pike で走り
  ——同じ全体 span にマッチする。scan の全シーケンスを強制 Pike 結果と span 単位
  **かつキャプチャ単位**で比較。これが CRLF 健全性バグを捕えた検査：`gen_subject`
  は意図的に `\r` と `\n` を出し、CR-LF を1クラスタとして扱う*書記素*エンジンだけが、
  それを2と誤るバイトパスを暴ける。
- **層3 — US-vs-EGC。** UnicodeScalar は別のバイトオートマトン；照合先の正解参照は実証済み
  EGC エンジンで、**単一コードポイント・単一書記素**の文字（`a b 1 ␣ é ñ α β 日 A É Α`）
  だけの subject では書記素単位とコードポイント単位が一致するため有効。アルファベットは
  大小ペアを含み `IgnoreCase` 差分が畳み込みを行使（US はコンパイル時、EGC はマッチ
  時に畳む——一致せねばならない）。
- **層4 — 非ASCII assert バイト tier** を強制書記素 Pike と、multiline on/off で照合。
- **層5 — `find_iter` vs `find_all`。** 遅延 `find_iter()` の全シーケンスが先行 `find_all()` と
  一致（全 span・全キャプチャ）——2つの view コンテナは異なる組み立て（`++` ごと1
  ステップ vs 完走）を通る。加えて **`FindCache` 再利用**チェック：subject 列に対し
  単一キャッシュ再利用 vs subject ごと新規が一致せねばならず、跨ぎ状態蓄積を守る。

`std::regex` 差分も保つが**情報用で決してゲートにしない**（意味論が標準ライブラリ間で
異なる）。可搬な意味論回帰コーパス（`regexlib_corpus`）は Python `re` で一度裁定して
焼き込み、実行時に参照エンジン不要。

**設計原則：** 保証は「多くのケースをテストした」ではなく、**各アクセラレータを、その
盲点を共有できないベースラインと照合する**こと——アクセラレータが悪用できない変換で
ベースラインを強制的に登場させる。アクセラレータを追加するとき、その固有の前提を
行使する入力で強制ベースラインと差分照合するまで完了ではない；自己整合チェックは代替
になりません。

---

## 不変条件（譲れない）

- **線形時間 / ReDoS 免疫** — 単一前進パス、逆クランプ、状態上限；無制限バック
  トラックなし。
- **全パターンで leftmost-first** — 順序付き+cut DFA は longest-safe 述語不要なので、
  どのパターン種別も黙って非 Perl な答えにならない。
- **書記素意味論が契約** — クラスはクラスタのベースコードポイントで判定；`.` は1
  クラスタ；オフセットはクラスタ境界。EGC バイトパスは純粋なアクセラレータで、
  `simple_from` / `simple_from_crlf_ok` でゲートし、さもなくば書記素 Pike へ後退。
- **各アクセラレータ == 強制ベースライン** — 差分ファザが常時保証（DFA、バイトパス、
  キャプチャエンジン、プレフィルタ、両 view コンテナ）、span **と**キャプチャを、
  生成 subject に CR/LF と大小ペアを含めて照合。
- **外部依存なし** — Unicode 表はヘッダに生成；プレフィルタは `memchr`/`memcmp` ＋
  手書き SIMD。
- **`Inst` は 16 バイト・trivially copyable** — クラスブロック出力とプログラム成長は
  `memcpy`。
