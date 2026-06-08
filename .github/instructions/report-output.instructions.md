---
applyTo: "**"
---

# 調査レポート出力規約（HTML）

SOC 調査の **最終レポート** および **要約サマリ** は本規約に従って **HTML** で出力する。  
（インタラクティブな探索チャットの中間応答は通常の Markdown で構わない。「レポート」「サマリ」「結果まとめ」を求められた場合に本規約を適用。）

---

## 1. 出力形式

- 単一の **`<!DOCTYPE html>` を含む完結した HTML ドキュメント** をコード フェンス `````html ... ````` で囲んで出力する
- 外部 CDN（D3.js のみ許可）以外の外部リソースは参照しない（CSS / フォント / 画像はインライン）
- ファイル保存を求められた場合は `.github/reports/<timestamp>-<topic>.html` または指定パスへ出力

---

## 2. デザイン テーマ（白ベース・クール）

### カラー パレット（CSS 変数で定義）

```css
:root {
  --bg:        #ffffff;
  --surface:   #f7f9fc;
  --border:    #e5e9f0;
  --text:      #1f2937;   /* slate-800 */
  --text-mute: #64748b;   /* slate-500 */
  --accent:    #2563eb;   /* blue-600 */
  --accent-2:  #0891b2;   /* cyan-600 */
  --success:   #059669;   /* emerald-600 */
  --warn:      #d97706;   /* amber-600 */
  --danger:    #dc2626;   /* red-600 */
  --critical:  #7c3aed;   /* violet-600 */
  --grid:      #eef2f7;
  --shadow:    0 1px 2px rgba(15,23,42,.04), 0 4px 12px rgba(15,23,42,.06);
  --radius:    10px;
}
```

### 重要度別カラー マッピング（厳守）
| Severity | 色 |
|---|---|
| Critical | `var(--critical)` |
| High | `var(--danger)` |
| Medium | `var(--warn)` |
| Low | `var(--accent-2)` |
| Informational | `var(--text-mute)` |

### タイポグラフィ
- `font-family: -apple-system, "Segoe UI", "Hiragino Sans", "Yu Gothic UI", sans-serif`
- 等幅: `"SF Mono", "Cascadia Mono", Consolas, monospace`
- 本文: 14px / 行間 1.6
- 見出し: `h1` 24px (font-weight 600), `h2` 18px, `h3` 15px、`letter-spacing: -0.01em`

### レイアウト原則
- 余白を多めに（カード `padding: 20px`, セクション間 `margin-bottom: 24px`）
- ボーダーは細く（`1px solid var(--border)`）、影は控えめ
- カード形式: `border-radius: var(--radius); background: var(--bg); box-shadow: var(--shadow);`
- 装飾過多禁止。情報密度優先

---

## 3. 必須セクション構造

```html
<body>
  <header>
    <h1>{調査タイトル}</h1>
    <div class="meta">
      <span>Incident: #{IncidentNumber} (XDR: {ProviderIncidentId})</span>
      <span>Generated: {ISO8601}</span>
      <span>Analyst: GitHub Copilot</span>
    </div>
    <div class="meta meta-runtime">
      <span>Model: {LLM 名 / バージョン} (例: Claude Opus 4.7)</span>
      <span>Credits used: {消費 credit 数}</span>
    </div>
  </header>
```

### 3.1 ランタイム メタ（必須）

レポート ヘッダー直下に **エージェントが使用した LLM 名と消費 credit** を必ず記載する。

- **Model**: 「自分は何のモデルを使っているか？」と尋ねられた時に答える値と同一の名称。バージョンやプロバイダが分かる場合は併記（例: `Claude Opus 4.7 (GitHub Copilot)`）。
- **Credits used**: 当該レポート生成セッションで消費した GitHub Copilot Premium Request の累計概算。正確な値が取得できない場合は `不明 (n/a)` と明記し、推測値は出力しない。
- HTML 中の表現は `<div class="meta meta-runtime">` を使い、本文と視覚的に区別する（フォント サイズ 12px / `color: var(--text-mute)` を推奨）。

```html
  <section id="summary">     <!-- TL;DR と verdict バッジ -->
  <section id="entities">    <!-- 抽出エンティティ一覧 -->
  <section id="timeline">    <!-- SVG タイムライン -->
  <section id="evidence">    <!-- 根拠クエリと結果 -->
  <section id="graph">       <!-- D3 関係グラフ（任意） -->
  <section id="recommendations">  <!-- 推奨アクション -->
  <footer>
    <small>Source: Sentinel Data Lake. Queries reproducible via attached KQL.</small>
  </footer>
</body>
```

### Verdict バッジ
```html
<span class="badge badge-malicious">MALICIOUS</span>  <!-- danger color -->
<span class="badge badge-suspicious">SUSPICIOUS</span> <!-- warn color -->
<span class="badge badge-benign">BENIGN</span>         <!-- success color -->
```

---

## 4. グラフィカル表現

### 優先順位
1. **シンプルな統計 → インライン SVG** (棒グラフ・ドーナツ・スパークライン)
2. **関係性 / タイムライン** → **D3.js v7** (CDN: `https://cdn.jsdelivr.net/npm/d3@7`)
3. 表で十分な情報 → 表（無理にグラフ化しない）

### インライン SVG パターン

**カウンタ バッジ（KPI カード）**
```html
<div class="kpi">
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="var(--danger)" stroke-width="2">
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
  </svg>
  <span class="kpi-value">12</span>
  <span class="kpi-label">High Alerts</span>
</div>
```

**ドーナツ（Severity 分布）**
```html
<svg viewBox="0 0 100 100" width="120">
  <!-- circumference = 2πr ≒ 251.3 (r=40)。stroke-dasharray で割合表現 -->
  <circle cx="50" cy="50" r="40" fill="none" stroke="var(--grid)" stroke-width="14"/>
  <circle cx="50" cy="50" r="40" fill="none" stroke="var(--danger)" stroke-width="14"
          stroke-dasharray="75 251.3" transform="rotate(-90 50 50)"/>
</svg>
```

### D3.js パターン

**Force-directed エンティティ関係グラフ**
- ノード: ユーザー(青) / デバイス(シアン) / IP(オレンジ) / URL(灰) / ファイル(紫)
- ノード半径: 関連アラート数で `d3.scaleSqrt`
- 配色は §2 のパレットを **CSS 変数経由** で参照（D3 内では `getComputedStyle(document.documentElement).getPropertyValue('--accent')`）

**タイムライン (ミニ ガント)**
- 軸: `d3.scaleTime()` で `FirstActivityTime → LastActivityTime`
- 各アラート / イベントを行ごとにストリップ表示
- ホバーで詳細ツールチップ（純粋 SVG `<title>` でも可）

### グラフ実装の必須要件
- `<svg role="img" aria-label="...">` でアクセシビリティ ラベル付与
- 凡例必須（色 = 意味のキー）
- レスポンシブ: `width: 100%; height: auto` または `viewBox` 使用

---

## 5. 表（KQL 結果テーブル）

```html
<table>
  <thead><tr><th>TimeGenerated</th><th>UserUpn</th><th>IpAddress</th>...</tr></thead>
  <tbody>...</tbody>
</table>
```

CSS:
```css
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { background: var(--surface); color: var(--text-mute); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em; }
tr:hover td { background: var(--surface); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.mono { font-family: var(--font-mono); font-size: 12px; color: var(--text-mute); }
```

---

## 6. KQL コード ブロック

```html
<details>
  <summary>KQL クエリ (再現用)</summary>
<pre><code class="kql">SecurityIncident
| where TimeGenerated > ago(1d)
...
</code></pre>
</details>
```

CSS:
```css
pre { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      padding: 14px; overflow-x: auto; font-size: 12.5px; line-height: 1.55; }
code { font-family: var(--font-mono); color: var(--text); }
```

---

## 7. 推奨アクション ブロック

各アクションを **「人手判断」/「自動化候補」** で明示区別する:

```html
<div class="action action-manual">
  <span class="action-tag">人手判断</span>
  <span class="action-text">対象ユーザーの MFA をリセットし、全セッションをサインアウト</span>
</div>
<div class="action action-auto">
  <span class="action-tag">AUTOMATION_CANDIDATE</span>
  <span class="action-text">IP <code>198.51.100.42</code> を Conditional Access で一時ブロック</span>
</div>
```

---

## 8. アクセシビリティ & 印刷

- `<html lang="ja">` を明示
- 色だけに依存しない（テキスト ラベル併記）
- `@media print { /* 影を消す, モノクロでも判別可能に */ }` を 1 ブロック含める
