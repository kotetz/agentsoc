---
mode: agent
description: VS Code + Copilot で固まった調査ロジックを Security Copilot Agent / Copilot Studio Agent に移植するための仕様書を生成する。
---

# handoff-to-secopilot — 自動化引き渡し プロンプト

VS Code 上で複数回検証したトリアージ / ピボット フローを **Security Copilot Agent** または **Copilot Studio Agent** に移植する際の仕様書テンプレートです。  
本プロンプトを実行すると、以下の構造で出力します。

---

## 入力（ユーザーから収集）

- `skillName`: 対象 Skill 名 (例: `triage-signin-anomaly`)
- `targetAgent`: `Security Copilot` / `Copilot Studio` のどちら
- `validationCount`: VS Code で同フローを実行した回数（3 回以上推奨）
- `falsePositiveNotes`: 既知の誤検知パターン

---

## 移植可否チェック リスト（必ず先に提示）

- [ ] 同じ判断パスを **3 回以上** 実行した
- [ ] 入力スキーマが固定 (UPN / IP / Hash 等の型と必須性)
- [ ] 出力スキーマが固定 (アナリストが必要とする項目)
- [ ] 「人手判断必須」分岐を明示的に分離した
- [ ] 誤検知時の影響が許容範囲

**いずれかが未達** → 移植を保留し、追加検証を推奨。

---

## 出力構造（仕様書）

````markdown
# Agent 仕様書: <skillName>

## 1. 目的とスコープ
- ターゲット: <Security Copilot / Copilot Studio>
- 想定起動: <例: SOAR から IncidentNumber を渡されて起動>
- 期待実行時間: <例: < 60 秒>

## 2. 入力スキーマ
```json
{
  "type": "object",
  "properties": {
    "userUpn":   { "type": "string", "format": "email" },
    "windowStart": { "type": "string", "format": "date-time" },
    "windowEnd":   { "type": "string", "format": "date-time" }
  },
  "required": ["userUpn"]
}
```

## 3. データ ソース
| データ | 方法 | 備考 |
|---|---|---|
| Sentinel Data Lake | KQL Plugin | 既存 |
| Defender XDR | 標準 Plugin | 既存 |
| Entra ID | Graph Plugin | 既存 |

## 4. 実行フロー (Promptbook)
```
[Step 1] KQL: <Step 1 のクエリ>
[Step 2] 結果が空でなければ: KQL <Step 2 のクエリ>
[Step 3] 判定: ...
[Step 4] 出力テンプレート整形
```

## 5. 出力スキーマ
```json
{
  "verdict": "BENIGN | SUSPICIOUS | MALICIOUS",
  "confidence": 0.0,
  "evidence": [ {"type": "...", "value": "...", "source": "..."} ],
  "recommendations": [
    {"action": "...", "automated": false, "rationale": "..."}
  ]
}
```

## 6. ガード レール
- 破壊的操作（無効化、隔離、削除）は **実行しない**
- 推奨に留め、`automated=false` でマーク
- 高 Severity 判定時は SOC アナリストへ通知 (Teams Webhook)

## 7. 誤検知パターン（既知）
- <例: 業務時間外サインインだが出張中ユーザー>

## 8. 評価指標
- True Positive Rate
- False Positive Rate
- Mean Time to Triage

## 9. ロールバック手順
- Agent を `Disabled` 状態に戻す
- VS Code フローへフォールバック

## 10. 関連ファイル
- 元 Skill: `.github/skills/<skillName>/SKILL.md`
- KQL 規約: `.github/instructions/kql-conventions.instructions.md`
````

---

## 使い方

1. このプロンプトを Chat で実行
2. プロンプトから求められた入力（`skillName` 等）を回答
3. 出力された仕様書を Security Copilot Workspace / Copilot Studio に貼り付け
4. KQL ブロックは Plugin 上で実行可能化、出力 JSON はチャネル整形
