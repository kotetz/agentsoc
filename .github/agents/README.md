# Copilot Studio エージェント実装

このディレクトリは **Microsoft Copilot Studio エージェントの実装** を格納する場所です。

## ⚠️ 配下の実装ディレクトリは既定で push されません

リポジトリ ルートの [`.gitignore`](../../.gitignore) で `.github/agents/*/` がブロックされています。
各エージェントの実装はテナント固有値 (ワークスペース ID, SharePoint URL, Entra アプリ ClientId 等) を含むため、**ローカル開発のみ** が想定されています。

例外:
- `_template/` — 共有可能な雛形 (push される)
- `README.md` — 本ファイル (push される)

## 推奨ディレクトリ構造

```
.github/agents/<agent-name>/
├── agent.yaml                 # Copilot Studio Agent メタデータ
│                              #   name / description / model / temperature / authentication
├── instructions.md            # システム プロンプト (DETERMINISTIC ルール / 出力スキーマを定義)
├── topics/                    # Copilot Studio トピック (YAML)
│   ├── <main>.yaml
│   └── fallback.yaml
├── actions/                   # 固定 KQL ライブラリ等の参照リソース
│   └── kql-queries.json
├── schemas/                   # 中間データ & 出力の JSON Schema
│   └── evidence-schema.json
├── templates/                 # HTML レポート テンプレート
│   └── report.html
├── deploy/                    # PowerShell + pac CLI による自動デプロイ
│   ├── Deploy-<Agent>.ps1
│   ├── 00-Install-Tools.ps1
│   ├── 01-Provision-SharePoint.ps1
│   ├── 02-Deploy-Solution.ps1
│   ├── 03-Create-CopilotStudio-Agent.md
│   ├── 99-Validate-Deployment.ps1
│   └── flows/                 # Power Automate フロー定義 (Solution 同梱)
│       └── *.flow.json
├── deployment.md              # デプロイ手順 (手動 & 自動)
└── README.md                  # 設計方針 / ファイル構成
```

## 設計方針 (推奨)

LLM の世代 / モデルによる挙動差を最小化するため、エージェント実装では以下を推奨します:

1. **データ アクセスは Sentinel MCP に集約** — `query_lake` ツールに **固定 KQL** を渡す
2. **KQL を LLM に生成させない** — `actions/kql-queries.json` に確定版を保存し、プレースホルダ (`{{upn}}` 等) のみ置換
3. **判定ルールは決定的 (deterministic)** — 「if カウント >= N then SUSPICIOUS」のような数値しきい値を **Power Fx の `if()`** で記述 (LLM 解釈に依存しない)
4. **出力スキーマを JSON で固定** — 自由文章は HTML 内の所定箇所のみ
5. **HTML テンプレートは外部ファイル化** — Power Automate `replace()` でデータ穴埋め
6. **Workspace ID は全 MCP 呼び出しで固定** — 省略すると全接続済みワークスペースが対象になり結果が非決定的

## 自由探索エージェント vs 固定 KQL エージェント

| ユース ケース | 推奨アーキテクチャ |
|---|---|
| **SOC のトリアージ自動化** | 固定 KQL + 決定的 Verdict (LLM 揺らぎ排除が SLA) |
| **アナリストの追加調査支援** | MCP 自由生成 (ガードレール必須: workspaceId 固定 / 除外テーブル / 呼び出し回数上限) |
| **ハンティング (新規 IoC 探索)** | MCP 自由生成 (`query_lake` 呼び出し回数とトークン消費を監査) |

## 関連スキル

エージェント実装の元となるスキル定義は [`../skills/`](../skills/) を参照してください。
スキルは VS Code + GitHub Copilot Chat から直接呼び出せるため、まずスキルとして検証してからエージェント化することを推奨します。
