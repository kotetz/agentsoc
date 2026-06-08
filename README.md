# AI SOC ハーネス — VS Code + GitHub Copilot for Microsoft Sentinel

**SOC アナリストが VS Code + GitHub Copilot から Microsoft Sentinel data lake を調査するための共通ハーネス**です。
Sentinel MCP server / Defender XDR / Power Platform Copilot Studio に対する標準的な調査スキル・プロンプト・テーブル規約を共有します。

---

## 構成

```
.
├── .github/
│   ├── copilot-instructions.md       # 全 SOC エージェントが従う共通指示
│   ├── instructions/                  # KQL 規約・テーブル マップ・レポート出力規約
│   │   ├── kql-conventions.instructions.md
│   │   ├── sentinel-tables.instructions.md
│   │   └── report-output.instructions.md
│   ├── skills/                        # ピボット / トリアージ Skill (pivot-* / triage-*)
│   │   ├── pivot-user/
│   │   ├── pivot-host/
│   │   ├── pivot-ip/
│   │   ├── pivot-url-domain/
│   │   ├── pivot-filehash/
│   │   ├── pivot-email/
│   │   ├── triage-incident/
│   │   ├── triage-signin-anomaly/
│   │   ├── triage-phishing/
│   │   ├── triage-mde-alert/
│   │   ├── triage-mda-alert/
│   │   ├── triage-aws-finding/
│   │   └── triage-sap-anomaly/
│   ├── prompts/                       # 自動化引き渡し プロンプト
│   │   └── handoff-to-secopilot.prompt.md
│   └── agents/                        # Copilot Studio エージェント実装 (.gitignore で個別実装は非公開)
│       └── README.md
├── .vscode/
│   └── mcp.json                       # Sentinel / Learn MCP サーバー定義
├── AGENTS.md                          # マルチ エージェント (GH Copilot / Security Copilot / Studio) 共通ガイダンス
├── README.md                          # 本ファイル
└── .gitignore
```

### このリポジトリで push されるもの

- `.github/copilot-instructions.md` — SOC アナリスト共通の振る舞い規約
- `.github/instructions/*.md` — KQL 規約 / テーブル スキーマ / レポート出力規約 (applyTo パターンで自動適用)
- `.github/skills/*/SKILL.md` — ピボット & トリアージの再利用可能スキル
- `.github/prompts/*.prompt.md` — 自動化引き渡し プロンプト
- `.github/agents/README.md` — エージェント実装の規約 (実装本体は各テナントでローカル管理)
- `.vscode/mcp.json` — MCP サーバー接続定義 (Sentinel data exploration / triage / Learn)
- `AGENTS.md` — マルチ エージェント共通ガイダンス

### push されないもの (`.gitignore`)

- `.github/agents/<実装名>/` — Copilot Studio 実装本体 (テナント固有値を含むため非公開)
- `.github/reports/` — 生成された HTML 調査レポート (アナリスト個別の調査結果)
- `**/deployment-config.json` — デプロイ時に生成されるテナント設定 (ClientId 等)
- `**/*.zip` — Power Platform Solution パッケージ

---

## クイック スタート

### 1. リポジトリをクローン

```powershell
git clone <repo-url> AISoC_Base
cd AISoC_Base
code .
```

### 2. MCP サーバーへの接続を承認

VS Code で `.vscode/mcp.json` を開き、各サーバーの **Start** ボタンをクリック。
初回はブラウザでテナント管理者アカウントでのサインインが求められます。

| MCP サーバー | URL | 用途 |
|---|---|---|
| `SentinelMCP-Data` | `https://sentinel.microsoft.com/mcp/data-exploration` | KQL 実行 / スキーマ取得 |
| `SentinelMCP-Triage` | `https://sentinel.microsoft.com/mcp/triage` | インシデント トリアージ |
| `Learn-MCP` | `https://learn.microsoft.com/api/mcp` | Microsoft Learn 公式ドキュメント |

### 3. ワークスペース ID を環境に合わせて更新

[.github/copilot-instructions.md](.github/copilot-instructions.md) の `CyberSOC` GUID と、各 SKILL.md 内の `workspaceId` をご自身の Sentinel ワークスペースに置き換えてください。

### 4. 調査を開始する

GitHub Copilot Chat で以下のようにスキルを呼び出します:

```
@workspace ピボット対象 IP: 198.51.100.42 を pivot-ip Skill で調査して
```

または:

```
@workspace SecurityIncident 12345 を triage-incident Skill でトリアージして
```

---

## エージェント実装の追加方法

新しい Copilot Studio エージェントを作る場合は以下のディレクトリ規約に従ってください:

```
.github/agents/<agent-name>/
├── agent.yaml                 # エージェント メタデータ
├── instructions.md            # システム プロンプト
├── topics/                    # Copilot Studio トピック
├── actions/                   # KQL クエリ ライブラリ等
├── schemas/                   # JSON Schema
├── templates/                 # HTML レポート テンプレート
├── deploy/                    # PowerShell / pac CLI デプロイ スクリプト
├── deployment.md              # デプロイ手順
└── README.md                  # エージェント概要
```

`.gitignore` により `.github/agents/<agent-name>/` 配下は **既定で push されません**。
共有可能なテンプレート版を作る場合は `.github/agents/_template/` という名前で作成すると push 対象になります。

---

## 関連ドキュメント

- [.github/copilot-instructions.md](.github/copilot-instructions.md) — SOC 共通インストラクション
- [.github/instructions/kql-conventions.instructions.md](.github/instructions/kql-conventions.instructions.md) — KQL コーディング規約
- [.github/instructions/sentinel-tables.instructions.md](.github/instructions/sentinel-tables.instructions.md) — Sentinel テーブル別エンティティ マップ
- [.github/instructions/report-output.instructions.md](.github/instructions/report-output.instructions.md) — HTML レポート出力規約
- [AGENTS.md](AGENTS.md) — マルチ エージェント運用ガイダンス

---

## ライセンス

(必要に応じて追記してください)
