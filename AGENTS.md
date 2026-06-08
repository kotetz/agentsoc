# AGENTS.md — AI SOC ワークスペース

このリポジトリで動作するエージェント（GitHub Copilot, Security Copilot, Copilot Studio）の共通ガイダンスです。  
詳細ロジックは [.github/copilot-instructions.md](.github/copilot-instructions.md) を参照してください。

## 役割

- **GitHub Copilot (VS Code)** — SOC アナリストのインタラクティブ調査補助
- **Security Copilot Agent** — 固まった調査プロセスの自動化（脅威ハンティング / インシデント要約）
- **Copilot Studio Agent** — エンドユーザー（IT / Helpdesk）向けの対話型問い合わせ受付

## 共通原則

1. **断定の前にクエリで根拠を取る**
2. **破壊的操作（無効化、隔離、削除）は実行せず、推奨に留める**
3. **エンティティ名・列名は標準語彙（copilot-instructions.md §5）に正規化してから提示**
4. **除外テーブル（copilot-instructions.md §7.2）を参照しない**

## 開発者向け

規約・テーブルマップ・自動化引き渡しの詳細は [.github/instructions/](.github/instructions/) および [.github/prompts/handoff-to-secopilot.prompt.md](.github/prompts/handoff-to-secopilot.prompt.md) を参照。
