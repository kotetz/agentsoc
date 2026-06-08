---
name: triage-mde-alert
description: Microsoft Defender for Endpoint (MDE) アラートのトリアージ。プロセス ツリー・ネットワーク・ファイル操作を時系列で確認し、誤検知判定とラテラル ムーブメント確認を行う。
---

# triage-mde-alert — MDE アラート トリアージ

## いつ使うか
- `ServiceSource == "Microsoft Defender for Endpoint"` のアラート
- MDE Live Response 後の事後分析

## 入力
- `alertId`
- 抽出された `DeviceId`, `AccountUpn`, `SHA256` 等

## 出力
1. **アラート詳細**
2. **当該プロセスのプロセス ツリー**
3. **同時刻のネットワーク・ファイル イベント**
4. **同端末の他アラート連動**
5. **同 SHA256 の組織内拡散**
6. **判定 & 推奨**

## 実行手順

### Step 1: アラート詳細
```kql
let aid = "<alertId>";
AlertInfo
| where AlertId == aid
| join kind=leftouter (AlertEvidence | where AlertId == aid) on AlertId
| project TimeGenerated, AlertId, Title, Severity, Category, AttackTechniques,
          DeviceId, DeviceName, AccountUpn, FileName, SHA256, RemoteIP, RemoteUrl,
          EvidenceRole, EvidenceDirection
```

### Step 2: プロセス ツリー（前後 5 分）
```kql
let did = "<DeviceId>"; let t = datetime(<alertTime>);
DeviceProcessEvents
| where TimeGenerated between (t - 5m .. t + 5m) and DeviceId == did
| project TimeGenerated, DeviceName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          ParentUniqueId = InitiatingProcessUniqueId,
          Child = FileName, ChildCmd = ProcessCommandLine, ChildUniqueId = ProcessUniqueId,
          AccountUpn, SHA256
| order by TimeGenerated asc
```

### Step 3: 同時刻のネットワーク・ファイル
```kql
let did = "<DeviceId>"; let puid = "<ProcessUniqueId>"; let t = datetime(<alertTime>);
union withsource=SourceTable
    (DeviceNetworkEvents | where TimeGenerated between (t - 5m .. t + 5m) and DeviceId == did and InitiatingProcessUniqueId == puid),
    (DeviceFileEvents | where TimeGenerated between (t - 5m .. t + 5m) and DeviceId == did and InitiatingProcessUniqueId == puid),
    (DeviceRegistryEvents | where TimeGenerated between (t - 5m .. t + 5m) and DeviceId == did and InitiatingProcessUniqueId == puid)
| order by TimeGenerated asc
```

### Step 4: 同端末の他アラート（直近 7 日）
```kql
let did = "<DeviceId>"; let aid = "<alertId>";
AlertEvidence
| where TimeGenerated > ago(7d) and DeviceId == did and AlertId != aid
| join kind=leftouter (AlertInfo) on AlertId
| project TimeGenerated, AlertId, Title, Severity, Category, ServiceSource
| order by TimeGenerated desc
```

### Step 5: SHA256 の組織内拡散
→ `pivot-filehash` を呼び出す。

## 判定マトリクス
| 観測 | 判定 |
|---|---|
| 親プロセス = Office アプリ + 子プロセス = PowerShell/wscript | マクロ実行、要 `pivot-host` |
| 既知 LOLBin + Encoded コマンドライン | 高確度悪性 |
| アンインストーラ／管理ツール由来 | 業務利用の可能性、誤検知判定 |
| RemoteIP が TI 一致 | C2 通信確定 |

## 推奨アクション
- [人手判断] 当該プロセス停止 → 端末隔離
- [人手判断] SHA256 を `Indicators` に追加（カスタム ブロック）
- [`# AUTOMATION_CANDIDATE`] 同 SHA256 の他端末スキャン トリガー
