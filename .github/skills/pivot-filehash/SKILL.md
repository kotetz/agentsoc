---
name: pivot-filehash
description: 単一のファイル ハッシュ (SHA256 / SHA1 / MD5) から、エンドポイント・メール添付・アラートの全テーブルを横断調査する。
---

# pivot-filehash — ファイル ハッシュ 横断ピボット

## いつ使うか
- マルウェア検出後の拡散範囲確認
- IOC ハッシュの組織内ヒット確認

## 入力
- `target`: ハッシュ値（小文字推奨）
- `hashType`: `sha256` / `sha1` / `md5` （省略可、長さで自動判別）
- `lookback` (optional): 既定 `7d`

## 出力
1. **TI 確認**
2. **エンドポイント実行 / 書き込み履歴**
3. **メール添付**
4. **アラート連動**
5. **証明書 / 署名者**
6. **推奨アクション**

## 実行手順

### Step 0: ハッシュ正規化
```kql
let raw = tolower("<hash>");
let isSha256 = strlen(raw) == 64;
let isSha1   = strlen(raw) == 40;
let isMd5    = strlen(raw) == 32;
```

### Step 1: TI
```kql
let h = tolower("<hash>");
ThreatIntelIndicators
| where IsActive == true
| where ObservableValue == h
| project ObservableKey, ObservableValue, Confidence, ValidFrom, ValidUntil, Description, Pattern
```

### Step 2: エンドポイント（実行・書き込み・ロード）
```kql
let h = tolower("<hash>");
union withsource=SourceTable
    (DeviceProcessEvents | where TimeGenerated > ago(7d) | where SHA256 == h or SHA1 == h or MD5 == h),
    (DeviceFileEvents | where TimeGenerated > ago(7d) | where SHA256 == h or SHA1 == h or MD5 == h),
    (DeviceImageLoadEvents | where TimeGenerated > ago(7d) | where SHA256 == h or SHA1 == h),
    (DeviceEvents | where TimeGenerated > ago(7d) | where SHA256 == h or SHA1 == h or MD5 == h)
| extend FileNameOut = coalesce(FileName, InitiatingProcessFileName),
         PathOut = coalesce(FolderPath, InitiatingProcessFolderPath)
| summarize Count = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Devices = make_set(DeviceName, 30),
            Accounts = make_set(coalesce(AccountUpn, InitiatingProcessAccountUpn), 20),
            Paths = make_set(PathOut, 10),
            FileNames = make_set(FileNameOut, 10),
            Actions = make_set(ActionType, 10)
        by SourceTable
```

### Step 3: メール添付
```kql
let h = tolower("<hash>");
EmailAttachmentInfo
| where TimeGenerated > ago(14d)
| where SHA256 == h
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, DeliveryAction, ThreatTypes) on NetworkMessageId
| project TimeGenerated, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, Subject, DeliveryAction, ThreatTypes
| order by TimeGenerated desc
```

### Step 4: アラート連動
```kql
let h = tolower("<hash>");
AlertEvidence
| where TimeGenerated > ago(30d)
| where SHA256 == h or SHA1 == h
| join kind=leftouter (AlertInfo | where TimeGenerated > ago(30d)) on AlertId
| project TimeGenerated, AlertId, Title, Severity, Category, ServiceSource, DeviceName, AccountUpn, EvidenceRole
| order by TimeGenerated desc
```

### Step 5: 証明書情報
```kql
let h = tolower("<hash>");
DeviceFileCertificateInfo
| where TimeGenerated > ago(30d) and SHA1 == h
| project TimeGenerated, DeviceName, Signer, Issuer, IsTrusted, IsSigned, IsRootSignerMicrosoft, SignatureType
| order by TimeGenerated desc
```

## 解釈ガイド
- **1 端末・1 ユーザーのみ** → 標的型または初期感染段階
- **複数端末で同時拡散** → ワーム的、緊急隔離
- **メール添付経由 + クリック後実行** → フィッシング由来
- **正規署名あり** → サプライ チェーン or ASR 例外悪用

## 推奨アクション
| 観測 | 推奨 | 種別 |
|---|---|---|
| 既知マルウェア + 複数端末 | 一斉隔離 + IOC ブロック | 人手判断 |
| 添付経由 1 件 | メール削除 + ユーザー教育 | 人手判断 |
| TI のみ ヒットなし | 環境ブロック リスト追加 | `# AUTOMATION_CANDIDATE` |
