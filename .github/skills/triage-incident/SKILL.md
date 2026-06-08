---
name: triage-incident
description: SecurityIncident を起点に AlertEvidence で全エンティティを展開し、関連 Pivot Skill を呼び出すための初動トリアージ。
---

# triage-incident — インシデント 起点 トリアージ

## いつ使うか
- `SecurityIncident` の IncidentNumber 指定でアナリストが調査を開始する時の **第一手**
- Defender XDR ポータル URL (`https://security.microsoft.com/incident2/<XdrId>`) から Sentinel 側を引き当てる時

## 入力
- `incidentNumber` (int, Sentinel 側) または `incidentName`
- もしくは `xdrIncidentId` (string, Defender XDR 側、`ProviderIncidentId` と同値)
- `lookback` (optional): 既定 `7d`（インシデント作成時刻 ± 範囲）

## Sentinel ⇄ XDR インシデント ID 対応

本テナントは Defender XDR と Sentinel が**統合済**で、`SecurityIncident` の全行が `ProviderName == "Microsoft XDR"`。1 件のインシデントが 2 種類の ID を持つ:

| 用途 | 列 / 取得方法 | 例 |
|---|---|---|
| **Sentinel ID** (アナリスト連絡で使用) | `IncidentNumber` (int) | `60404` |
| **XDR ID** (Defender ポータルで使用) | `ProviderIncidentId` (string) | `93618` |
| Sentinel URL | `IncidentUrl` | `https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/...` |
| XDR URL | `tostring(AdditionalData.providerIncidentUrl)` | `https://security.microsoft.com/incident2/93618/overview?tid=<tenantId>` |
| 元プロダクト | `tostring(AdditionalData.alertProductNames)` | `["Microsoft 365 Defender","Office 365 Advanced Threat Protection","Azure Security Center",...]` |

### XDR ID → Sentinel ID 解決
```kql
let xdrId = "<XdrIncidentId>";  // 例: "93618"
SecurityIncident
| where TimeGenerated > ago(30d)
| where ProviderIncidentId == xdrId
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, XdrIncidentId = ProviderIncidentId, Title, Severity, Status,
          SentinelUrl = IncidentUrl,
          XdrUrl = tostring(AdditionalData.providerIncidentUrl),
          AlertProducts = tostring(AdditionalData.alertProductNames)
```

### Sentinel ID → XDR ID 解決
```kql
let inum = <IncidentNumber>;
SecurityIncident
| where TimeGenerated > ago(30d)
| where IncidentNumber == inum
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, XdrIncidentId = ProviderIncidentId,
          SentinelUrl = IncidentUrl,
          XdrUrl = tostring(AdditionalData.providerIncidentUrl)
```

> ⚠️ `IncidentName` (GUID) は Sentinel 内部 ID で、XDR ID と無関係。アナリスト連絡時は **`IncidentNumber` と `ProviderIncidentId` の両方** を必ず併記する。

## 出力
1. **インシデント メタ**
2. **アラート一覧 (`AlertInfo`)**
3. **証拠エンティティ展開 (`AlertEvidence`)**
4. **エンティティ別調査の推奨 Pivot Skill**
5. **重要度判定 & 推奨初動**

## 実行手順

### Step 1: インシデント取得
```kql
let inum = <incidentNumber>;
SecurityIncident
| where TimeGenerated > ago(30d)
| where IncidentNumber == inum
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, IncidentName=Title, Status, Severity, Classification, ClassificationReason,
          CreatedTime, FirstActivityTime, LastActivityTime,
          AlertIds, BookmarkIds, RelatedAnalyticRuleIds, Owner, AdditionalData
```

### Step 2: アラート展開
```kql
let inum = <incidentNumber>;
let alertIds = toscalar(SecurityIncident
    | where IncidentNumber == inum
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project AlertIds);
AlertInfo
| where TimeGenerated > ago(30d)
| where AlertId in (alertIds)
| project TimeGenerated, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques
| order by TimeGenerated desc
```

### Step 3: 証拠エンティティ（**AlertEvidence ハブ**）
```kql
let inum = <incidentNumber>;
let alertIds = toscalar(SecurityIncident
    | where IncidentNumber == inum
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project AlertIds);
AlertEvidence
| where TimeGenerated > ago(30d)
| where AlertId in (alertIds)
| project TimeGenerated, AlertId, EntityType, EvidenceRole, EvidenceDirection,
          AccountUpn, AccountObjectId, AccountSid, AccountName, AccountDomain,
          DeviceId, DeviceName,
          FileName, SHA256, FolderPath,
          RemoteIP, LocalIP, RemoteUrl,
          NetworkMessageId, EmailSubject,
          OAuthApplicationId, CloudResource, CloudPlatform,
          AdditionalFields
| order by TimeGenerated desc
```

### Step 4: エンティティ サマリ
```kql
// Step 3 の結果から要約
AlertEvidence
| where AlertId in (<alertIds>)
| summarize 
    Users = make_set(AccountUpn, 20),
    UserOids = make_set(AccountObjectId, 20),
    Devices = make_set(DeviceName, 20),
    DeviceIds = make_set(DeviceId, 20),
    Files = make_set(SHA256, 20),
    IPs = make_set(coalesce(RemoteIP, LocalIP), 20),
    Urls = make_set(RemoteUrl, 20),
    Emails = make_set(NetworkMessageId, 20),
    OAuthApps = make_set(OAuthApplicationId, 20)
```

## ピボット推奨マトリクス

抽出したエンティティに応じて次の Skill を呼び出す。

| エンティティ | 推奨 Skill |
|---|---|
| `AccountUpn` / `AccountObjectId` あり | `pivot-user` |
| `DeviceId` / `DeviceName` あり | `pivot-host` |
| `RemoteIP` / `LocalIP` あり | `pivot-ip` |
| `RemoteUrl` あり | `pivot-url-domain` |
| `SHA256` / `SHA1` あり | `pivot-filehash` |
| `NetworkMessageId` あり | `pivot-email` |

## カテゴリ別 専門 Triage への引き渡し

`AlertInfo.Category` / `ServiceSource` を見て以下を呼び出す:

| Category / ServiceSource | 専門 Triage |
|---|---|
| `InitialAccess` + Sign-in 系 | `triage-signin-anomaly` |
| `Phish` / メール 関連 | `triage-phishing` |
| `Microsoft Defender for Endpoint` | `triage-mde-alert` |
| `Microsoft Defender for Cloud Apps` | `triage-mda-alert` |
| AWS GuardDuty / CloudTrail 関連 | `triage-aws-finding` |
| SAP 関連 | `triage-sap-anomaly` |

## 重要度判定ヒント
- **High Severity + 複数エンティティ侵害** → 即時エスカレーション
- **複数アラートが同一ユーザー** → アカウント侵害シナリオ
- **同一 IP / Device が複数インシデントで再発** → 持続性脅威

## 出力テンプレート
```
インシデント #<N> "<Name>" — Severity: <S>

主要エンティティ:
- ユーザー: <list>
- デバイス: <list>
- IP: <list>
- URL: <list>
- ファイル: <list>
- メール: <list>

次の調査:
1. pivot-user("<upn>")  ← ユーザー侵害確認
2. pivot-host("<device>") ← ラテラル ムーブメント確認
3. ...

初動推奨:
- [人手判断] MFA リセット
- [# AUTOMATION_CANDIDATE] IP ブロック
```
