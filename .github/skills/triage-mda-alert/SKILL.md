---
name: triage-mda-alert
description: Microsoft Defender for Cloud Apps (MDA) アラートのトリアージ。クラウド アプリの異常活動・OAuth 同意・大量ダウンロード等を確認する。
---

# triage-mda-alert — MDA アラート トリアージ

## いつ使うか
- `ServiceSource == "Microsoft Defender for Cloud Apps"`
- 異常な OAuth 同意、Impossible Travel (MDA 検出), 大量ダウンロード等

## 入力
- `alertId` または `accountObjectId`, `application`
- `windowStart` / `windowEnd`

## 出力
1. **アラート詳細**
2. **対象ユーザーの全 SaaS 操作**
3. **OAuth 同意状況**
4. **データ アクセス／ダウンロード サマリ**
5. **連動 Entra Audit**
6. **判定 & 推奨**

## 実行手順

### Step 1: アラート詳細
```kql
let aid = "<alertId>";
AlertInfo
| where AlertId == aid
| join kind=leftouter (AlertEvidence | where AlertId == aid) on AlertId
| project TimeGenerated, AlertId, Title, Severity, Category, AttackTechniques,
          AccountUpn, AccountObjectId, RemoteIP, OAuthApplicationId, CloudResource, CloudPlatform
```

### Step 2: 対象ユーザーの SaaS 操作
```kql
let oid = "<AccountObjectId>"; let s = datetime(<start>); let e = datetime(<end>);
CloudAppEvents
| where TimeGenerated between (s .. e) and AccountObjectId == oid
| mv-expand Obj = ActivityObjects
| extend ObjRole = tostring(Obj.Role), ObjType = tostring(Obj.Type), ObjName = tostring(Obj.Name)
| project TimeGenerated, Application, ActionType, ActivityType,
          IPAddress, CountryCode, City, UserAgent,
          ObjRole, ObjType, ObjName, RawEventData
| order by TimeGenerated asc
```

### Step 3: OAuth 同意確認（Entra Audit）
```kql
let upn = tolower("<upn>"); let oid = "<oid>";
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant", "Add app role assignment grant to user")
| where tostring(InitiatedBy.user.id) == oid or tolower(tostring(InitiatedBy.user.userPrincipalName)) == upn
| mv-expand Target = TargetResources
| project TimeGenerated, OperationName, Result,
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          TargetId = tostring(Target.id),
          TargetType = tostring(Target.type),
          TargetName = tostring(Target.displayName),
          ModifiedProperties = tostring(Target.modifiedProperties)
| order by TimeGenerated desc
```

### Step 4: 大量ダウンロード判定
```kql
let oid = "<oid>"; let s = datetime(<start>); let e = datetime(<end>);
CloudAppEvents
| where TimeGenerated between (s .. e) and AccountObjectId == oid
| where ActionType has_any ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| summarize Count = count(), Apps = make_set(Application, 5), Files = make_set(ObjectName, 50)
        by bin(TimeGenerated, 15m)
| where Count > 50
```

### Step 5: 連動 OfficeActivity（同時刻）
```kql
let upn = tolower("<upn>"); let s = datetime(<start>); let e = datetime(<end>);
OfficeActivity
| where TimeGenerated between (s .. e)
| where tolower(UserId) == upn or tolower(MailboxOwnerUPN) == upn
| project TimeGenerated, RecordType, Operation, OfficeWorkload, ClientIP,
          OfficeObjectId, ResultStatus
| order by TimeGenerated desc
```

## 判定マトリクス
| 観測 | 判定 |
|---|---|
| 異常 OAuth 同意 + 危険スコープ (Mail.Read, Files.Read.All) | 永続化、即取消 |
| Impossible travel + 大量ダウンロード | 漏洩疑い |
| Mailbox Rule 追加 (Forward/Move) | 横展開・情報窃取 |

## 推奨アクション
- [人手判断] OAuth 同意取消、Service Principal 監査
- [人手判断] Mailbox Rule 削除確認
- [人手判断] アカウント停止 → `pivot-user` で影響範囲確認
