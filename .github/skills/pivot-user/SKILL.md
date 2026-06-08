---
name: pivot-user
description: 単一のユーザー識別子（UPN / ObjectId / SID / SAM / メール）から、Identity・Endpoint・Email・Cloud・Network・SAP の全テーブルを横断調査する。出力は標準語彙 (UserUpn, UserObjectId, IpAddress, DeviceName 等) に正規化済み。
---

# pivot-user — ユーザー横断ピボット

## いつ使うか
- アラートやインシデントから抽出された **単一ユーザー** の活動を全データソースで確認したい
- 漏洩疑い／インサイダーの初動調査
- パスワード スプレー被害者の影響範囲確認

## 入力
- `target`: UPN / メール / ObjectId / SID / SAM のいずれか 1 つ
- `lookback` (optional): 既定 `7d`

## 出力
1. **ID 解決テーブル** (IdentityInfo より全エイリアス)
2. **サインイン サマリ** (国・IP・デバイス・成功失敗)
3. **クラウド アプリ操作サマリ** (CloudAppEvents / OfficeActivity / AzureActivity)
4. **エンドポイント活動** (DeviceLogonEvents / DeviceProcessEvents)
5. **メール送受信** (EmailEvents 直近)
6. **UEBA 異常** (BehaviorAnalytics / Anomalies)
7. **TI ヒット** (ThreatIntelIndicators との IP 突合)
8. **推奨アクション**

## 実行手順

### Step 1: ID 解決（IdentityInfo ハブ）
```kql
let target = "<target>";
let id = IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | where tolower(AccountUPN) == tolower(target)
         or tolower(MailAddress) == tolower(target)
         or AccountObjectId == target
         or AccountSID == target
         or tolower(SAMAccountName) == tolower(tostring(split(target,"@")[0]))
         or AdditionalMailAddresses has tolower(target)
    | project AccountUPN, AccountObjectId, AccountSID, AccountCloudSID,
              SAMAccountName, AccountDomain, MailAddress, AdditionalMailAddresses,
              JobTitle, Department, Manager, IsAccountEnabled, RiskLevel;
id
```
> 解決した `AccountUPN` / `AccountObjectId` / `AccountSID` / `SAMAccountName` を後続の `let upn = "..."; let oid = "..."; ...` で固定する。

### Step 2: サインイン
```kql
let upn = "<resolved UPN>"; let oid = "<resolved ObjectId>";
union withsource=SourceTable
    (SigninLogs | where TimeGenerated > ago(7d) | where tolower(UserPrincipalName) == upn or UserId == oid),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(7d) | where tolower(UserPrincipalName) == upn or UserId == oid)
| extend Country = tostring(LocationDetails.countryOrRegion),
         City = tostring(LocationDetails.city),
         DeviceIdStr = tostring(DeviceDetail.deviceId),
         OS = tostring(DeviceDetail.operatingSystem)
| summarize SignIns = count(),
            FailedCount = countif(ResultType != 0),
            Apps = make_set(AppDisplayName, 20),
            IPs = make_set(IPAddress, 20),
            Countries = make_set(Country, 10),
            Devices = make_set(DeviceIdStr, 10)
        by SourceTable, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

### Step 3: AuditLogs（管理操作・変更）
```kql
let upn = "<upn>"; let oid = "<oid>";
AuditLogs
| where TimeGenerated > ago(7d)
| where tostring(InitiatedBy.user.id) == oid
     or tolower(tostring(InitiatedBy.user.userPrincipalName)) == upn
| project TimeGenerated, OperationName, Category, Result,
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          ActorIP = tostring(InitiatedBy.user.ipAddress),
          TargetSummary = tostring(TargetResources)
| order by TimeGenerated desc
| take 200
```

### Step 4: クラウド アプリ
```kql
let upn = "<upn>"; let oid = "<oid>";
union withsource=SourceTable
    (CloudAppEvents | where TimeGenerated > ago(7d) | where AccountObjectId == oid or tolower(AccountId) == upn),
    (OfficeActivity | where TimeGenerated > ago(7d) | where tolower(UserId) == upn or tolower(MailboxOwnerUPN) == upn),
    (AzureActivity | where TimeGenerated > ago(7d) | where tolower(Caller) == upn)
| extend IpAddress = coalesce(tostring(IPAddress), tostring(ClientIP), tostring(CallerIpAddress))
| summarize Count = count(), Apps = make_set(coalesce(Application, OperationNameValue, OperationName), 10), IPs = make_set(IpAddress, 10)
        by SourceTable, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

### Step 5: エンドポイント活動
```kql
let upn = "<upn>"; let sid = "<sid>"; let sam = "<sam>";
union withsource=SourceTable
    (DeviceLogonEvents | where TimeGenerated > ago(7d) | where tolower(AccountName) == sam or AccountSid == sid),
    (DeviceProcessEvents | where TimeGenerated > ago(7d) | where tolower(AccountUpn) == upn or AccountSid == sid),
    (IdentityLogonEvents | where TimeGenerated > ago(7d) | where tolower(AccountUpn) == upn or tolower(TargetAccountUpn) == upn)
| summarize Count = count(), Devices = make_set(DeviceName, 20)
        by SourceTable, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

### Step 6: メール送受信（EmailEvents は大規模なのでサマリ）
```kql
let upn = "<upn>";
EmailEvents
| where TimeGenerated > ago(7d)
| where tolower(RecipientEmailAddress) == upn or tolower(SenderFromAddress) == upn
| summarize Inbound = countif(tolower(RecipientEmailAddress) == upn),
            Outbound = countif(tolower(SenderFromAddress) == upn),
            Threats = countif(ThreatTypes != ""),
            Blocked = countif(DeliveryAction == "Blocked")
        by bin(TimeGenerated, 1d)
```

### Step 7: UEBA
```kql
let upn = "<upn>";
union
    (BehaviorAnalytics | where TimeGenerated > ago(7d) | where tolower(UserPrincipalName) == upn),
    (Anomalies | where TimeGenerated > ago(7d) | where tolower(UserName) == upn or tolower(UserPrincipalName) == upn)
| project TimeGenerated, Source = iif(isnotempty(RuleName), "Anomaly", "Behavior"),
          Detail = coalesce(RuleName, ActivityType), Score = coalesce(InvestigationPriority, todouble(Score))
| order by TimeGenerated desc
```

### Step 8: TI 突合（過去 7 日に通信した IP との照合）
```kql
let upn = "<upn>"; let oid = "<oid>";
let userIps = union
    (SigninLogs | where TimeGenerated > ago(7d) | where tolower(UserPrincipalName) == upn or UserId == oid | distinct IPAddress),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(7d) | where tolower(UserPrincipalName) == upn or UserId == oid | distinct IPAddress);
ThreatIntelIndicators
| where IsActive == true and ObservableKey has "ipv4-addr"
| where ObservableValue in (userIps)
| project ObservableValue, Confidence, ValidFrom, ValidUntil, Pattern
```

## 解釈ガイド
- **複数国からの短時間サインイン** → impossible travel 疑い (`triage-signin-anomaly` へ)
- **AuditLogs に Mailbox / OAuth Grant** → 永続化疑い
- **DeviceProcessEvents に LOLBin / Encoded PowerShell** → MDE アラート連動確認 (`triage-mde-alert`)
- **EmailEvents に大量送信** → アカウント乗っ取り後のフィッシング配布

## 推奨アクション テンプレート
| 観測 | 推奨 | 種別 |
|---|---|---|
| 異国サインイン成功 | MFA リセット、サインアウト | 人手判断 |
| OAuth 危険同意 | 同意取消、SP 監査 | 人手判断 |
| 大量送信 | 送信無効化、メール削除 | 人手判断 |
| TI ヒット IP のみ | IP ブロック検討 | `# AUTOMATION_CANDIDATE: Security Copilot Agent` |
