---
applyTo: "**/*.kql,**/*.kusto"
---

# KQL コーディング規約（Sentinel Data Lake）

## 1. 基本方針

- すべての調査クエリは **`copilot-instructions.md` §5 標準エンティティ語彙** に正規化した列で `project` する。
- 大規模テーブルは `where TimeGenerated > ago(7d)` を **最初** に置く。
- 動的列 (`dynamic`) は必ず `tostring()` または `parse_json()` で展開してから使う。

## 2. テンプレート

### 2.1 単一テーブル ピボット
```kql
TableName
| where TimeGenerated > ago(7d)
| where <フィルタ>
| extend UserUpn = tolower(<元列>),
         IpAddress = tostring(<元列>),
         DeviceName = tolower(<元列>)
| project TimeGenerated, UserUpn, IpAddress, DeviceName, <原典の主要列>
| order by TimeGenerated desc
| take 100
```

### 2.2 横断 union ピボット
```kql
union withsource=SourceTable
    (T1 | where TimeGenerated > ago(7d) | extend UserUpn=tolower(<col>)),
    (T2 | where TimeGenerated > ago(7d) | extend UserUpn=tolower(<col>))
| where UserUpn == "<target>"
| project TimeGenerated, SourceTable, UserUpn, <共通列>
| order by TimeGenerated desc
```

> ⚠️ **`withsource=TableName` は禁止**（既存列と衝突）。必ず `SourceTable` を使う。

### 2.3 IdentityInfo を使ったユーザー解決
```kql
let target = "user@example.com";
let userIds = IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | where tolower(AccountUPN) == tolower(target)
           or tolower(MailAddress) == tolower(target)
           or AccountObjectId == target
           or AccountSID == target
    | project AccountUPN, AccountObjectId, AccountSID, SAMAccountName, MailAddress;
userIds
```

### 2.4 dynamic 列の展開
```kql
// SigninLogs
SigninLogs
| where TimeGenerated > ago(1d)
| extend DeviceId = tostring(DeviceDetail.deviceId),
         OS = tostring(DeviceDetail.operatingSystem),
         Country = tostring(LocationDetails.countryOrRegion),
         City = tostring(LocationDetails.city)

// AuditLogs
AuditLogs
| where TimeGenerated > ago(1d)
| extend UserUpn = tolower(tostring(InitiatedBy.user.userPrincipalName)),
         UserObjectId = tostring(InitiatedBy.user.id),
         AppDisplayName = tostring(InitiatedBy.app.displayName)
| mv-expand Target = TargetResources
| extend TargetId = tostring(Target.id), TargetType = tostring(Target.type)

// CloudAppEvents
CloudAppEvents
| where TimeGenerated > ago(1d)
| mv-expand Obj = ActivityObjects
| extend ObjRole = tostring(Obj.Role),
         ObjType = tostring(Obj.Type),
         ObjName = tostring(Obj.Name),
         ObjId = tostring(Obj.Id)
| where ObjRole == "Target"
```

## 3. アンチパターン

| ❌ NG | ✅ OK |
|---|---|
| `union withsource=TableName *` | `union withsource=SourceTable *` |
| `SecurityEvent | take 100` | `SecurityEvent | where EventID == 4624 | take 100` |
| `where UPN == "Alice@..."` | `where tolower(UPN) == tolower("Alice@...")` |
| `DeviceDetail.deviceId == "..."` | `tostring(DeviceDetail.deviceId) == "..."` |
| `search "alice"` (調査用途) | テーブル/列を指定したクエリ |

## 4. 列名の表記揺れ正規化チート シート

```kql
// IP 列を IpAddress に統一する例
extend IpAddress = coalesce(
    tostring(IPAddress),
    tostring(IpAddress),
    tostring(SourceIp),
    tostring(SourceIPAddress),
    tostring(CallerIpAddress),
    tostring(ClientIP),
    tostring(Client_IPAddress),
    tostring(ActorIpAddress),
    tostring(RemoteIP),
    tostring(SrcIpAddr))
```
