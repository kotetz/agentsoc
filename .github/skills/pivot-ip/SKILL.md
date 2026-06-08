---
name: pivot-ip
description: 単一の IP アドレスから、サインイン・エンドポイント通信・ファイアウォール・DNS・TI の全テーブルを横断調査する。列名の表記揺れ (IPAddress / SourceIp / SrcIpAddr 等) を IpAddress に正規化する。
---

# pivot-ip — IP 横断ピボット

## いつ使うか
- TI ヒット IP の影響範囲確認
- 不審 IP からのアクセス調査
- 既知 C2 / Tor / VPN 出口の利用者特定

## 入力
- `target`: IPv4 / IPv6 アドレス（CIDR は未対応、必要なら `ipv4_is_match()` 化）
- `lookback` (optional): 既定 `7d`

## 出力
1. **TI / 評価情報**
2. **このIPを使ったサインイン**（ユーザー特定）
3. **このIPと通信したエンドポイント**
4. **ファイアウォール ルール ヒット**
5. **DNS / Web プロキシ**
6. **クラウド アプリ操作**
7. **推奨アクション**

## 実行手順

### Step 1: TI 確認
```kql
let target = "<ip>";
ThreatIntelIndicators
| where IsActive == true
| where ObservableValue == target
| project ObservableKey, ObservableValue, Confidence, ValidFrom, ValidUntil, Pattern, Description
```

### Step 2: サインイン
```kql
let target = "<ip>";
union withsource=SourceTable
    (SigninLogs | where TimeGenerated > ago(7d) | where IPAddress == target),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(7d) | where IPAddress == target),
    (AADServicePrincipalSignInLogs | where TimeGenerated > ago(7d) | where IPAddress == target)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignIns = count(),
            Users = make_set(coalesce(UserPrincipalName, ServicePrincipalName), 30),
            Apps = make_set(AppDisplayName, 20),
            Countries = make_set(Country, 5),
            Failures = countif(ResultType != 0)
        by SourceTable, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 3: エンドポイント通信
```kql
let target = "<ip>";
union withsource=SourceTable
    (DeviceNetworkEvents | where TimeGenerated > ago(7d) | where RemoteIP == target or LocalIP == target),
    (DeviceLogonEvents | where TimeGenerated > ago(7d) | where RemoteIP == target),
    (DeviceFileEvents | where TimeGenerated > ago(7d) | where FileOriginIP == target or RequestSourceIP == target)
| summarize Count = count(), Devices = make_set(DeviceName, 20), Accounts = make_set(coalesce(AccountUpn, InitiatingProcessAccountUpn), 10)
        by SourceTable, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 4: ファイアウォール
```kql
let target = "<ip>";
union withsource=SourceTable
    (AZFWNetworkRule | where TimeGenerated > ago(7d) | where SourceIp == target or DestinationIp == target),
    (AZFWApplicationRule | where TimeGenerated > ago(7d) | where SourceIp == target),
    (AZFWDnsQuery | where TimeGenerated > ago(7d) | where SourceIp == target),
    (AZFWThreatIntel | where TimeGenerated > ago(7d) | where SourceIp == target or DestinationIp == target),
    (AZFWIdpsSignature | where TimeGenerated > ago(7d) | where SourceIp == target or DestinationIp == target)
| summarize Count = count(), Actions = make_set(Action, 5), Fqdns = make_set(coalesce(Fqdn, QueryName, TargetUrl), 30)
        by SourceTable, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 5: DNS / Web (ASIM)
```kql
let target = "<ip>";
ASimDnsActivityLogs
| where TimeGenerated > ago(7d)
| where SrcIpAddr == target or DstIpAddr == target
| summarize Count = count(),
            Queries = make_set(DnsQuery, 30),
            Hosts = make_set(SrcHostname, 10),
            Users = make_set(SrcUsername, 10)
        by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 6: クラウド アプリ
```kql
let target = "<ip>";
union withsource=SourceTable
    (CloudAppEvents | where TimeGenerated > ago(7d) | where IPAddress == target),
    (OfficeActivity | where TimeGenerated > ago(7d) | where ClientIP == target or ActorIpAddress == target or Client_IPAddress == target),
    (AzureActivity | where TimeGenerated > ago(7d) | where CallerIpAddress == target),
    (AWSCloudTrail | where TimeGenerated > ago(7d) | where SourceIpAddress == target)
| summarize Count = count(),
            Users = make_set(coalesce(AccountDisplayName, UserId, Caller, UserIdentityUserName), 20),
            Ops = make_set(coalesce(ActionType, Operation, OperationName, OperationNameValue, EventName), 20)
        by SourceTable, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

## 解釈ガイド
- **複数ユーザーで同一 IP** → 共有 NAT / プロキシ、または侵害インフラ
- **失敗→成功の遷移** → パスワード スプレー成功
- **企業外IPからのSP/MIサインイン** → 異常

## 推奨アクション
| 観測 | 推奨 | 種別 |
|---|---|---|
| TI 高信頼 + 通信あり | NSG/Firewall ブロック | `# AUTOMATION_CANDIDATE` |
| 利用者 1 名のみ | 当該ユーザー再確認 | 人手判断 |
| 多数失敗のみ | Conditional Access 強化 | 人手判断 |
