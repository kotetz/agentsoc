---
name: pivot-url-domain
description: 単一の URL またはドメインから、メール・エンドポイント・ファイアウォール・DNS の全テーブルを横断調査する。
---

# pivot-url-domain — URL/ドメイン 横断ピボット

## いつ使うか
- フィッシング メールに含まれた URL／C2 ドメインの影響範囲調査
- 既知悪性ドメインへのアクセスがあったか

## 入力
- `target`: URL（完全形）または FQDN
- `lookback` (optional): 既定 `7d`

## 出力
1. **TI 確認**
2. **メール内 URL とクリック イベント**
3. **エンドポイント アクセス**
4. **DNS クエリ**
5. **ファイアウォール ヒット**
6. **推奨アクション**

## 実行手順

### Step 0: 正規化
```kql
let raw = "<target>";
let domain = tolower(tostring(parse_url(raw).Host));
let host = iif(isempty(domain), tolower(raw), domain);
let urlStr = raw;
```

### Step 1: TI
```kql
ThreatIntelIndicators
| where IsActive == true
| where ObservableValue == urlStr or ObservableValue == host or ObservableValue endswith ("." + host)
| project ObservableKey, ObservableValue, Confidence, ValidFrom, ValidUntil, Description
```

### Step 2: メール内 URL とクリック
```kql
let host = "<host>"; let urlStr = "<url>";
union
    (EmailUrlInfo | where TimeGenerated > ago(7d) | where Url == urlStr or UrlDomain == host
        | join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, ThreatTypes) on NetworkMessageId
        | project TimeGenerated, Source="EmailUrl", RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, ThreatTypes),
    (UrlClickEvents | where TimeGenerated > ago(7d) | where Url == urlStr or parse_url(Url).Host =~ host
        | project TimeGenerated, Source="UrlClick", AccountUpn, Url, IPAddress, IsClickedThrough, ThreatTypes, ActionType)
| order by TimeGenerated desc
```

### Step 3: エンドポイント アクセス
```kql
let host = "<host>"; let urlStr = "<url>";
union withsource=SourceTable
    (DeviceNetworkEvents | where TimeGenerated > ago(7d) | where tolower(RemoteUrl) has host),
    (DeviceFileEvents | where TimeGenerated > ago(7d) | where tolower(FileOriginUrl) has host),
    (DeviceEvents | where TimeGenerated > ago(7d) | where tolower(RemoteUrl) has host or tolower(FileOriginUrl) has host)
| summarize Count = count(),
            Devices = make_set(DeviceName, 20),
            Users = make_set(InitiatingProcessAccountUpn, 10),
            Processes = make_set(InitiatingProcessFileName, 10)
        by SourceTable, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 4: DNS
```kql
let host = "<host>";
ASimDnsActivityLogs
| where TimeGenerated > ago(7d)
| where DnsQuery =~ host or DstFQDN =~ host or DstDomain endswith host
| summarize Count = count(),
            Hosts = make_set(SrcHostname, 20),
            Users = make_set(SrcUsername, 10),
            Responses = make_set(DnsResponseName, 10)
        by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 5: ファイアウォール
```kql
let host = "<host>"; let urlStr = "<url>";
union withsource=SourceTable
    (AZFWApplicationRule | where TimeGenerated > ago(7d) | where Fqdn =~ host or TargetUrl has host),
    (AZFWDnsQuery | where TimeGenerated > ago(7d) | where QueryName =~ host),
    (AZFWThreatIntel | where TimeGenerated > ago(7d) | where Fqdn =~ host or TargetUrl has host)
| summarize Count = count(), Actions = make_set(Action, 5), Sources = make_set(SourceIp, 20)
        by SourceTable, bin(TimeGenerated, 1h)
```

## 解釈ガイド
- **メール → クリック → エンドポイント アクセス** の連鎖 → 侵害成立。エンドポイントで `pivot-host`
- **DNS のみで HTTP/HTTPS 通信なし** → DNS パンチ確認のみ
- **特定ユーザーのみクリック** → 標的型

## 推奨アクション
| 観測 | 推奨 | 種別 |
|---|---|---|
| 多数クリック | URL ブロック、ユーザー注意喚起 | 人手判断 |
| 侵害成立疑い | エンドポイント `pivot-host` 起動 | 人手判断 |
| TI のみ通信なし | 予防ブロック | `# AUTOMATION_CANDIDATE` |
