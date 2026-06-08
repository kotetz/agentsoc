---
name: pivot-host
description: 単一のデバイス識別子（DeviceId / DeviceName / AadDeviceId / ComputerName）から、MDE・Entra・Intune・Windows・Network の全テーブルを横断調査する。
---

# pivot-host — ホスト横断ピボット

## いつ使うか
- MDE アラートで指摘されたデバイスの全体像を把握したい
- ラテラル ムーブメント被害確認
- 端末コンプライアンス／所有者確認

## 入力
- `target`: DeviceId / DeviceName / AadDeviceId / ComputerName / FQDN
- `lookback` (optional): 既定 `7d`

## 出力
1. **デバイス ID 解決** (DeviceInfo ハブ)
2. **所有者 / プライマリ ユーザー** (IntuneDevices)
3. **ログオン履歴** (DeviceLogonEvents)
4. **プロセス実行サマリ** (DeviceProcessEvents)
5. **ネットワーク通信** (DeviceNetworkEvents / ASimDnsActivityLogs)
6. **ファイル操作 / 検疫** (DeviceFileEvents / DeviceEvents)
7. **アラート連動** (AlertEvidence)
8. **推奨アクション**

## 実行手順

### Step 1: ID 解決
```kql
let target = "<target>";
DeviceInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by DeviceId
| where DeviceId == target
     or AadDeviceId == target
     or DeviceObjectId == target
     or tolower(DeviceName) == tolower(target)
     or tolower(DeviceName) startswith tolower(tostring(split(target,".")[0]))
     or MergedDeviceIds has target
| project DeviceId, AadDeviceId, DeviceObjectId, DeviceName, OSPlatform, OSVersion,
          PublicIP, LoggedOnUsers, MachineGroup, JoinType, IsAzureADJoined,
          MergedDeviceIds, OnboardingStatus
```

### Step 2: 所有者 / 管理状態
```kql
let did = "<resolved DeviceId>"; let aadid = "<AadDeviceId>"; let name = "<DeviceName>";
IntuneDevices
| where TimeGenerated > ago(30d)
| where DeviceId == aadid or tolower(DeviceName) == tolower(name) or tolower(ManagedDeviceName) == tolower(name)
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceName, PrimaryUser, UPN, UserEmail, OS, OSVersion,
          EnrollmentType, ComplianceState, ManagementAgent, LastContact
```

### Step 3: ログオン履歴
```kql
let did = "<DeviceId>"; let name = "<DeviceName>";
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where DeviceId == did or tolower(DeviceName) == tolower(name)
| summarize Logons = count(),
            Success = countif(ActionType == "LogonSuccess"),
            Failed = countif(ActionType == "LogonFailed"),
            Users = make_set(AccountName, 30),
            RemoteIPs = make_set(RemoteIP, 30)
        by LogonType, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

### Step 4: プロセス実行（疑わしいシグナル抽出）
```kql
let did = "<DeviceId>";
DeviceProcessEvents
| where TimeGenerated > ago(7d) and DeviceId == did
| extend Suspicious =
       ProcessCommandLine has_any ("-enc","-encoded","FromBase64String","DownloadString","Invoke-Expression","mimikatz")
    or InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe") and FileName !in~ ("winword.exe","excel.exe")
| summarize Count = count(),
            SuspiciousCount = countif(Suspicious),
            TopBin = make_set_if(FileName, Suspicious, 10),
            TopCmd = make_set_if(ProcessCommandLine, Suspicious, 10)
        by AccountUpn, bin(TimeGenerated, 1d)
| order by SuspiciousCount desc, TimeGenerated desc
```

### Step 5: ネットワーク通信
```kql
let did = "<DeviceId>"; let name = "<DeviceName>";
union withsource=SourceTable
    (DeviceNetworkEvents | where TimeGenerated > ago(7d) and DeviceId == did
        | summarize Count = count(), TopHosts = make_set(RemoteUrl, 30), TopIPs = make_set(RemoteIP, 30) by ActionType, bin(TimeGenerated, 1d)),
    (ASimDnsActivityLogs | where TimeGenerated > ago(7d) and (tolower(SrcHostname) == tolower(name) or tolower(SrcFQDN) startswith tolower(name))
        | summarize Count = count(), TopQueries = make_set(DnsQuery, 30) by bin(TimeGenerated, 1d))
| order by TimeGenerated desc
```

### Step 6: ファイル操作
```kql
let did = "<DeviceId>";
DeviceFileEvents
| where TimeGenerated > ago(7d) and DeviceId == did
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| summarize Count = count(), TopPaths = make_set(FolderPath, 20), TopHashes = make_set(SHA256, 20)
        by ActionType, bin(TimeGenerated, 1d)
```

### Step 7: アラート連動
```kql
let did = "<DeviceId>"; let name = "<DeviceName>";
AlertEvidence
| where TimeGenerated > ago(14d)
| where DeviceId == did or tolower(DeviceName) == tolower(name)
| join kind=leftouter (AlertInfo | where TimeGenerated > ago(14d)) on AlertId
| project TimeGenerated, AlertId, Title, Severity, Category, ServiceSource, EvidenceRole
| order by TimeGenerated desc
```

## 解釈ガイド
- **同時刻に複数アカウント ログオン (LogonType=3)** → 横展開疑い
- **WMI / WinRM / PsExec の初動** → Living-off-the-land、`triage-mde-alert` へ
- **大量 DNS NXDOMAIN** → DGA / C2 疑い
- **PublicIP が短期間で複数変化** → モバイル端末 or 異常

## 推奨アクション
| 観測 | 推奨 | 種別 |
|---|---|---|
| 既知マルウェア SHA256 検出 | 隔離、フォレンジック | 人手判断 |
| LOLBin スプレー | プロセス停止、調査 | 人手判断 |
| 未知ホスト 大量通信 | URL/IP ブロック検討 | `# AUTOMATION_CANDIDATE` |
