---
name: triage-sap-anomaly
description: SAP ABAP / BTP / Cribl 経由ログから検出された異常のトリアージ。SAP ユーザー識別子と業務時間/権限を考慮する。
---

# triage-sap-anomaly — SAP 異常 トリアージ

## いつ使うか
- SAP ABAP 監査ログ (SM20 / SAL) の異常
- SAP BTP ロール変更・大量データ アクセス
- SAPLogServ_CL (Cribl 経由 RAW) からの検出

## 入力
- `sapUser` (SAP ログイン名)
- `clientId` (SAP クライアント)
- `windowStart`, `windowEnd`

## 出力
1. **対象 SAP 活動明細**
2. **権限変更履歴**
3. **業務時間外活動判定**
4. **同 SAP ユーザーの Entra 紐付け確認**
5. **判定 & 推奨**

## 実行手順

### Step 1: ABAP 監査ログ明細
```kql
let u = "<SapUser>"; let c = "<ClientId>"; let s = datetime(<start>); let e = datetime(<end>);
ABAPAuditLog
| where TimeGenerated between (s .. e)
| where User =~ u and ClientId == c
| project TimeGenerated, User, Email, ClientId, Computer, Host,
          SalIpAddress, RemoteIpCountry,
          MessageId, Message, Severity, Category, SystemId
| order by TimeGenerated asc
```

### Step 2: ユーザー属性 / 権限
```kql
let u = "<SapUser>"; let c = "<ClientId>";
ABAPUserDetails
| where User =~ u and ClientId == c
| summarize arg_max(TimeGenerated, *) by User, ClientId
| project User, Email, UserType, UserGroup, ValidFrom, ValidTo, LastLogon, LockStatus;
ABAPAuthorizationDetails
| where User =~ u and ClientId == c
| summarize arg_max(TimeGenerated, *) by User, ClientId, Object
| project User, Object, Field, FromValue, ToValue
```

### Step 3: 業務時間外活動
```kql
let u = "<SapUser>"; let c = "<ClientId>";
ABAPAuditLog
| where TimeGenerated > ago(7d) and User =~ u and ClientId == c
| extend HourLocal = datetime_part("hour", TimeGenerated)
| summarize Count = count(), OffHours = countif(HourLocal < 7 or HourLocal > 20)
        by bin(TimeGenerated, 1d)
| order by OffHours desc
```

### Step 4: BTP ログ（該当する場合）
```kql
let u = "<SapUser>";
SAPBTPAuditLog_CL
| where TimeGenerated > ago(7d)
| where UserName =~ u
| project TimeGenerated, UserName, SubaccountName, Tenant, Action, Category
| order by TimeGenerated desc
```

### Step 5: Entra 紐付け確認
```kql
let email = "<SAP User Email>";
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where tolower(MailAddress) == tolower(email) or AdditionalMailAddresses has tolower(email)
| project AccountUPN, AccountObjectId, AccountSID, IsAccountEnabled
```

### Step 6: Cribl RAW (必要に応じて)
```kql
SAPLogServ_CL
| where TimeGenerated > ago(7d)
| where RawLog has "<SapUser>" or RawLog has "<keyword>"
| take 50
| project TimeGenerated, host, source, sourcetype, cribl_pipe, RawLog
```
> RawLog は JSON or text の混在の可能性。必要に応じて `parse_json` でフィールド抽出。

## 判定マトリクス
| 観測 | 判定 |
|---|---|
| 業務時間外大量変更 | インサイダー疑い、要 HR/Manager 連携 |
| SU01 ユーザー作成 + 強権限付与 | 永続化 |
| 海外 IP からの SAP ログイン | アクセス制御確認 |
| DEBUG / SE38 / TABLE 直接編集 | 不正データ操作 |

## 推奨アクション
- [人手判断] SAP ユーザー一時ロック (`SU01`)
- [人手判断] 権限変更ロールバック (PFCG)
- [人手判断] 紐付く Entra ユーザーで `pivot-user`
