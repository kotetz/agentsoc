---
name: triage-signin-anomaly
description: サインイン異常（不可能旅行、ハイ リスク サインイン、パスワード スプレー、MFA 疲労攻撃）の初動トリアージ。
---

# triage-signin-anomaly — サインイン異常 トリアージ

## いつ使うか
- AAD Identity Protection / Anomalies / Sentinel 検出ルールから発火したサインイン関連アラート
- Risk Level High のユーザー発生

## 入力
- `userUpn` または `userObjectId`
- `windowStart`, `windowEnd`（イベント発生時刻 ± 数時間推奨）

## 出力
1. **対象期間のサインイン明細**（国・IP・成功失敗・MFA 状態）
2. **直前との挙動差分**（普段使う国／IP／App）
3. **同一 IP 共有ユーザー**（スプレー判定）
4. **MFA 失敗連発有無**
5. **判定 & 次の Pivot**

## 実行手順

### Step 1: 対象サインイン明細
```kql
let upn = tolower("<upn>"); let s = datetime(<windowStart>); let e = datetime(<windowEnd>);
union
    (SigninLogs | where TimeGenerated between (s .. e) | where tolower(UserPrincipalName) == upn),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated between (s .. e) | where tolower(UserPrincipalName) == upn)
| extend Country = tostring(LocationDetails.countryOrRegion),
         City = tostring(LocationDetails.city),
         DeviceIdStr = tostring(DeviceDetail.deviceId),
         OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser),
         IsCompliant = tobool(DeviceDetail.isCompliant)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, City, AppDisplayName,
          ResultType, ResultDescription, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState,
          DeviceIdStr, OS, Browser, IsCompliant, AuthenticationRequirement, MfaDetail=tostring(MfaDetail)
| order by TimeGenerated asc
```

### Step 2: 普段との差分（過去 30 日ベースライン）
```kql
let upn = tolower("<upn>");
let baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where tolower(UserPrincipalName) == upn and ResultType == 0
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | summarize Countries = make_set(Country, 20),
                IPs = make_set(IPAddress, 50),
                Apps = make_set(AppDisplayName, 30);
baseline
```

### Step 3: 同一 IP 共有（スプレー判定）
```kql
let target_ip = "<ip>";
SigninLogs
| where TimeGenerated > ago(7d) and IPAddress == target_ip
| summarize Failed = countif(ResultType != 0),
            Success = countif(ResultType == 0),
            DistinctUsers = dcount(UserPrincipalName),
            Users = make_set(UserPrincipalName, 50)
        by IPAddress, bin(TimeGenerated, 1h)
| where DistinctUsers > 5
| order by TimeGenerated desc
```

### Step 4: MFA 疲労攻撃シグナル
```kql
let upn = tolower("<upn>");
SigninLogs
| where TimeGenerated > ago(2d) and tolower(UserPrincipalName) == upn
| where ResultType in (50074, 50158, 500121, 530002) // MFA 関連
| summarize MfaPrompts = count() by bin(TimeGenerated, 5m)
| where MfaPrompts > 5
| order by TimeGenerated desc
```

## 判定マトリクス
| 観測 | 判定 | 次のアクション |
|---|---|---|
| 普段使わない国 + ResultType=0 | アカウント乗っ取り疑い | `pivot-user`, MFA リセット |
| 同 IP で多数ユーザー失敗 | パスワード スプレー | `pivot-ip`, Conditional Access 強化 |
| MFA 多数連続 | MFA 疲労攻撃 | 端末確認 + ユーザー連絡 |
| RiskLevelDuringSignIn=high + Compliant=false | リスク高 | 隔離検討 |

## 推奨アクション
- [人手判断] パスワード リセット + 全セッション サインアウト
- [人手判断] MFA 強制再登録
- [`# AUTOMATION_CANDIDATE`] 不審 IP の Conditional Access 一時ブロック
