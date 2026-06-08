---
name: triage-phishing
description: フィッシング メール検出時の初動トリアージ。配信状況・添付・URL・クリック・他受信者を一括把握。
---

# triage-phishing — フィッシング トリアージ

## いつ使うか
- MDO Defender for Office 365 アラート
- ユーザー報告メール (UserSubmissions / 手動)
- Email URL がブロックされた / クリック後ブロックされた

## 入力
- `networkMessageId` または `internetMessageId` または `subjectPattern`
- `lookback` (optional): 既定 `14d`

## 出力
1. **メール詳細**
2. **添付 / URL / クリック サマリ**
3. **クラスタ展開**（同一キャンペーン）
4. **受信者の侵害評価**（クリックしたユーザーの直後活動）
5. **配信後アクション要否**

## 実行手順

`pivot-email` を呼び出して Step 1-6 を実行。その結果に対し以下を追加。

### Step A: クリックしたユーザーの直後活動（侵害評価）
```kql
let nmid = "<NetworkMessageId>";
let clickers = UrlClickEvents
    | where TimeGenerated > ago(14d) and NetworkMessageId == nmid and IsClickedThrough == "true"
    | distinct AccountUpn;
SigninLogs
| where TimeGenerated > ago(14d)
| where tolower(UserPrincipalName) in (clickers)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSignin = min(TimeGenerated),
            LastSignin = max(TimeGenerated),
            Countries = make_set(Country, 10),
            IPs = make_set(IPAddress, 30),
            RiskHigh = countif(RiskLevelDuringSignIn == "high")
        by UserPrincipalName
```

### Step B: クリック後の OAuth 同意（永続化チェック）
```kql
let clickers = <upn list>;
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant")
| where tolower(tostring(InitiatedBy.user.userPrincipalName)) in (clickers)
| project TimeGenerated, OperationName, Actor=tostring(InitiatedBy.user.userPrincipalName),
          Target=tostring(TargetResources)
```

### Step C: 同一クラスタ全受信者の侵害有無
```kql
let cluster = "<EmailClusterId>";
let recipients = EmailEvents
    | where TimeGenerated > ago(14d) and EmailClusterId == cluster
    | distinct RecipientEmailAddress;
UrlClickEvents
| where TimeGenerated > ago(14d)
| where tolower(AccountUpn) in (recipients) and IsClickedThrough == "true"
| summarize Clicks = count(), Urls = make_set(Url, 10) by AccountUpn
```

## 判定マトリクス
| 観測 | 判定 | 次のアクション |
|---|---|---|
| クリックなし + 配信前ブロック | リスク低 | ZAP 確認のみ |
| クリックあり + サインイン正常 | 注意 | パスワード変更推奨 |
| クリックあり + 異国サインイン | 高リスク侵害 | 即時パスワード/MFA リセット, `pivot-user` |
| クリックあり + OAuth 同意 | 永続化済み | 同意取消 + SP 監査 |

## 推奨アクション
- [人手判断] 配信済悪性メール ZAP / 手動削除
- [人手判断] 受信者全員へ注意喚起
- [`# AUTOMATION_CANDIDATE`] URL / 送信者ドメイン ブロック
- [人手判断] クリック確認者の認証情報リセット
