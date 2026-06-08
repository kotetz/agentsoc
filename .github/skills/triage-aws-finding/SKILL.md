---
name: triage-aws-finding
description: AWS CloudTrail 由来のセキュリティ検出（GuardDuty・カスタム ルール）のトリアージ。AWS の ARN 体系と Entra フェデレーションを考慮する。
---

# triage-aws-finding — AWS 由来トリアージ

## いつ使うか
- AWS GuardDuty / 任意の AWS 検出ルール
- フェデレーション ユーザーの異常 AWS 操作

## 入力
- `userIdentityArn` または `accessKeyId` または `eventName`
- `windowStart`, `windowEnd`

## 出力
1. **対象アクティビティ明細**
2. **使用 IAM ロール / ユーザー**
3. **アクセス元 IP / リージョン**
4. **フェデレーション元 Entra ユーザー特定**
5. **判定 & 推奨**

## 実行手順

### Step 1: 対象アクティビティ
```kql
let arn = "<UserIdentityArn>"; let s = datetime(<start>); let e = datetime(<end>);
AWSCloudTrail
| where TimeGenerated between (s .. e)
| where UserIdentityArn == arn
| project TimeGenerated, EventName, EventSource, AwsRegion,
          UserIdentityType, UserIdentityUserName, UserIdentityArn,
          UserIdentityAccountId, SessionIssuerUserName, SessionIssuerArn,
          SourceIpAddress, UserAgent, RecipientAccountId,
          RequestParameters, ResponseElements, ErrorCode, ErrorMessage
| order by TimeGenerated asc
```

### Step 2: 失敗とエラー パターン
```kql
let arn = "<arn>"; let s = datetime(<start>); let e = datetime(<end>);
AWSCloudTrail
| where TimeGenerated between (s .. e) and UserIdentityArn == arn
| summarize Count = count() by EventName, ErrorCode
| order by Count desc
```

### Step 3: アクセス元 IP の利用パターン
```kql
let arn = "<arn>";
AWSCloudTrail
| where TimeGenerated > ago(7d) and UserIdentityArn == arn
| summarize Events = count(), Sources = make_set(EventSource, 20), Names = make_set(EventName, 30)
        by SourceIpAddress, AwsRegion, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Step 4: フェデレーション元 Entra ユーザー特定
- `SessionIssuerUserName` が Entra UPN 形式の場合: `IdentityInfo` で照合
- ロール名のみの場合: 同時刻の `SigninLogs` で AWS アプリ サインインを照合

```kql
let issuer = "<SessionIssuerUserName>"; let t = datetime(<eventTime>);
SigninLogs
| where TimeGenerated between (t - 30m .. t + 5m)
| where AppDisplayName has "AWS" or AppDisplayName has "Amazon"
| where tolower(UserPrincipalName) contains tolower(issuer)
   or  ResourceDisplayName has "AWS"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
| order by TimeGenerated desc
```

## 判定マトリクス
| 観測 | 判定 |
|---|---|
| ConsoleLogin Success from new region | 不審サインイン |
| IAM CreateUser / CreateAccessKey | 永続化作成 |
| GetCallerIdentity 大量 / EnumerateAccounts | 偵察 |
| s3:GetObject 大量 + ExternalIp | データ流出 |

## 推奨アクション
- [人手判断] AccessKey 無効化、ロール revoke
- [人手判断] フェデレーション元 Entra ユーザーで `pivot-user`
- [`# AUTOMATION_CANDIDATE`] SourceIpAddress の Entra 側 CA 連動ブロック
