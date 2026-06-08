---
name: pivot-email
description: 単一の NetworkMessageId / InternetMessageId / 件名から、メール送受信・添付・URL・配信後イベント・クリックを横断調査する。
---

# pivot-email — メール 横断ピボット

## いつ使うか
- フィッシング メールの全受信者・添付・URL・クリック実績を一括把握
- 配信後にユーザー操作（クリック、開封）があったかを確認

## 入力
- `target`: `NetworkMessageId`（推奨） / `InternetMessageId` / 件名（部分一致）
- `lookback` (optional): 既定 `14d`

## 出力
1. **メール本体メタ**
2. **添付一覧**
3. **URL 一覧**
4. **配信後イベント**
5. **クリック イベント**
6. **クラスタ展開** (`EmailClusterId` で類似メール)
7. **推奨アクション**

## 実行手順

### Step 1: メール本体
```kql
let nmid = "<NetworkMessageId>";
EmailEvents
| where TimeGenerated > ago(14d) and NetworkMessageId == nmid
| project TimeGenerated, NetworkMessageId, InternetMessageId, EmailClusterId,
          SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderDisplayName,
          RecipientEmailAddress, RecipientObjectId, RecipientDomain,
          Subject, DeliveryAction, DeliveryLocation, ThreatTypes, ThreatNames,
          AuthenticationDetails, AttachmentCount, UrlCount, EmailDirection
```

### Step 2: 添付
```kql
let nmid = "<NetworkMessageId>";
EmailAttachmentInfo
| where TimeGenerated > ago(14d) and NetworkMessageId == nmid
| project TimeGenerated, FileName, FileType, SHA256, ThreatTypes, MalwareFilterVerdict, DetectionMethods
```

### Step 3: URL
```kql
let nmid = "<NetworkMessageId>";
EmailUrlInfo
| where TimeGenerated > ago(14d) and NetworkMessageId == nmid
| project TimeGenerated, Url, UrlDomain, UrlLocation
```

### Step 4: 配信後イベント（隔離・削除など）
```kql
let nmid = "<NetworkMessageId>";
EmailPostDeliveryEvents
| where TimeGenerated > ago(14d) and NetworkMessageId == nmid
| project TimeGenerated, Action, ActionType, ActionResult, ActionTrigger, DeliveryLocation
```

### Step 5: クリック
```kql
let nmid = "<NetworkMessageId>";
UrlClickEvents
| where TimeGenerated > ago(14d) and NetworkMessageId == nmid
| project TimeGenerated, AccountUpn, Url, IPAddress, IsClickedThrough, ActionType, ThreatTypes, UrlChain
```

### Step 6: クラスタ展開（同件名・同送信者 ファミリ）
```kql
let nmid = "<NetworkMessageId>";
let cluster = toscalar(EmailEvents | where TimeGenerated > ago(14d) and NetworkMessageId == nmid | take 1 | project EmailClusterId);
EmailEvents
| where TimeGenerated > ago(14d) and EmailClusterId == cluster
| summarize Recipients = dcount(RecipientEmailAddress),
            Senders = make_set(SenderFromAddress, 10),
            Subjects = make_set(Subject, 5),
            Delivered = countif(DeliveryAction == "Delivered"),
            Blocked = countif(DeliveryAction == "Blocked")
        by EmailClusterId
```

## 解釈ガイド
- **Delivered + IsClickedThrough=true** → 侵害成立疑い、`pivot-user` で受信者調査
- **同クラスタが多数配信** → 大量配信／キャンペーン
- **添付 SHA256 が `ThreatIntelIndicators` に登録あり** → 確定マルウェア

## 推奨アクション
| 観測 | 推奨 | 種別 |
|---|---|---|
| クリック確認済 | パスワード リセット + デバイス調査 | 人手判断 |
| 配信済の悪性メール | ZAP / 手動削除 | 人手判断 |
| クラスタ全件配信前ブロック | URL/IP/Sender ブロック | `# AUTOMATION_CANDIDATE` |
