---
applyTo: "**/*.kql,**/*.kusto,**/SKILL.md"
---

# Sentinel テーブル別エンティティ列マップ

本ファイルは Pivot / Triage Skill から参照する **正規化テーブル**。  
出典: 一般的な Microsoft Sentinel データレイクワークスペースの `getschema` + サンプル分析（2026-06）。

> 💡 テーブルスキーマはテナント・コネクタ構成で多少異なります。ご自身のワークスペースで `getschema` を実行して検証してください。

---

## Identity / Sign-in

| テーブル | UserUpn | UserObjectId | IpAddress | DeviceId/Name | 備考 |
|---|---|---|---|---|---|
| `SigninLogs` | `UserPrincipalName` | `UserId` | `IPAddress` | `tostring(DeviceDetail.deviceId)` | `DeviceDetail` / `LocationDetails` = dynamic |
| `AADNonInteractiveUserSignInLogs` | `UserPrincipalName` | `UserId` | `IPAddress` | `DeviceDetail` | 大規模 (5M行/週) |
| `AADServicePrincipalSignInLogs` | — | `ServicePrincipalId` | `IPAddress` | — | SP |
| `MicrosoftServicePrincipalSignInLogs` | — | `ServicePrincipalId` | — | — | Microsoft 1st-party |
| `AADManagedIdentitySignInLogs` | — | `ServicePrincipalId` | `IPAddress` | — | MI |
| `AADGraphActivityLogs` | — | `UserId`, `ServicePrincipalId` | `CallerIpAddress` | `DeviceId` | Graph API |
| `MicrosoftGraphActivityLogs` | — | `UserId`, `ServicePrincipalId` | `IPAddress` | `DeviceId` | **大規模 10M+/週** |
| `AuditLogs` | `tostring(InitiatedBy.user.userPrincipalName)` | `tostring(InitiatedBy.user.id)` | `tostring(InitiatedBy.user.ipAddress)` | — | `InitiatedBy`, `TargetResources` = dynamic |
| `AADProvisioningLogs` | `TargetIdentity` | — | — | — | InitiatedBy も dynamic |
| `AADRiskyUsers` | `UserPrincipalName` | — | — | — | リスク状態 |
| `AADUserRiskEvents` | `UserPrincipalName` | `UserId` | `IpAddress` | — | リスク イベント |
| **`IdentityInfo`** | **`AccountUPN`** | **`AccountObjectId`** | — | — | **★ハブ表**: SID, CloudSID, SAM, Domain, MailAddress, AdditionalMailAddresses |
| `IdentityLogonEvents` | `AccountUpn` / `TargetAccountUpn` | `AccountObjectId` | `IPAddress`, `DestinationIPAddress` | `DeviceName`, `DestinationDeviceName` | MDI |
| `IdentityDirectoryEvents` | `AccountUpn` / `TargetAccountUpn` | `AccountObjectId` | `IPAddress`, `DestinationIPAddress` | `DeviceName` | MDI |
| `IdentityQueryEvents` | `AccountUpn` / `TargetAccountUpn` | `AccountObjectId` | `IPAddress` | `DeviceName` | MDI |
| `BehaviorAnalytics` | `UserPrincipalName`, `ActorPrincipalName`, `TargetPrincipalName` | — | `SourceIPAddress`, `DestinationIPAddress` | `SourceDevice`, `DestinationDevice` | UEBA |
| `UserPeerAnalytics` | `UserPrincipalName`, `PeerUserPrincipalName` | `UserId`, `PeerUserId` | — | — | Peer |

---

## Endpoint (MDE)

共通: 全テーブルに `DeviceId` (MDE GUID), `DeviceName`, `MachineGroup` と `InitiatingProcess*` (親プロセス情報) がある。

| テーブル | Account | Device | File/Hash | Network |
|---|---|---|---|---|
| `DeviceInfo` | `LoggedOnUsers` (dynamic) | `DeviceId`, **`AadDeviceId`**, `DeviceObjectId`, `PublicIP`, `MergedDeviceIds` | — | — |
| `DeviceLogonEvents` | `AccountName`, `AccountDomain`, `AccountSid` | `DeviceId`, `DeviceName`, `RemoteDeviceName`, `RemoteIP` | — | `RemoteIP`, `RemotePort` |
| `DeviceProcessEvents` | **`AccountUpn`**, **`AccountObjectId`**, `AccountSid`, `AccountName`, `AccountDomain` | `DeviceId`, `DeviceName` | `FileName`, **`SHA256`**, `SHA1`, `MD5`, `FolderPath` | — |
| `DeviceFileEvents` | `InitiatingProcessAccountUpn`, `RequestAccountName/Sid` | `DeviceId`, `DeviceName` | `FileName`, **`SHA256`**, `SHA1`, `MD5`, `FolderPath` | `FileOriginIP`, `FileOriginUrl`, `RequestSourceIP` |
| `DeviceImageLoadEvents` | `InitiatingProcessAccountUpn` | `DeviceId`, `DeviceName` | `FileName`, **`SHA256`**, `FolderPath` | — |
| `DeviceNetworkEvents` | `InitiatingProcessAccountUpn` | `DeviceId`, `DeviceName` | — | **`RemoteIP`, `RemotePort`, `RemoteUrl`**, `LocalIP`, `LocalPort` |
| `DeviceRegistryEvents` | `InitiatingProcessAccountUpn` | `DeviceId`, `DeviceName` | — | — |
| `DeviceEvents` | `AccountName/Domain/Sid`, `InitiatingProcessAccountUpn` | `DeviceId`, `DeviceName` | `FileName`, `SHA256`, `FolderPath`, `FileOriginIP`, `FileOriginUrl` | `LocalIP/Port`, `RemoteIP/Port/Url` |
| `DeviceFileCertificateInfo` | — | `DeviceId` | `SHA1`, `IssuerHash`, `SignerHash` | — |
| `DeviceNetworkInfo` | — | `DeviceId`, `DeviceName`, `MacAddress` | — | `IPAddresses` (dynamic) |

---

## Email (MDO)

主キー: **`NetworkMessageId`** で 5 テーブルが結合可能。

| テーブル | 送信者 | 受信者 | キー | URL/File |
|---|---|---|---|---|
| `EmailEvents` | `SenderFromAddress`, `SenderMailFromAddress`, `SenderObjectId`, `SenderIPv4/v6`, `SenderDisplayName` | `RecipientEmailAddress`, `RecipientObjectId`, `RecipientDomain`, `To`/`Cc` (dynamic) | **`NetworkMessageId`**, `InternetMessageId`, `EmailClusterId` | `Subject`, `ThreatTypes`, `DeliveryAction` |
| `EmailAttachmentInfo` | `SenderFromAddress`, `SenderObjectId` | `RecipientEmailAddress`, `RecipientObjectId` | `NetworkMessageId` | `FileName`, **`SHA256`**, `FileType`, `ThreatTypes` |
| `EmailUrlInfo` | — | — | `NetworkMessageId` | **`Url`, `UrlDomain`**, `UrlLocation` |
| `EmailPostDeliveryEvents` | `SenderFromAddress` | `RecipientEmailAddress` | `NetworkMessageId` | `Action`, `ActionResult` |
| `UrlClickEvents` | — | **`AccountUpn`** | `NetworkMessageId` | `Url`, `UrlChain`, `IPAddress`, `IsClickedThrough` |

---

## Cloud / SaaS / IaaS

| テーブル | ユーザー識別 | IP | リソース/操作 | 備考 |
|---|---|---|---|---|
| `CloudAppEvents` (MDA) | **`AccountObjectId`** (Entra), `AccountId`, `AccountDisplayName`, `AccountType` | `IPAddress` | `Application`, `ApplicationId`, `ObjectId`, `ObjectName`, `ObjectType`, `ActivityObjects` (dynamic) | dynamic = array `[{Type,Role,Name,Id,ApplicationId}]` |
| `OfficeActivity` | `UserId` (=**UPN**), `MailboxOwnerUPN`, `MailboxOwnerSid`, `Actor`, `DestMailboxOwnerUPN`, `LogonUserSid`, `SendAsUserSmtp` | `ClientIP`, `ActorIpAddress`, `Client_IPAddress` | `OfficeObjectId`, `ApplicationId`, `AppId` | **★`UserId` は UPN 文字列** |
| `AzureActivity` | `Caller` (UPN) | `CallerIpAddress` | `SubscriptionId`, `ResourceGroup`, `ResourceProviderValue`, `CorrelationId` | ARM 操作 |
| `AWSCloudTrail` | `UserIdentityUserName`, `UserIdentityArn`, `UserIdentityPrincipalid`, `SessionIssuerUserName`, `SessionIssuerArn` | `SourceIpAddress` | `UserIdentityAccountId`, `RecipientAccountId`, `EventSource`, `Resources` | **Entra と別系統** |
| `DataverseActivity` | `UserUpn`, `UserId`, `UserKey`, `SystemUserId` | `ClientIp` | `InstanceUrl`, `ItemUrl`, `SourceRecordId` | — |
| `MicrosoftPurviewInformationProtection` | `UserId`, `SensitivityLabelOwnerEmail` | `ClientIP` | `ObjectId`, `Application`, `DeviceName`, `EmailInfo` (dynamic) | DLP |
| `CopilotActivity` | `ActorName`, `ActorUserId` | `SrcIpAddr` | `AppHost`, `AppIdentity` | M365 Copilot |
| `Windows365AuditLogs` | `UserPrincipalName`, `UserId` | — | `ApplicationId`, `ApplicationName` | Cloud PC |
| `GraphNotificationsActivityLogs` | — (`ResourceIdentity`, `SubscriptionIdentity`) | — | `ApplicationId`, `WorkloadResource` | 通知 API |

---

## Network / Firewall

| テーブル | ユーザー | 送信元 | 宛先 | 備考 |
|---|---|---|---|---|
| **`ASimDnsActivityLogs`** | `SrcUserId`, `SrcUsername` | `SrcIpAddr`, `SrcHostname`, `SrcFQDN` | `DnsQuery`, `DstIpAddr`, `DstFQDN`, `DstDomain`, `DnsResponseName` | **★ASIM 正規化** |
| `AZFWNetworkRule` | — | `SourceIp`, `SourcePort` | `DestinationIp`, `DestinationPort`, `Protocol` | Azure FW |
| `AZFWApplicationRule` | — | `SourceIp`, `SourcePort` | `Fqdn`, `TargetUrl`, `Protocol` | L7 |
| `AZFWDnsQuery` | — | `SourceIp`, `SourcePort` | `QueryName`, `QueryType` | DNS |
| `AZFWFlowTrace` | — | `SourceIp`, `SourcePort` | `DestinationIp`, `DestinationPort` | フロー |
| `AZFWNatRule` | — | `SourceIp`, `SourcePort` | `DestinationIp`, `TranslatedIp`, `TranslatedPort` | NAT |
| `AZFWThreatIntel` | — | `SourceIp` | `Fqdn`, `TargetUrl`, `DestinationIp`, `ThreatDescription` | TI ヒット |
| `AZFWIdpsSignature` | — | `SourceIp` | `DestinationIp`, `Description` | IDPS |
| `NetworkAccessConnectionEvents` | **`UserPrincipalName`**, `UserId` | `SourceIp`, `SourcePrivateIp`, `RemoteNetworkSourceIp` | `DestinationIp`, `DestinationFqdn` | Entra IA |
| `NetworkAccessTraffic` | **`UserPrincipalName`**, `UserId`, `CloudAppLoginUser` | `SourceIp`, `ConnectorIp` | `DestinationIp`, `DestinationFqdn`, `DestinationUrl` | Entra IA |
| `NSPAccessLogs` | — | `SourceIpAddress`, `SourceAppId`, `SourceResourceId` | `DestinationFqdn`, `DestinationResourceId`, `DestinationEmailAddress`, `DestinationPort` | NSP |

---

## Alerts / Incidents / TI / UEBA

| テーブル | ユーザー | デバイス | ファイル/ネット | キー |
|---|---|---|---|---|
| `SecurityAlert` | `CompromisedEntity` (string), `Entities` (stringified JSON) | (Entities内) | (Entities内) | `SystemAlertId`, `ProviderName`, `ProductName`, `Tactics`, `Techniques` |
| `SecurityIncident` | — | — | — | **`IncidentNumber`** (Sentinel ID, int), **`ProviderIncidentId`** (XDR ID, string), `IncidentName` (内部 GUID), `Severity`, `Status`, `AlertIds`, `BookmarkIds`, `IncidentUrl` (Sentinel), `tostring(AdditionalData.providerIncidentUrl)` (XDR URL), `tostring(AdditionalData.alertProductNames)` (元製品配列) |
| **`AlertEvidence`** | **`AccountUpn`, `AccountObjectId`**, `AccountSid`, `AccountName`, `AccountDomain` | `DeviceId`, `DeviceName` | `FileName`, `SHA256`, `SHA1`, `FolderPath`, `RemoteIP`, `RemoteUrl`, `LocalIP`, `NetworkMessageId`, `EmailSubject`, `OAuthApplicationId`, `CloudResource`, `CloudPlatform` | `AlertId`, `EvidenceRole`, `EvidenceDirection` ★**横断ピボット起点** |
| `AlertInfo` | — | — | — | `AlertId`, `Title`, `Category`, `ServiceSource`, `DetectionSource`, `Severity`, `AttackTechniques` |
| `Anomalies` | `UserPrincipalName`, `UserName` | `SourceDevice`, `DestinationDevice` | `SourceIpAddress`, `DestinationIpAddress` | `Id`, `RuleId`, `RuleName`, `Score`, `Entities` (dynamic) |
| `HuntingBookmark` | — | — | — | `BookmarkId`, `Entities`, `QueryText`, `CreatedBy` |
| `ThreatIntelIndicators` | — | — | `ObservableValue` (IoC値), `ObservableKey` (タイプ) | `Pattern` (STIX), `Confidence`, `ValidFrom/Until`, `IsActive` |
| `ThreatIntelObjects` | — | — | `Data` (dynamic STIX) | `StixType` |

---

## Windows / Server

| テーブル | ユーザー | デバイス | プロセス/その他 |
|---|---|---|---|
| `SecurityEvent` | `Account`, `AccountName`, `AccountDomain`, `UserPrincipalName`, `SubjectAccount`, `SubjectUserName`, `SubjectUserSid`, `TargetAccount`, `TargetUserName`, `TargetUserSid`, `SamAccountName` | `Computer`, `SourceComputerId` | `Process`, `ProcessName`, `ProcessId`, `NewProcessName`, `ParentProcessName`, `CallerProcessName`, `FilePath`, `FileHash`, `IpAddress`, `ClientIPAddress`, `RemoteIpAddress` |
| `Heartbeat` | — | `Computer`, `ComputerIP`, `ComputerPrivateIPs` (dynamic), `ResourceId` | サブスクリプション情報 |
| `ProtectionStatus` | — | `Computer`, `DeviceName`, `SourceComputerId` | — |

---

## SAP

| テーブル | ユーザー | 識別子 | 備考 |
|---|---|---|---|
| `ABAPAuditLog` | `User`, `Email` | `ClientId`, `Computer`, `Host`, `SalIpAddress`, `RemoteIpCountry` | ECC/S4 |
| `ABAPUserDetails` | `User`, `Email` | `ClientId`, `UserGroup`, `UserType` | マスタ |
| `ABAPAuthorizationDetails` | — | `ClientId`, `Object` | 権限 |
| `SAPBTPAuditLog_CL` | `UserName` | `SubaccountName`, `Tenant` | BTP |
| `SAPLogServ_CL` | (RawLog内 JSON) | `host`, `source`, `sourcetype`, `cribl_pipe` | **Cribl 経由 RAW**。RawLog パース要 |

---

## Intune / Cloud PC

| テーブル | ユーザー | デバイス | 備考 |
|---|---|---|---|
| `IntuneDevices` | `UPN`, `UserEmail`, `UserName`, `PrimaryUser` | `DeviceId`, `DeviceName`, `ManagedDeviceName`, `WifiMacAddress` | インベントリ |
| `IntuneDeviceComplianceOrg` | `UPN`, `UserEmail`, `UserId`, `UserName` | `DeviceId`, `DeviceName`, `OSDescription`, `DeviceHealthThreatLevel` | コンプライアンス |
| `IntuneAuditLogs` | (`ResultDescription` 内) | — | 監査 |
