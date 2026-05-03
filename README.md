# Microsoft Entra ID Modern SOC Enviroment Investigation

## Introduction

The goal of this project is to learn the main threats and defenses in Entra ID environments and how to detect them. Identity-based attacks are now the dominant initial access path in cloud environments. According to Microsoft's (opens in new tab) own telemetry, over 99% of account compromise attacks are preventable with basic controls like MFA, yet attackers continue to succeed because misconfigurations and policy gaps remain widespread. This lab explores the walkthrough of the most common attack techniques targeting Entra ID identities: how they work, what they leave behind in logs, and how to hunt for them with logs.

Identity-based attacks are now the dominant initial access path in cloud environments. According to Microsoft's own telemetry, over 99% of account compromise attacks are preventable with basic controls like MFA, yet attackers continue to succeed because misconfigurations and policy gaps remain widespread.
This room walks through the most common attack techniques targeting Entra ID identities: how they work, what they leave behind in logs, and how to hunt for them with logs. 

Password-based attacks are often launched in the Microsoft Entra ID environments and Entra ID is an especially attractive target because its authentication endpoints are internet-exposed by design. Any attacker with a username list can start attempting logins without ever touching the target's network perimeter. And when a login succeeds, it can look identical to a legitimate one, with no exploit, no malware, and no network anomalies. The only way to catch it is through log analysis.

## Detection with Logs

In this simulation, the first task is to access the logs and search for failed logging attempts.
* To filter failure attempt in sign-in logs, the query below was entered in the search bar.

`index="task-2" sourcetype="azure:aad:signin" "status.errorCode" !=0 conditionalAccessStatus!=success`

`| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason`

`| sort - _time`

The query above lists only failure attempts against Entra ID identities; however, you can leverage Splunk's (or any other SIEM's) query features to identify brute-force or password-spraying patterns better.

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-1.png)
Figure 1



* To list failed sign-in attempts by IP address, the following query was performed:

This query above can reveal which IP address has the most failure attempts and how many accounts were targeted:

`index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success`

`| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress`

`| sort - failures`

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-2.png)
Figure 2



The returned result shows us three IP addresses executing suspicious attempts.

The IP address executing various techniques and the relevant account being targeted was identfied, so this compelled me to specifically filter for these artifacts to investigate the suspicious behavior.

* To check whether any authentication has been successful, I used the following Splunk query below

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0

| where userPrincipalName="<TARGET_USER>"

| stats count by userPrincipalName, status.errorCode, ipAddress

| sort status.errorCode
```

The above query lists successful logins by user


* To list successful logins by **IP** address, the following search query is explored

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0

| where ipAddress="<SUSPICIOUS_IP>"

| stats count by userPrincipalName, status.errorCode

| sort status.errorCode
```

* To find which IP address was performing a password spraying, the following search query was entered in the search field:

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
ipAddress="94.20.222.248"
```

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-3.png)
Figure 3


![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-4.png)
Figure 4



* To find which IP address was performing a throttling brute force spraying, the following search query was entered in the search field:

`index="task-2" sourcetype="azure:aad:signin"`

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-5.png)
Figure 5


*  The IP 38.165.231.218 was identified as the address behind the use of throttling bruteforce

*  The E-Mail-address of the compromised user is: amanda.costa@finegalo.thm



![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-6.png)
Figurer 6



* To see the blocked sign-ins by CAP listed, I entered the following queries

```splunk
index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure

| spath output=policies path=appliedConditionalAccessPolicies{}

| mvexpand policies

| spath input=policies output=policy_result path=result
```

```splunk
| spath input=policies output=policy_name path=displayName
| where policy_result="failure"
| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
| eval FailedPolicies=mvjoin(FailedPolicies, ", ")
| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
| sort - _time
```

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-7.png)
Figure 7



* To have the High-risk-sign-ins listed, the following search queries are entered in the search

index="task-3" sourcetype="azure:aad:signin"

| where riskLevelDuringSignIn="high"

| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion,

riskLevelDuringSignIn, riskLevelAggregated

| sort - _time

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-8.png)
Figure 8



*  To list risk detections related to anonymized IPaddresses, the following queries are entered.

```splunk
index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="anonymizedIPAddress"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
```

| sort - _time

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-9.png)
Figure 9



### Risky User Logs (azure:aad:identity_protection:risky_user)

Every user has a risk level in Entra ID. This is calculated based on risk detections, and it's a way for Microsoft to alert admins to users who are likely compromised (or almost compromised) and require their attention.

Once a user changes its risk state, a risky user log is generated. This makes this log type a good trigger to perform proactive threat hunting to identify users who are likely compromised.

Thw Splunk query below was used to filter all risky user logs:

```splunk
index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time
```


* To identify the Email address of the user that is at risk in the tenant and reveal all risk detections related to the incidents, the following query was entered in the search.

```splunk
index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="anonymizedIPAddress"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

The result shows: <u>allan.senna@finegalo.thm</u>

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-10.png)
Figure 10



Additionally, the above output showed the timeline of the first and last risky sign-in attempt from this risky user occurred based on risk detection logs.

*  To view the event and examine the risk type provided by the risk detection log, I clicked on one of the results result returned and identified the risk type as “anonymizedIPAdress”

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-11.png)
Figure 11



* To identity the name of the CAP policy that was enforced and blocked some sign-in attempts from this risky user, the following long queries must be performed:

```splunk
index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure
| spath output=policies path=appliedConditionalAccessPolicies{}
```

| mvexpand policies

| spath input=policies output=policy_result path=result

| spath input=policies output=policy_name path=displayName

| where policy_result="failure"

| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress,
conditionalAccessStatus

| eval FailedPolicies=mvjoin(FailedPolicies, ", ")

| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies

| sort - _time

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-12.png)
Figure 12



(CAP) Policy Name: <mark>Block Suspicious Address</mark>

Based on the output above, “ipAddress” is clicked under the selected field to reveal the IP address that was blocked.

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-13.png)
Figure 13



### Focusing on MFA Bypass Technique

MFA is the single most impactful control against password-based attacks. Once an attacker has valid credentials, MFA is the wall between them and a full account takeover. As we mentioned before, Microsoft reports that MFA blocks over 99% of automated credential-based attacks.

### How MFA Works in Entra ID

When a user signs in, Entra ID breaks authentication into two sequential challenges:

Something you know: the user enters their username and password. Entra ID validates these credentials against the directory.

Something you have: if the password is correct (and a Conditional Access policy that enforces MFA is active), Entra ID sends a second challenge to a pre-registered method.

Only after both factors are satisfied does Entra ID generate a session token and grant access to the requested resource. Unfortunately, MFA is not a silver bullet. Attackers have developed techniques to bypass it without ever breaking the cryptography. This task covers the most relevant techniques for a SOC analyst to recognise.

## MFA Fatigue (Prompt Bombing)

The attacker already has valid credentials. They initiate repeated authentication attempts in rapid succession, each one generating an Authenticator push notification on the victim's phone. The goal is to overwhelm the user until they approve one, out of frustration, confusion, or the mistaken belief that it's a legitimate prompt.

This is a social engineering attack, not a technical one. It works because push notifications give the user a single button to approve without any additional context about where the sign-in is coming from.

### How it looks in logs:


*   A high volume of MFA prompts against a single account in a short window.


*   MFA-related error codes, such as 50074, 50076, 500121, repeated.


*   If the user approves, followed eventually by error code 0.

Microsoft has partially mitigated this with number matching (the user must enter a number shown on the login screen into their Authenticator app) and additional context (the app shows location and app name). These controls make fatigue attacks significantly harder.


To list MFA failures by user, the following queries are performed

`index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)`

`stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress`

`sort - mfa_failures`

# SIM Swapping

When SMS is used as the MFA method, an attacker can convince a mobile carrier to port the victim's phone number to a SIM they control, allowing them to receive all SMS codes. This primarily poses a threat to consumer accounts and organizations that still rely on SMS-based MFA. The mitigation is straightforward: move away from SMS as a factor.

In logs, this technique is characterized by:

*  A successful logon using an unusual device or browser for a user.

*  A successful logon from an unusual location for a user.

# Adversary-in-the-Middle (AiTM) Phishing

AiTM is a more sophisticated technique. The attacker sets up a reverse proxy between the victim and the legitimate Microsoft login page. The victim authenticates normally, including completing MFA, but the proxy captures the session token issued after authentication. The attacker then replays that token on their own machine, bypassing MFA entirely because authentication has already occurred.

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-14.png)
Figure 14



From the token's perspective, the session is legitimate. The attack doesn't break MFA; it steals the MFA result. The pattern can be described as:

*  The sign-in succeeds without a new MFA prompt because the token already carries proof that MFA was completed during the original (victim's) authentication.

*  The source IP and location differ from those where MFA was originally completed.

*  Conditional Access shows the session as compliant. The policy was satisfied, just not by the person who's now using the token.

This is why token theft is so dangerous: from Entra ID's perspective, everything looks fine. The only anomalies are geography and IP, which require an analyst to connect the dots between two separate sign-in events.

# Impossible Travel

You may have noticed that an attacker who has bypassed authentication, whether through SIM Swapping or by stealing a session token (AiTM), often ends up authenticating from a location that makes no physical sense relative to the user's last known sign-in location. This is the basis for one of the most reliable detection signals in Entra ID: impossible travel.

For example: a user signs in from São Paulo at 09:00, and then the same account signs in from Moscow at 09:45. That's physically impossible. One of those sign-ins is unlikely to be performed by the legitimate user.

Identity Protection tries to detect this automatically and flags it as an impossibleTravel risk event. But as we mentioned before, you can't blindly trust these alerts, since sometimes they aren't accurate. You can hunt for this pattern proactively, directly in Sign-in logs, by using the Splunk query below and trying to spot logins from different countries in a timestamp that is physically impossible:

*  Entered the following queries to list successful sign-in activity for a user:

```splunk
index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion, conditionalAccessStatus
| sort - _time
```

*  Entered the following queries to list "impossibleTravel" alerts in Identity Protection logs:

```splunk
index="task-4" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="impossibleTravel"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

# Legitimate False Positives

Not every impossible travel event is malicious. Before confirming an incident, you may consider:

*   Corporate VPNs** — A user connecting through a VPN exit node in another country will appear to sign in from that country, even while sitting in their office.
*   Split tunnelling** — Some traffic goes through the VPN, some doesn't, producing sign-ins from multiple apparent locations simultaneously.
*   Cloud service IPs** — Automated sign-ins from Microsoft services or third-party integrations can produce location anomalies.

* To identify which user was the target of an MFA fatigue attack, the following query was performed:

`index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)`

`| stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress`

`| sort - mfa_failures`

**Output:**

**userPrincipalName**: <u>igor.bicalho@finegalo.thm</u>

**The errorCode**: 5000121

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-15.png)
Figure 15




* To identify the country code that the user used to sign in before the attack, the following query was entered:

`index="task-4" sourcetype="azure:aad:signin" status.errorCode=0`

`| table _time, userPrincipalName, ipAddress, location.countryOrRegion, conditionalAccessStatus`

| sort - _time

![Splunk Enterprise search interface showing a table of sign-in events.](page_26_image_1_v2.jpg)

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-16A.png)
Figure 16A



* The output shows DK” which Denmark as the country. The country code is DK

* To find when the attacker successfully authenticated in the user account,

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-16B.png)
Figure 16B



The above output showed **2026-03-04 13:26** as the time log for a successful authentication into the user account located in Brazil

# Privilege Escalation

Getting into an account is only the first step. Once an attacker has a foothold, their next priority is two things: expand their access and make sure they can keep it even if the compromised account is locked out or its password is reset.

This task introduces the most common post-compromise actions that an attacker takes in Entra ID. The focus here is on recognition, knowing what to look for in Audit logs.

## Common Post-Compromise Techniques

You may have noticed that everything up to this point has lived in Sign-in logs. Once the attacker is authenticated and begins taking action within the tenant, the relevant evidence is moved to Audit Logs.

Audit logs capture administrative actions and any changes to the tenant's state. Role assignments, user creation, policy modifications. All changes land there.

Once you suspect a user is compromised, the key filtering field is activityDisplayName, which indicates the action the user performed.

* To filter and list all audit logs performed in a tenant, the following Splunk query was used:

`index="task-5" sourcetype="azure:aad:audit"`

But in short, the most important fields in audit logs that must be paid an attention to in an investigation of post-compromise activity are:

* activityDisplayName**: The detailed activity or action that was performed by a user or app.

* initiatedBy**: The account or app that performed the action.

* targetResources**: The account or objects that have been changed or affected by an action.

These fields answer the most important question for analyzing post-compromise activity: what was changed (activityDisplayName), who made that change (initiatedBy), and the details of the changes (targetResources).

Keep that in mind to answer the task practice questions.

## Role Assignment

This is the most direct path to elevated access: assign a privileged Entra ID role to the compromised account (or to a new account the attacker creates). Below are common target roles:

* Global Administrator:** Full control over the tenant.

* Exchange Administrator:** Access to all mailboxes.

* User Administrator:** Can reset passwords and modify accounts.

* Application Administrator:** Can manage app registrations and consent grants.

A legitimate role assignment isn't inherently suspicious. What's suspicious is a role assignment that happens outside normal provisioning workflows. For example, at an unusual time, initiated by an account that doesn't normally perform these actions, targeting an account that was recently involved in suspicious sign-in activity

* To list all assigned role activities in a tenant,the following query was entered:

`index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"`

`| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue | sort - _time`

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-17.png)
Figure 17



# Creating Backdoor Accounts

A new admin account created outside normal HR/IT provisioning flows is a classic example of a persistence mechanism. The attacker creates it, assigns it a privileged role, and uses it as a fallback if the original compromised account is remediated.


* The following Splunk query below was used to list all accounts created within a tenant:

```splunk
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"

| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')

| eval userCreated='targetResources{}.userPrincipalName'

| table _time, activityDisplayName,initiator, userCreated
```

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-18.png)
Figure 18



# Adding Alternate MFA Methods

If an attacker registers their own authenticator app or phone number on the compromised account, they maintain access even after the victim changes their password, since they control the MFA factor. This shows up in Audit logs as an MFA registration event on a user object, initiated by the user themselves.

When onboarding an MFA device, it can generate multiple types of logs for each step.

* To list MFA onboard attempts or validate if a user attempted to add an MFA device to their account, the Splunk query below was used:

```splunk
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods" operationType="Add"
```

```splunk
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
```

```splunk
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
```

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-19.png)
Figure 19




To continue the investigation from MFA bypass, the focus was shifted on the post compromise activity in the compromised account that was identified


* The following query was performed to identify user creation by the initiator

`index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"`

`| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')`

| eval userCreated='targetResources{}.userPrincipalName'

| table _time, activityDisplayName,initiator, userCreated

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-20.png)
Figure 20



The result showed that the attacker created a user with the email address <u>rafael.maciel@finegalo.thm</u>


* To uncover the role that was assigned to this new account, the following query was entered:

index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"

| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue | sort - _time

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-21.png)
Figure 21



**Role**: Global Administrator

* Further query was performed to see if any alternative MFA device was added by the attacker:

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-22.png)
Figure 22



## OAuth Applicatiopn Abuse

Password reset, MFA resets, and account lockouts. A thorough remediation effort can undo most of what an attacker achieved through credential theft. However, there is one persistent mechanism that survives it all: a consented OAuth application.

This task dives deeper into OAuth abuse as a standalone technique. It is one of the stealthiest persistence methods available to an attacker because the access isn't tied to the user's credentials at all. It lives in the application layer, and most organizations are not actively monitoring it.

## How OAuth Consent Works

OAuth (Open Authorization) is the protocol that powers the "Sign in with Google" or "Connect your Microsoft account" buttons you see everywhere. It allows a third-party application to request access to a user's resources on a platform, such as M365, without ever handling the user's password. Instead, the user (or an administrator) reviews a consent screen listing what the application wants to do, approves it, and the platform issues an access token granting that application those permissions.

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-23.png)
Figure 23



From an attacker's perspective, this is ideal. Once a user or admin clicks "Accept", the application holds a persistent grant to the user's data via API. That access:

Survives password changes, because it's not credential-based.

Survives MFA resets, because authentication already happened at consent time.

Requires active revocation, not just credential remediation, to remove.

## Delegated vs Application Permissions

Not all consent grants are equal. Microsoft's permission model has two distinct types, and understanding the difference is critical for assessing how dangerous a consent grant is.


![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/b4f14dc3dec54ed9c1799607b824feba274f8c7b/Figure-24.png)
Figure 24



Delegated permissions are the more common and less alarming of the two. The app borrows the user's identity and can only do what that user could do themselves. If that user leaves the organization, the grant becomes useless.

Application permissions are a different story. They grant the application a standing right to act across the entire tenant, independently of any user session. An app with **Mail.Read.All** can silently read every mailbox in the organization indefinitely. An app with **RoleManagement.ReadWrite.Directory** can assign Entra ID roles. These permissions require admin consent precisely because of how powerful they are, which is also why tricking a Global Administrator into granting consent is one of the highest-value moves an attacker can make.

## High-Risk Permission Scopes to Know

The following permissions are commonly abused and should be treated as high-priority findings during a hunt:

*  Mail.Read.All / Mail.ReadWrite.All**: Read or modify all mailboxes in the tenant.

*  Files.ReadWrite.All**: Read and write all files across SharePoint and OneDrive.

*  RoleManagement.ReadWrite.Directory**: Assign and remove Entra ID roles, including Global Administrator.

*  Directory.ReadWrite.All**: Read and write all directory data, including users and groups.

*  offline_access**: Maintain access indefinitely via refresh tokens, even when the user is not actively signed in.

Any consent grant that includes one or more of these scopes warrants immediate investigation.

## Detecting OAuth Abuse in Audit Logs

Consent grant events are captured in Audit logs under the `activityDisplayName` value "Consent to application". The `targetResources` field is particularly important here since it contains both the application that was granted consent and the specific permissions that were approved.

![image alt](https://github.com/Michaelsalaja/Cloud-Based-IAM-Investigation-Lab-/blob/0ff7be675c72993b980b87c55b076e3f0f0ec20c/Figure-25.png)
Figure 25



The following query was performed to list all consent grant to an application

```splunk
index="main" sourcetype="azure:aad:audit"

activityDisplayName="Consent to application"

| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')

| eval appName='targetResources{}.displayName'

| eval permissionsGranted='targetResources{}.modifiedProperties{}.newValue'
```

```
| table _time, initiator, appName, permissionsGranted

| sort - _time
```

**Mail.Read.All:** This is the permission that allows an application to read all mailboxes within a tenant

**Consent to Application:** This is the activityDisplayName value that is used to track all consent grants to applications within Entra ID audit logs

## Conclusion

This lab project gave me a solid understanding of what the main threats against Microsoft Entra ID are and how to identify them using Sign-in and Audit logs.

*  Learned the main attacks that target Entra ID.

*  Learned how Conditional Access policies and Identity Protection work together to help admins quickly identify potentially compromised accounts.

*  Identified bruteforce and password spraying patterns using Splunk queries to extract Sign-in logs and Audit logs for post compromise activities.

*  Understood how to use Entra ID Sign-in and Audit logs to detect these threats before compromising an account and how to identify post-compromise activities.

*  Explored how MFA works in Entra ID, reviewed SIM Swapping and **Adversary-in-the-Middle (AiTM)** techniques often used by attacker, including MFA-related error codes such as 50074, 50076, 500121

