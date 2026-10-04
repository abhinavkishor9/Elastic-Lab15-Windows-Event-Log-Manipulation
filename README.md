# Lab 15 — Defense Evasion — Windows Event Log Manipulation

## Overview

This lab investigates Windows Event Log manipulation as a defense evasion technique using a controlled Security log clearing activity on a Windows endpoint monitored by Elastic Security.

The investigation focuses on Windows Security Event ID 1102, authentication and privilege-related events, process telemetry, and the difference between confirmed evidence and unavailable telemetry.

> Follow the evidence, not the assumption.

Event ID 1102 is treated as an investigation trigger rather than automatic proof of malicious activity.

## Objectives

- Understand Windows Security Event ID 1102.
- Generate a controlled Security log clearing event.
- Validate the event locally using PowerShell.
- Detect the same event in Elastic Security.
- Review authentication and privilege-related events.
- Investigate process telemetry associated with the activity.
- Compare local Windows evidence with Elastic telemetry.
- Identify telemetry gaps.
- Distinguish confirmed findings from assumptions.

## Scenario

A Windows endpoint monitored by Elastic generates Security Event ID 1102 indicating that the audit log was cleared.

The SOC analyst must determine:

- When was the Security log cleared?
- Which host generated the event?
- What user context was associated with the activity?
- What authentication activity was available?
- Was process telemetry captured?
- Did Elastic receive the event?
- What can be confirmed from the available evidence?
- What remains unknown?

The activity is intentionally generated on the lab endpoint for investigation and detection testing.

## Environment

| Component | Details |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 |
| PowerShell | 7.6.6 |
| SIEM | Elastic Security |
| Monitoring | Elastic Agent / Elastic Defend |
| User | `desktop-9mmm37v\dell` |
| Relevant Event | Windows Security Event ID `1102` |

## Lab Workflow

1. Verify the Windows Security log.
2. Establish a Security event baseline.
3. Record the host, user, and current time.
4. Perform the controlled log-clear activity.
5. Validate Event ID 1102 locally.
6. Search for Event ID 1102 in Elastic.
7. Review authentication and privilege events.
8. Investigate process telemetry.
9. Build the investigation timeline.
10. Compare local and Elastic evidence.
11. Document confirmed findings and telemetry limitations.

## Step 1 — Verify the Security Log

```powershell
Get-WinEvent -ListLog Security |
Select-Object LogName, RecordCount, IsEnabled
```

Observed:

```text
LogName  RecordCount IsEnabled
Security         686      True
```

The Security log was enabled before the test.

## Step 2 — Establish a Baseline

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

The baseline contained existing Security events, including:

- Event ID 4616 — System time was changed.
- Event ID 4625 — An account failed to log on.

This confirmed that the endpoint was generating Security telemetry before the controlled activity.

## Step 3 — Record Host and User Context

```powershell
whoami
hostname
Get-Date
```

Observed:

```text
desktop-9mmm37v\dell
DESKTOP-9MMM37V
04 October 2026 06:18:51
```

## Step 4 — Perform the Controlled Log-Clear Activity

The following command was executed on the isolated lab endpoint:

```powershell
wevtutil cl Security
```

The command completed successfully without an error.

This was an intentional lab activity.

## Step 5 — Validate Event ID 1102 Locally

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=1102
} -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Observed:

```text
TimeCreated            Id ProviderName                 Message
-----------            -- ------------                 -------
04-10-2026 06:19:37  1102 Microsoft-Windows-Eventlog The audit log was cleared....
```

This confirmed that Windows generated Event ID 1102.

## Step 6 — Detect Event ID 1102 in Elastic

```esql
FROM logs-*
| WHERE event.code == "1102"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.SubjectUserName,
       winlog.event_data.SubjectDomainName
| SORT @timestamp DESC
```

Elastic returned one document:

| Field | Value |
|---|---|
| `@timestamp` | Oct 4, 2026 @ 06:19:37.864 |
| `host.name` | `desktop-9mmm37v` |
| `user.name` | `Dell` |
| `event.code` | `1102` |
| `SubjectUserName` | `-` |
| `SubjectDomainName` | `-` |

This confirmed that Elastic received the Security log clearing event.

## Step 7 — Correlate Authentication and Privilege Events

```esql
FROM logs-*
| WHERE event.code IN ("1102", "4624", "4625", "4672")
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.LogonType,
       winlog.event_data.SubjectUserName,
       winlog.event_data.SubjectDomainName
| SORT @timestamp DESC
```

The Elastic search returned the Event ID 1102 document.

The local Windows query for Event IDs 4624, 4625, and 4672 performed after the log clear returned no events.

This does not prove that authentication or privilege activity did not occur. It means those events were no longer available in the local Security log after the clearing operation.

## Step 8 — Investigate Process Telemetry

```esql
FROM logs-*
| WHERE process.name IN ("wevtutil.exe", "powershell.exe", "pwsh.exe")
| KEEP @timestamp,
       host.name,
       user.name,
       process.name,
       process.pid
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

A specific search for `wevtutil.exe` also returned no matching documents.

### Interpretation

No matching process telemetry was returned by the query.

The investigation therefore does not claim that Elastic observed `wevtutil.exe`.

The controlled command was executed locally and completed successfully, but the corresponding process execution was not independently observed through the queried Elastic process telemetry.

## Findings

### Confirmed Findings

- Security logging was enabled.
- Existing Security events were present before the test.
- The controlled `wevtutil cl Security` command completed successfully.
- Windows generated Event ID 1102.
- Event ID 1102 occurred at approximately `06:19:37`.
- Elastic captured Event ID 1102 at `06:19:37.864`.
- The affected host was `desktop-9mmm37v`.
- Elastic populated `user.name` as `Dell`.

### Process Telemetry Limitation

Elastic returned no matching process documents for:

- `wevtutil.exe`
- `powershell.exe`
- `pwsh.exe`

Therefore, the exact process-level execution mechanism was not established through the queried Elastic process telemetry.

### Important Distinction

The absence of process telemetry does not prove that the process did not execute.

The correct finding is:

> No matching process telemetry was returned by the query.

## Investigation Outcome

The controlled exercise successfully demonstrated Windows Security log clearing and confirmed Event ID 1102 locally and in Elastic Security.

The exact process responsible for the log-clearing activity was not independently established through Elastic process telemetry.

The final assessment is:

> Confirmed Security log clearing with incomplete process attribution.

## SOC Takeaway

Event ID 1102 should trigger investigation, not an automatic malicious verdict.

A stronger investigation correlates:

- Event ID 1102
- User context
- Authentication activity
- Privilege activity
- Process execution
- Parent-child relationships
- Command-line telemetry
- Host context
- Timeline

The key lesson is:

> A confirmed security event does not automatically provide complete execution evidence.
