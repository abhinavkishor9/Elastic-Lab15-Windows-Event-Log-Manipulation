# Elastic-Lab15-Windows-Event-Log-Manipulation
## Overview
Windows Event Logs provide valuable evidence for authentication, process execution, privilege use, and other security activity. An attacker with sufficient privileges may attempt to clear or manipulate event logs to remove traces of their actions.

This lab focuses on Windows Security Event ID 1102 — “The audit log was cleared.” The event is an important detection signal because clearing the Security log can reduce the availability of forensic evidence.

However, Event ID 1102 alone does not prove malicious activity. Administrators may legitimately clear logs during maintenance, troubleshooting, or controlled testing. The investigation therefore focuses on correlating the log-clear event with authentication, privilege, process, and command-line telemetry.

This lab investigates Windows Event Log manipulation as a defense evasion technique using a controlled Security log clearing activity on a Windows endpoint monitored by Elastic Security.

The investigation focuses on Windows Security Event ID 1102, authentication and privilege-related events, process telemetry, and the difference between confirmed evidence and unavailable telemetry.

> Follow the evidence, not the assumption.

Event ID 1102 is treated as an investigation trigger rather than automatic proof of malicious activity.

## Lab Objectives

- Understand how Windows Event Log manipulation can be used as a defense evasion technique.
- Understand the significance of Windows Security Event ID `1102`.
- Perform a controlled Security log clearing activity on the Windows lab endpoint.
- Validate the generated Event ID `1102` locally using Windows Event Viewer/PowerShell telemetry.
- Identify the timestamp, host, and available user context associated with the event.
- Verify whether the cleared-log event is received by Elastic Security.
- Correlate Event ID `1102` with authentication and privilege-related events such as `4624`, `4625`, and `4672`.
- Investigate available process telemetry for `wevtutil.exe` and related PowerShell processes.
- Compare endpoint-side evidence with centralized Elastic telemetry.
- Identify gaps or limitations in process and authentication telemetry.
- Distinguish confirmed evidence from assumptions and unavailable evidence.
- Document the investigation using an evidence-first SOC methodology.
- Understand why Event ID `1102` should be treated as an investigation trigger rather than automatic proof of malicious activity.
  
## Lab Scenario

A Windows endpoint monitored by Elastic Security is suspected of experiencing activity that could interfere with security logging. In a real-world incident, an attacker may attempt to clear Windows event logs to remove evidence of authentication activity, process execution, or other actions performed during a compromise.

For this controlled lab, the Security log is intentionally cleared using `wevtutil`. The resulting Windows Security Event ID `1102` is then investigated locally and through Elastic Security.

The investigation focuses on determining:

- When the Security log was cleared.
- Which endpoint generated the event.
- What user context is available.
- Whether Event ID `1102` was successfully ingested into Elastic.
- Whether related authentication or privilege events can be correlated.
- Whether process telemetry provides evidence of `wevtutil.exe` or PowerShell execution.
- What evidence can be confirmed and what remains unavailable.

The activity is performed only on the controlled Windows lab endpoint. The objective is not to simulate a complete attack, but to understand how a SOC analyst would detect, validate, correlate, and document Windows event log manipulation.

The investigation follows an evidence-first approach. Event ID `1102` confirms that the audit log was cleared, but it does not by itself establish malicious intent or identify the responsible process. Any missing telemetry is documented as a visibility limitation rather than treated as evidence that the activity did not occur.

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

