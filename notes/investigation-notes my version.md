# Lab 15 — Investigation Notes

## 1. Security Log Baseline

The Security log was checked before testing:

```powershell
Get-WinEvent -ListLog Security |
Select-Object LogName, RecordCount, IsEnabled
```

Observed:

```text
LogName  RecordCount IsEnabled
Security         686      True
```

The Security log was enabled and contained existing events.

## 2. Pre-Test Security Events

The recent Security event baseline included:

- Event ID 4616 — The system time was changed.
- Event ID 4625 — An account failed to log on.

These events were present before the controlled log-clear activity.

## 3. Host and User Context

The following commands were executed:

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

This established the endpoint and user context before the test.

## 4. Controlled Log-Clear Activity

The following command was executed on the lab endpoint:

```powershell
wevtutil cl Security
```

The command completed successfully without an error.

This was an intentional activity performed for the lab.

## 5. Local Event ID 1102 Validation

The Security log was queried for Event ID 1102:

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

### Finding

Event ID 1102 was confirmed locally at approximately `06:19:37`.

This confirms that the Windows Security audit log was cleared during the controlled exercise.

## 6. Elastic Detection

Elastic was searched for Event ID 1102:

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

Observed:

```text
@timestamp
Oct 4, 2026 @ 06:19:37.864

host.name
desktop-9mmm37v

user.name
Dell

event.code
1102

winlog.event_data.SubjectUserName
-

winlog.event_data.SubjectDomainName
-
```

### Finding

Elastic successfully captured the same Event ID 1102.

The Elastic timestamp was:

```text
06:19:37.864
```

The affected host was:

```text
desktop-9mmm37v
```

The available `user.name` value was:

```text
Dell
```

The `SubjectUserName` and `SubjectDomainName` fields were not populated in the captured document.

## 7. Authentication and Privilege Investigation

The local system was queried for:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon
- Event ID 4672 — Special privileges assigned

Command:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625,4672
} -MaxEvents 50 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Result:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

The query was executed after the Security log had been cleared.

Previously stored Security events were therefore no longer available through the local Security log.

The result does not prove that no logon or privilege activity occurred.

It only establishes that those events were not available in the local Security log after the clearing operation.

## 8. Elastic Process Investigation

The following query was used:

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

A specific query for `wevtutil.exe` also returned zero matching documents.

### Finding

No matching process documents were returned for the tested process names.

The investigation therefore does not claim that Elastic observed `wevtutil.exe`.

The local execution of the controlled command is known from the successful command execution and resulting Event ID 1102, but the process execution was not independently observed through the queried Elastic process telemetry.

## 9. Evidence Assessment

### Confirmed

- Security logging was enabled.
- Existing Security events were present before the test.
- The controlled log-clear command completed successfully.
- Event ID 1102 was generated locally.
- Event ID 1102 was received by Elastic.
- The local and Elastic timestamps corresponded to the same activity.
- The affected host was `DESKTOP-9MMM37V`.
- Elastic populated `user.name` as `Dell`.

### Not Confirmed

- Elastic did not return process telemetry for `wevtutil.exe`.
- Elastic did not return process telemetry for `powershell.exe` or `pwsh.exe` through the tested query.
- The exact process-level execution mechanism was not established from the queried Elastic process data.
- `SubjectUserName` and `SubjectDomainName` were not populated in the captured Elastic 1102 event.

### Unknown

- Whether the action would be authorized or unauthorized in a real environment.
- Whether additional process telemetry existed outside the queried dataset or time range.
- The complete authentication context immediately preceding the event after the local Security log was cleared.


