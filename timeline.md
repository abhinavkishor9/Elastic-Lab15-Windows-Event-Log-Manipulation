# Lab 15 — Investigation Timeline

## Timeline

| Time | Source | Event | Evidence / Interpretation |
|---|---|---|---|
| 06:12:07 | Windows Security | Event ID 4616 | System time was changed; observed in the pre-test Security log baseline |
| 06:18:51 | PowerShell | Host and user context | `desktop-9mmm37v\dell`; host `DESKTOP-9MMM37V` |
| 06:19:xx | PowerShell | Controlled log-clear activity | `wevtutil cl Security` completed successfully |
| 06:19:37 | Windows Security | Event ID 1102 | The audit log was cleared |
| 06:19:37.864 | Elastic | Event ID 1102 | Elastic received the corresponding log-clear event |
| After 06:19:37 | Windows Security | Authentication/privilege query | No 4624, 4625, or 4672 events returned locally after the Security log was cleared |
| After 06:19:37 | Elastic | Process telemetry search | No matching `wevtutil.exe`, `powershell.exe`, or `pwsh.exe` process documents returned |

## Detailed Timeline

### 06:12:07 — Pre-Test Security Activity

Windows Security logs contained Event ID 4616:

```text
The system time was changed.
```

This was part of the existing Security event baseline and was not generated as part of the log-clearing test.

### 06:18:51 — Test Context Recorded

The lab recorded:

```text
User:
desktop-9mmm37v\dell

Host:
DESKTOP-9MMM37V

Time:
04 October 2026 06:18:51
```

### 06:19:xx — Controlled Log-Clear Activity

The following command was executed:

```powershell
wevtutil cl Security
```

The command completed successfully.

### 06:19:37 — Windows Event ID 1102

Windows generated:

```text
Event ID: 1102
Provider: Microsoft-Windows-Eventlog
Message: The audit log was cleared.
```

This is the primary local evidence confirming the log-clearing activity.

### 06:19:37.864 — Elastic Detection

Elastic recorded:

```text
event.code: 1102
host.name: desktop-9mmm37v
user.name: Dell
@timestamp: Oct 4, 2026 @ 06:19:37.864
```

This independently confirmed that the event reached the SIEM.

### After 06:19:37 — Local Authentication Query

The following events were queried:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon
- Event ID 4672 — Special privileges assigned

No matching events were returned from the local Security log.

The result occurred after the Security log had been cleared and therefore cannot be used to conclude that those activities never occurred.

### After 06:19:37 — Process Telemetry Investigation

Elastic was searched for:

- `wevtutil.exe`
- `powershell.exe`
- `pwsh.exe`

The query returned:

```text
0 documents processed
```

Therefore, process-level attribution was not established through the queried Elastic telemetry.

## Investigation Sequence

```text
06:18:51
    |
    +-- Host and user context recorded
    |
    v
06:19:xx
    |
    +-- Controlled log-clear command
    |   wevtutil cl Security
    |
    v
06:19:37
    |
    +-- Windows Event ID 1102
    |   The audit log was cleared
    |
    v
06:19:37.864
    |
    +-- Elastic Event ID 1102
    |   Host: desktop-9mmm37v
    |   User: Dell
    |
    v
Post-Test
    |
    +-- Local 4624/4625/4672 query
    |   No events returned
    |
    +-- Elastic process query
        No matching process documents
```

## Final Timeline Assessment

### Confirmed

- Controlled Security log clearing occurred.
- Windows generated Event ID 1102.
- Elastic received Event ID 1102.
- The Windows and Elastic timestamps corresponded to the same activity.
- The affected host was `DESKTOP-9MMM37V`.

### Not Confirmed

- Elastic did not provide matching process telemetry for `wevtutil.exe`.
- The exact process-level mechanism was not independently established.

### Unknown

- Whether the activity would be authorized or malicious in a real-world environment.
- Whether additional process telemetry existed outside the queried dataset or time range.

## Final Assessment

**Confirmed:** Windows Security log clearing.

**Confirmed:** Elastic detection of Event ID 1102.

**Not confirmed:** Specific process attribution through Elastic process telemetry.

**Unknown:** Intent or authorization of the activity outside the controlled lab context.
