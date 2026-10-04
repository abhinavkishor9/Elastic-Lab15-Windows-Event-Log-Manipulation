# Lab 15 — Troubleshooting Notes

## Issue 1 — Process Telemetry Query Returned Zero Documents

### Query

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

### Result

```text
0 documents processed
```

A specific search for `wevtutil.exe` also returned zero matching documents.

### Troubleshooting Approach

The original process query was simplified by removing additional fields such as:

- `process.command_line`
- `process.parent.name`
- `process.parent.pid`

The final query used only:

- `@timestamp`
- `host.name`
- `user.name`
- `process.name`
- `process.pid`

Even with the simplified query, no matching process documents were returned.

### Interpretation

The result establishes only that the query returned zero matching process documents.

It does not prove that:

- `wevtutil.exe` did not execute.
- PowerShell did not execute.
- Process telemetry was never generated.
- No relevant process data exists in another dataset.

The correct finding is:

> No matching process telemetry was returned by the tested Elastic query.

## Issue 2 — Local Authentication Events Were Missing

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625,4672
} -MaxEvents 50 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Result

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Explanation

The query was executed after the Security log had been cleared.

Previously stored Security events were therefore no longer available through the local Security log.

This should not be interpreted as proof that:

- no successful logons occurred,
- no failed logons occurred,
- no privileged activity occurred.

It only shows that those events were not available locally after the log was cleared.

## Issue 3 — Elastic Still Detected Event ID 1102

Elastic returned one Event ID 1102 document:

| Field | Value |
|---|---|
| `@timestamp` | Oct 4, 2026 @ 06:19:37.864 |
| `host.name` | `desktop-9mmm37v` |
| `user.name` | `Dell` |
| `event.code` | `1102` |

This demonstrates that centralized telemetry captured the generated event independently of the current contents of the endpoint's local Security log.

## Issue 4 — Subject Fields Were Empty

The captured Elastic event showed:

```text
winlog.event_data.SubjectUserName
-

winlog.event_data.SubjectDomainName
-
```

The investigation therefore does not assign a specific Windows event subject account from those fields.

The available `user.name` value was:

```text
Dell
```

This should be treated as observed event context rather than a complete reconstruction of the Windows event subject fields.

## Troubleshooting Conclusion

The lab successfully generated and detected Event ID 1102.

The main investigation limitation was the absence of matching process telemetry for the tested process names.

The final evidence-based conclusion is:

> The Security log clearing was confirmed, but the exact process-level execution evidence was not available in the queried Elastic telemetry.
