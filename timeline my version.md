# Investigation Timeline


| Time | Source | Event | Evidence / Interpretation |
|---|---|---|---|
| 06:12:07 | Windows Security | Event ID 4616 | System time was changed; observed in the pre-test Security log baseline |
| 06:18:51 | PowerShell | Host and user context | `desktop-9mmm37v\dell`; host `DESKTOP-9MMM37V` |
| 06:19:xx | PowerShell | Controlled log-clear activity | `wevtutil cl Security` completed successfully |
| 06:19:37 | Windows Security | Event ID 1102 | The audit log was cleared |
| 06:19:37.864 | Elastic | Event ID 1102 | Elastic received the corresponding log-clear event |
| After 06:19:37 | Windows Security | Authentication/privilege query | No 4624, 4625, or 4672 events returned locally after the Security log was cleared |
| After 06:19:37 | Elastic | Process telemetry search | No matching `wevtutil.exe`, `powershell.exe`, or `pwsh.exe` process documents returned |

