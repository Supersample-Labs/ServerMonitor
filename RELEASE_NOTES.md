# Server Monitor v1.4.2

Self-contained Windows x64 release; no separate .NET runtime installation is required.

- Added one-time **Configure this PC (admin)** setup via Windows UAC. The short-lived helper starts local WinRM, sets Automatic startup, and appends only the selected HTTP destination to TrustedHosts.
- Password fields now clearly indicate saved credentials. Connection/threshold edits retain encrypted passwords without re-entry; new entries replace them, and Windows account-name casing changes preserve the credential.
- Enabled Windows monitors now automatically check source readiness before saving. Canceled approval and policy failures are handled without elevating the monitoring worker.
- Added a read-only source-PC readiness check for Windows PowerShell/CIM support, the local WinRM service, and HTTP destination trust.
- Added reviewable source setup commands for administrators, preserving existing TrustedHosts entries and limiting additions to the selected destination. System changes are applied only through the explicitly approved setup helper.
- Windows resource tests now include source readiness diagnostics in a resizable full-text result window.
- Added resizable details panes, full-text windows, and copy support for monitors and events so CPU, memory, and all disk readings remain readable.
- Unchanged refreshes preserve details text selection, and event refreshes retain the selected event.

Includes the existing Windows resource, SNMP, TCP/UDP, certificate, HTTPS, SMTP, tray, and Windows service features. Existing databases remain compatible. Stop the desktop app/service and back up the database before replacing the executable. Update the installed copy for service deployments.

Validation covers long result display, refresh selection preservation, source readiness/trust matching, generated command syntax without executing system changes, real local PowerShell/CIM inspection, and the existing application regression suite. Use Test Windows resources to validate the destination listener, credentials, and permissions in your environment.
