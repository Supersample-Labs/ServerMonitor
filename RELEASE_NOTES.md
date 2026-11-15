# Server Monitor v1.4.0

Self-contained Windows x64 release. Extract the Windows ZIP and run ServerMonitor.exe; no separate .NET runtime installation is required.

- Windows Server CPU, physical memory, and fixed-drive utilization checks using read-only CIM/WMI queries over WinRM.
- Independent warning and critical thresholds, selected drive letters, notification severity filtering, and a test button.
- HTTPS WinRM with certificate validation, Windows authentication, and machine-protected stored credentials.
- SNMP v2c numeric polling with severity alerts, a searchable metric catalog, live instance discovery, and vendor MIB JSON import.
- Existing TCP, UDP, TLS/HTTPS, private certificate, SMTP reminder/recovery, tray, and Windows service features.

The binary ZIP contains only the executable, README, and third-party notices. Source code and SHA-256 checksums are attached separately. Databases, credentials, test logs, and local monitor settings are excluded.

Existing databases upgrade automatically. Stop the app and service and back up the database before replacing the executable. For installed service deployments, update the installed copy as well. Keep the database beside the active executable.

Validation: the published executable passes the application self-test suite, including Windows resource thresholds, protected credentials, query serialization and cancellation, SNMP discovery, SQLite migration, TCP/UDP/TLS/HTTPS, SMTP, and WinForms initialization. Real remote WinRM listeners, credentials, and permissions must be tested in your environment.
