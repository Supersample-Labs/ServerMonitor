# Server Monitor

A .NET 10 Windows Forms monitor for TCP/UDP ports, TLS certificates, HTTPS websites, SNMP values, and Windows server CPU, memory, and disk usage over WinRM. The Windows x64 release is self-contained: no separate .NET runtime installation is required.

## Start

1. Extract the ZIP to a writable local folder. Run `ServerMonitor.exe`.
2. Select **Add monitor**. Enter a name, hostname/IP, type, port, interval, and timeout. New monitors default to HTTPS on 443.
3. For a website, choose **HTTPS**. It combines TCP connectivity, certificate validity/expiry, and an anonymous HTTP GET over the same TLS connection. Set the path (default `/`) and acceptable HTTP status range (default **200-399**). A failure in any component is red and can alert.
4. For certificate-only checks, use a direct TLS port (typically 443). Set the optional TLS server name/SNI if connecting to an IP or a different DNS name.
5. For UDP, choose the built-in DNS probe or supply the service's correct request payload. Optionally specify an expected hexadecimal reply prefix.
6. Open **SMTP alerts**, configure your relay, send a test email, then save and enable alerting.

The app ships without preconfigured checks or SMTP destinations. It performs only the checks you add.

## Status and alert rules

| Color | Meaning |
| --- | --- |
| Green | TCP connected; a valid UDP probe response arrived; or a valid TLS certificate has more than 30 days left. HTTPS additionally requires an accepted HTTP status. |
| Red | TCP/TLS failure; UDP no response; certificate expires in **30 days or less**, is expired, is not yet valid, fails TLS chain/hostname validation, or HTTPS returns an unexpected status / incomplete response. |
| Gray | Pending first result or disabled monitor. |

UDP has no connection handshake. A timeout is labeled **NO RESPONSE**, is highlighted red, and can alert, but does not prove the host is offline. DNS mode sends a root NS query and checks the transaction ID and response flag. Custom mode accepts a nonempty response from the connected endpoint and optionally checks a byte prefix. A service can be reachable yet ignore an incorrect payload.

Certificate monitoring uses `SslStream` to inspect the peer certificate. Validation failures are recorded as unhealthy; the monitor does not send application credentials, cookies, or authentication headers. HTTPS uses only an anonymous GET and evaluates the response status even when certificate validation fails; such a certificate always keeps the result red. Direct TLS only: SMTP/IMAP/FTP STARTTLS negotiation, HTTP authentication, certificate pinning and revocation checks are outside this version's scope. Certificate-only checks send no HTTP request. Expiry dates are stored in UTC and displayed in local time. Days are measured as actual 24-hour periods.

SMTP is optional. STARTTLS is required by default, with implicit TLS and unencrypted trusted-relay modes also available. Authentication is optional. Recipients may be separated with semicolons or commas. The test email uses the form's current values; **Save SMTP settings** applies them to monitoring.

An initial failed check sends an alert. Successful delivery suppresses identical repeated alerts until the configured reminder interval (24 hours by default) or a change of failure status. Recovery emails are optional. Failed email delivery retries after five minutes. State survives process restarts in SQLite. Like other SMTP clients, a crash after relay acceptance but before recording success can produce a duplicate email on retry. The Events tab shows transitions and email outcomes, retaining the latest 5,000 events.

## Tray mode

Closing the main window hides it to the notification area and keeps the desktop worker running. Double-click the shield icon or select **Open Server Monitor** to restore it. Choose **Exit desktop app** in the tray menu to stop desktop monitoring. Optionally select **Start the tray app when I sign in** in Background & service.

Notifications use Windows tray balloons. They require an interactive session and can be suppressed by Windows notification settings or Focus Assist. When the service is running, an open tray app reads its persisted events and displays notifications. The service itself does not display UI in session 0.

## Windows service

Open **Background & service** and click **Install Windows service**. Windows asks for administrator approval. This is an explicit installation action; running the portable app does not create a service automatically.

- Service name: `ServerMonitorService`; display name: `Server Monitor`.
- Account: built-in `NT AUTHORITY\LocalService`.
- Startup: automatic, with restart-on-failure recovery.
- Installed executable: `%ProgramData%\ServerMonitor\ServerMonitor.exe`.
- Installed database: `%ProgramData%\ServerMonitor\ServerMonitor.db`, **beside the installed executable**.
- Initial installation copies your portable database using SQLite's backup API. If an installed database already exists, it is retained instead of overwritten.
- The app reopens the installed copy. Future launches of the portable copy redirect to it while the service exists. Use the installed copy thereafter to keep using the installed database.
- The installation folder restricts executable modification to Administrators/SYSTEM. The installing user and LocalService can access the database and persistent journal; the executables remain read-only to them unless elevated.
- A database lease prevents multiple workers sharing that database from performing duplicate checks. While the service is active, the desktop worker stands by.
- SMTP delivery continues without a signed-in user. The computer must remain on, awake, and connected to the monitored network and relay.

Click **Remove Windows service** to stop and delete the service entry. This also requests administrator approval. It retains the installed executable and database, and the running desktop app resumes monitoring. Exit the desktop app as well if all monitoring should stop. The optional tray startup setting is separate and can be unchecked independently.

The LocalService account uses the machine's network access, not your interactive VPN/profile or stored user credentials. Test your endpoints and SMTP relay from service mode on the intended deployment machine. Only the installing user is granted database editing access by default. A different interactive user may need an administrator to grant access or run the GUI elevated.

Service installation/removal is implemented, but the development test suite intentionally does **not** register a persistent service on the developer's computer. Administrator/UAC and signed-out delivery should be validated on your target Windows machine. If service creation succeeds but startup fails, the entry may remain; remove it using the GUI after reviewing the error.

## Storage and backups

`ServerMonitor.db` is created beside the active executable. It stores monitor definitions, SMTP settings, results, events, and worker coordination. SQLite uses a persistent rollback journal (`ServerMonitor.db-journal`) and a 15-second busy timeout for desktop/service coordination.

The SMTP password is encrypted with Windows DPAPI **machine scope** so the service and desktop can both decrypt it on the same computer. This is not a portable secret vault; protect access to the database. Copying it to a different computer requires re-entering the SMTP password. Other settings, including endpoint names and SMTP addresses, are ordinary SQLite data.

To back up or move a database, exit the desktop app and stop the service first. Retain the journal if present, particularly after an unclean shutdown. Do not place the active database on a network share, in a protected portable folder, or in a cloud-sync folder. Service mode installs to its dedicated local directory.

The executable is not code-signed. Windows may show a publisher/reputation prompt. It does not require an inbound firewall rule for normal outbound probes. This is an endpoint monitor rather than a protocol-complete application health check or an internet port scanner.

## Build from source

Requires a .NET 10 SDK and NuGet access on the build machine:

```powershell
.\build.ps1
```

Or:

```powershell
dotnet publish ServerMonitor.csproj -c Release -r win-x64 --self-contained true -o .\Release\ServerMonitor-win-x64
```

The single-file build embeds the .NET runtime, Windows Forms dependencies and native SQLite library. Native components are extracted by .NET into the user's/service account's temporary bundle cache on first launch. Keep the published executable in its chosen folder; the database path uses `AppContext.BaseDirectory`, not the extraction directory. Service installation from an ordinary non-published development apphost is not supported: use the self-contained published executable.

## Verification

Run the published executable with `--self-test`. It writes `ServerMonitor-selftest.log` beside itself and exits with code 0 on success. Tests use temporary databases and loopback servers; they do not send external emails or install a Windows service.

Tests cover TCP open/closed ports, custom UDP responses, silent UDP, DNS reply matching, a real local TLS handshake, the 30-day expiry boundary, expired/name-mismatched/future-dated certificates, SQLite CRUD and backup, stale-result rejection, worker lease handoff, machine DPAPI, alert suppression/reminders/recovery/retry, and SMTP delivery to a local test relay.

The desktop UI was visually checked with live local TCP/UDP endpoints to confirm green/red rows and inspected for monitor configuration, SMTP settings, and service controls. Real relay credentials and remote hosts must be configured and tested by the operator.

## HTTPS behavior

HTTPS sends an HTTP/1.1 GET over the connection whose certificate was inspected. The configured TLS name/SNI is also the HTTP Host name. Paths can include query strings; header injection and invalid paths are rejected. The timeout applies to the entire DNS, TCP, TLS, and HTTP-header sequence. Only headers are read, with size limits; the response body is not downloaded or checked. Redirects are evaluated as responses at the configured endpoint and are **not followed** to a different endpoint. HTTP 200-399 is the default healthy response range; choose 200-299 for strict success-only monitoring or another range for an intentional authentication/status response. HTTPS is red for 500 errors, unexpected HTTP status, malformed/truncated headers, or response timeouts, even when the certificate itself is healthy.

Version 1.1 also replaces the fixed-height title container with an auto-sized two-row layout so the subtitle has its own full-height row.

## Private certificate expiration tracking

Choose **Add monitor → Private Certificate**, enter a display name (for example, SAML signing certificate), and assign the expiration date and time in the computer’s local time zone. Host, port, and network settings are not needed. No certificate or private key is uploaded or stored.

The monitor is healthy with more than 30 days remaining, expiring at 30 days or less, and expired at the expiration instant. It uses the existing desktop notifications, SMTP alerts, reminders, and recovery settings. Monitoring must be running in the desktop app or Windows service. Update the assigned expiration after renewal. This is manual expiry tracking; it does not validate certificate trust or discover renewals. Existing databases upgrade automatically.

## SNMP OID monitoring

Choose **Add monitor > SNMP** for SNMP v2c GET polling over UDP (default 161). Configure the hostname/IP, read-only community, numeric OID with instance suffix, interval, and timeout. Devices must permit requests from the monitoring computer. SNMP v1/v3, traps, and rate conversion are not enabled. Use the picker below to discover table instances and resolve catalog names.

Configure warning and critical thresholds and select **At or above** or **At or below**. Equality triggers the severity; critical takes precedence. Critical must be above warning for rising values and below warning for falling values. Values use raw OID units: sysUpTime is hundredths of seconds and counters are cumulative. Integers, Counter32/64, Gauge32, TimeTicks, and numeric strings are supported. Nonnumeric values and agent errors are unhealthy; silence is NoResponse.

**Minimum alert severity** filters email and desktop notifications. Warning includes warning and critical; Critical suppresses warning notifications; None disables SNMP notifications. With Warning or Critical selected, connection/protocol/timeout failures still alert. Health and history remain visible regardless. Existing SMTP retries, reminders, and recovery settings apply. Recovery occurs when the value becomes healthy after a delivered problem alert.

SNMP v2c sends the community unencrypted and stores it in the local database. Restrict database access and use a trusted network. Protocol reference: [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html).

### Choosing SNMP metrics

In **Add monitor > SNMP**, enter the device address, port, and community, then select **Choose / discover metric**. The searchable built-in catalog covers system identity/uptime, interface states/counters, processor utilization, and storage. Availability depends on the device. Choose a scalar directly or select **Browse selected** to discover a table column's actual instances. **Discover metrics** walks the displayed subtree; it does not scan other hosts. Each scan stops at 512 readings or approximately 30 seconds, with a per-request timeout and Cancel scan button. Narrow the subtree for large devices. Partial results remain available on timeout. Numeric readings can become monitors; text readings help identify the device or instance.

The selected metric name and units are saved with the monitor and appear in results. Thresholds still compare raw numbers. Traffic counters are cumulative rather than bits/second, storage units are not percentages, and state codes are not a severity scale. Confirm the documented units and set thresholds before saving. Imported catalogs supply labels and descriptions, not automatic threshold defaults or conversions. Custom OID entry remains available.

### Vendor MIB catalogs

The picker accepts **PySMI JSON modules** or a simple JSON catalog. Imported definitions are saved in the application's database and included in its backups. Reimporting an OID updates its definition. Existing monitor names/units remain as selected until you choose the metric again. Imports are limited to 8 MiB / 10,000 definitions and are validated before saving.

To convert a vendor ASN.1 MIB on a development/admin computer, install the free [PySMI tool](https://docs.lextudio.com/pysmi/quick-start) and run its `mibdump` command, for example:

```powershell
mibdump --generate-mib-texts --destination-format=json --destination-directory=./catalogs --mib-source=file:///C:/MIBs MY-VENDOR-MIB
```

Supply the vendor's MIB and its required dependency modules. See the [PySMI command documentation](https://docs.lextudio.com/pysmi/docs/mibdump) for source/dependency options. In the picker select **Import MIB JSON** and choose the generated module JSON file. Repeat for additional modules. Raw `.mib`/`.txt` files and PySMI index files are not imported directly. PySMI is an optional preparation tool: users running Server Monitor do not need Python. Check the vendor's terms before redistributing its MIB definitions.

A simple catalog uses definition OIDs without instance suffixes; `scalar: true` adds `.0`, while `scalar: false` requires discovery or a custom instance:

```json
[
  {
    "oid": "1.3.6.1.4.1.32473.1",
    "name": "Example temperature",
    "units": "degrees C",
    "description": "Example only: replace with your device's documented definition.",
    "scalar": true
  }
]
```

SNMP communication and discovery use the MIT-licensed [SharpSnmpLib](https://github.com/lextudio/sharpsnmplib), bundled in the executable. The app currently exposes v2c configuration; v1/v3 and traps are not enabled. Common metric definitions follow [RFC 2790](https://www.rfc-editor.org/rfc/rfc2790.html) and [RFC 2863](https://www.rfc-editor.org/rfc/rfc2863.html).

## Windows Server resources over WinRM

Choose **Add monitor > Windows Server (WinRM)**. Enter a server hostname, choose the WinRM transport/port, and configure the authentication account. Set independent **CPU used %**, **Memory used %**, and **Disk used %** warning/critical thresholds. Each metric can be disabled; at least one must remain enabled. Defaults are warning at 80% used and critical at 90% used. Threshold equality triggers that severity. The highest severity among the enabled readings determines the monitor status; details list all evaluated readings.

Set **Drive letters** to `*` to monitor all fixed drives returned by `Win32_LogicalDisk`, or enter a comma-separated list such as `C:, D:`. Disk thresholds apply to each selected drive individually. A requested missing drive, missing CPU/memory value, invalid capacity, authentication error, or failed query is an unhealthy error rather than a healthy zero. Drive-letter volumes are supported; mount-point-only volumes are outside this check's scope.

Select **Test Windows resources** to query the form's current settings before saving. The test shows readings/errors without saving a monitor or sending email. New Windows checks default to a 30-second total timeout; this includes starting the local helper, connecting, and running the selected queries. Monitoring samples the current values on each interval; thresholds do not require a sustained breach or calculate historical averages.

### Connection and credentials

- **HTTPS** defaults to port **5986** and validates the server certificate, including its trust and hostname. Use the server's matching DNS name. There is no certificate-validation bypass.
- **HTTP** defaults to port **5985** and uses Windows Negotiate authentication with normal WinRM message protection. Basic authentication and unencrypted WinRM payloads are not enabled by the app. Domain Kerberos setups generally work best with DNS names; IP addresses/workgroups require an appropriate existing WinRM trust/authentication configuration.
- **Use worker's Windows account** authenticates as the active desktop or Windows service worker. The app's service runs as LocalService by default, which normally has no usable remote account credentials. Use an explicit Windows account for unattended remote checks, or an appropriately configured service identity.
- **Use a specific Windows account** accepts `DOMAIN\user`, `user@domain`, or `SERVER\user` as appropriate for your environment. Passwords use the same machine DPAPI protection as SMTP passwords. Leaving the password blank when editing preserves the saved password for the unchanged username. Changing the username requires a password. Selecting the worker account removes the stored explicit credential when saved. Moving the database to another computer requires re-entering passwords.

The target server must already have a working WinRM listener, network/firewall access from the monitoring computer, and an account authorized to read `root/cimv2` WMI/CIM data and the performance classes. An administrator should configure the listener, certificate, and least-privilege remote permissions according to your environment. This app does not enable remote management, open firewall rules, change TrustedHosts, or grant permissions automatically. Use the test button to diagnose access before enabling unattended monitoring. Refer to Microsoft's [CIM session documentation](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-5.1) and [WinRM authentication documentation](https://learn.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections).

### Measurements and alerts

| Metric | Measurement |
| --- | --- |
| CPU | `_Total.PercentProcessorTime` from `Win32_PerfFormattedData_PerfOS_Processor`; the provider's formatted CPU utilization sample. |
| Memory | Physical memory used: `100 * (1 - FreePhysicalMemory / TotalVisibleMemorySize)` from `Win32_OperatingSystem`. This is not committed/virtual memory usage. |
| Disk | Used capacity per fixed logical drive: `100 * (1 - FreeSpace / Size)` from `Win32_LogicalDisk` with `DriveType = 3`. |

**Minimum severity** filters both email and desktop notifications: Warning includes warning and critical, Critical suppresses warning notifications, and None disables notifications for this monitor. Authentication, query, and timeout failures alert at either Warning or Critical minimum. Current health/history remain visible regardless. Existing SMTP retry, reminder, and recovery settings apply to the monitor's aggregate status. If the failing component changes while overall severity stays the same, its details update and the existing reminder interval applies; create separate monitors with only one enabled metric if independent alert transitions are needed.

The monitor computer requires built-in **Windows PowerShell 5.1** and its CIM cmdlets. Each check starts a hidden local helper with fixed read-only queries and passes settings/credentials through stdin; it does not execute remote PowerShell scripts. Helper processes are canceled on timeout or shutdown. No additional PowerShell module, SNMP agent, or .NET installation is needed for the published self-contained application. Resource/serialization tests use fixtures and a mocked CIM session; a real remote server and its authentication/listener configuration must be validated with the test button in your environment.

### Source PC readiness and readable results (v1.4.1)

In a Windows monitor, select **Check this PC for WinRM** to inspect the computer running Server Monitor. It checks Windows PowerShell/CIM cmdlets, the local WinRM service and startup mode, and whether the selected HTTP destination matches this PC's TrustedHosts list. Domain Kerberos may work without a TrustedHosts entry; HTTPS uses server certificate trust instead. This is a read-only local check and does not prove that the destination account has permission to query resources.

If the source needs configuration, select **View setup commands**. Review/copy the commands and run them in **Windows PowerShell as administrator on the source PC**. They start the local WinRM service, set it to Automatic for unattended use, and for HTTP add only the selected destination while preserving existing TrustedHosts entries. The app does not execute these commands automatically, create inbound listeners, modify firewall rules, or disable security checks. A destination listener and remote permissions still need their own configuration.

**Test Windows resources** now performs this source inspection before the remote check and includes both reports in a scrollable, resizable result window. Source inspection has its own 12-second limit; the configured monitor timeout applies to the subsequent remote resource check. Regular background polls retain their existing timeout and do not run an extra readiness helper. The desktop inspection uses the signed-in app account; service-mode authentication may differ, especially with LocalService.

Select a row in **Monitors** or **Events** to read its entire result in the details pane below the table. Drag the divider to enlarge the pane. Use **Copy details** or **Open full details**, or double-click a monitor's DETAILS cell (an event can be double-clicked anywhere). Other monitor cells retain the existing double-click-to-edit behavior. Long results wrap and scroll, each semicolon-separated reading appears on a new line, and unchanged refreshes preserve text selection/scroll position. The selected event is retained when the event list refreshes.

### One-time administrator setup (v1.4.2)

When saving an enabled **Windows Server (WinRM)** monitor, the app checks source readiness automatically. If local WinRM is stopped, its startup mode is not Automatic, CIM support is missing, or HTTP trust needs review, the source readiness dialog opens before saving. Choose **Back to monitor** to keep editing, or **Continue saving** to save without applying source changes (useful for offline targets or domain Kerberos configurations).

Select **Configure this PC (admin)** to request a Windows UAC prompt for a separate, short-lived helper. Once approved, it sets only the local WinRM service to Automatic, starts it, and for HTTP adds the selected hostname/IP to TrustedHosts while preserving existing entries. HTTPS setup leaves TrustedHosts unchanged. Setup verifies the service/startup settings and selected trust entry, then exits. The desktop app and monitoring service retain their original accounts; neither is permanently elevated. No destination username/password is passed to the elevated helper.

Canceling UAC leaves the helper unstarted. Failed setup is shown as incomplete, and readiness is refreshed so partial changes can be reviewed. Repeating setup is safe and does not duplicate the same destination. The setup dialog stays open until the approved helper completes; Windows policy can still prevent configuration. Source setup does not create inbound listeners, open firewall rules, disable TLS checks, enable Basic authentication, change remote account permissions, or configure the target PC.

Existing enabled monitors can use **Edit > Check this PC for WinRM > Configure this PC (admin)**. Saving Windows settings rechecks readiness; routine polling does not repeatedly prompt for elevation. Use **Test Windows resources** afterward to validate actual destination data access. Explicit monitoring credentials are still required when the default LocalService worker cannot authenticate remotely.

### Editing saved credentials

Windows and SMTP password fields show **Saved password — leave blank to keep** when a credential is stored for the selected account. Editing a host, port, resource threshold, or other connection setting keeps that password if the field is left blank. Enter a new password to replace it. Windows account matching ignores letter case and surrounding whitespace; switching to a different account requires its password. Selecting the worker account removes the explicit Windows credential when saved. SMTP has a separate **Remove the saved password** option. Changing an SMTP username does not silently reuse a different account's credential.

Password hints never decrypt or display the stored password. New passwords are protected with Windows DPAPI before saving to SQLite; unchanged edits retain the existing encrypted value. DPAPI uses machine scope so the service can authenticate, and database file permissions remain important. The SQLite database as a whole is not encrypted.

## Monitoring performance (v1.5.0)

Open **Monitoring settings** to tune the active desktop or service worker. Defaults apply automatically to existing databases:

| Setting | Default | Range |
| --- | --- | --- |
| Concurrent checks | 16 | 1–64 |
| Independent scheduling | Enabled | Enabled / disabled |
| Separate email queue | Enabled | Enabled / disabled |
| Concurrent emails | 2 | 1–8 |
| Email attempt timeout | 30 seconds | 1–120 seconds |
| New network-check timeout | 5 seconds | 1–60 seconds |
| New WinRM-check timeout | 30 seconds | 1–60 seconds |

Each monitor retains its own editable interval and timeout. Changing timeout defaults affects newly added monitors and type changes in the editor; existing saved timeouts are retained. Increasing concurrency can use more CPU, memory, network connections, and WinRM helper processes. There is no fixed maximum number of saved checks, but no production capacity guarantee; validate your workload on its deployment PC.

Independent scheduling considers due checks approximately every 250 ms and when work finishes. It starts the oldest completed checks first, up to the configured limit, without waiting for an entire batch. A monitor never has overlapping probes. Intervals are measured from the last completed result, so timeouts and a full worker pool can still make checks late. Disabling independent scheduling waits for the running group to finish before starting the next group.

Separate email delivery uses persisted check results as a latest-state queue, with at most one email in flight per monitor. Email waits do not occupy host-check slots. The worker re-evaluates alert eligibility independently of polling, including after restart; failed deliveries become eligible after five minutes. Repeated failures still follow reminder/suppression settings. A pending failure that recovers before email starts is replaced by the current healthy state; no recovery email is needed if no failure email was delivered. A failure email already in flight can still arrive, followed by recovery when enabled. This queue does not retain every intermediate status transition. Desktop event history continues to record transitions.

Disabling the separate queue sends email within the host-check slot and retries on subsequent polls. The concurrent-email setting applies only to the separate queue. Email timeout applies to both modes and test messages. Settings changes apply automatically: lower limits let current work finish, and scheduling/queue mode changes wait for active work to drain. Shutdown cancels and drains active checks and sends before releasing the database lease. As before, a crash or cancellation after relay acceptance but before recording success can cause a duplicate email.

For 100 simultaneously due checks that all take their full timeout, 16 slots need approximately 7 waves: about **35 seconds with 5-second timeouts** or **3.5 minutes with 30-second timeouts**, plus processing overhead. Add the wait until each check becomes due and actual email relay delivery time. These are calculations, not measured production guarantees. Monitoring and SMTP connectivity must survive the outage for remote email alerts to arrive.
