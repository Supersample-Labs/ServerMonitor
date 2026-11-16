# Server Monitor v1.5.0

Self-contained Windows x64 release; no separate .NET runtime installation is required.

- Increased the default polling concurrency to 16, configurable from 1 to 64 in the new **Monitoring settings** tab.
- Enabled independent scheduling by default: newly due checks can start as slots become available without waiting for the running group. Each monitor has at most one active probe; oldest results receive priority.
- Enabled separate email delivery by default, with 2 configurable delivery slots (1–8). Slow SMTP no longer occupies polling slots.
- Persisted results form a latest-state alert queue. Pending alerts survive restart and retry after five minutes without waiting for the next host poll. Intermediate unsent states are coalesced; recovery after an in-flight failure is delivered when enabled.
- Added configurable email attempt timeout (default 30 seconds), new-check timeout (5 seconds), and new-WinRM timeout (30 seconds). Existing saved monitor timeouts and SMTP credentials are preserved.
- Added switches for independent scheduling and the separate email queue. Changes apply to the active desktop/service worker without restart; mode changes drain active work first.
- Cancellation drains work before releasing the database lease, preventing overlapping workers during normal handoff.

Validation includes scheduler concurrency/no-overlap, blocked probes, blocked SMTP, recovery during delivery, restart delivery, a 100-check simulated outage, settings persistence, and the existing loopback protocol/database/alert regression suite. This is not a production capacity benchmark. Real WinRM destinations and SMTP relays require validation in your environment.

Stop the desktop app/service and back up its database before replacing the executable. Update the installed copy for service deployments. Existing databases upgrade automatically.
