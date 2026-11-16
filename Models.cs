namespace ServerMonitor;

public enum CheckKind { TCP, UDP, Certificate, HTTPS, PrivateCertificate, SNMP, WindowsServer }
public enum Health { Pending, Healthy, Down, NoResponse, Expiring, Expired, InvalidCertificate, Error, HttpError, Warning, Critical }
public sealed record MonitorCheck
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 443;
    public CheckKind Kind { get; set; }
    public string TlsName { get; set; } = "";
    public int IntervalSeconds { get; set; } = 60;
    public int TimeoutSeconds { get; set; } = 5;
    public bool Enabled { get; set; } = true;
    public string UdpMode { get; set; } = "DNS";
    public string Payload { get; set; } = "";
    public bool HexPayload { get; set; }
    public string ExpectedHex { get; set; } = "";
    public string HttpPath { get; set; } = "/";
    public int HttpStatusMin { get; set; } = 200;
    public int HttpStatusMax { get; set; } = 399;
    public DateTimeOffset? ManualExpiration { get; set; }
    public SnmpSettings Snmp { get; set; } = new();
    public WindowsServerSettings Windows { get; set; } = new();
    public long Revision { get; set; }
    public Health Status { get; set; } = Health.Pending;
    public string Detail { get; set; } = "Not checked yet";
    public DateTimeOffset? LastChecked { get; set; }
    public DateTimeOffset? Expires { get; set; }
    public long? LatencyMs { get; set; }
    public string LastAlertStatus { get; set; } = "";
    public DateTimeOffset? LastAlert { get; set; }
    public DateTimeOffset? LastAttempt { get; set; }
}
public sealed record CheckResult(Health Status, string Detail, DateTimeOffset CheckedAt, long? LatencyMs = null, DateTimeOffset? Expires = null)
{
    public bool Problem => Status is not (Health.Healthy or Health.Pending);
}
public sealed record SnmpSettings
{
    public string Community { get; set; } = "public";
    public string Oid { get; set; } = "1.3.6.1.2.1.1.3.0";
    public string MetricName { get; set; } = "";
    public string Units { get; set; } = "";
    public decimal Warning { get; set; } = 80;
    public decimal Critical { get; set; } = 90;
    public bool LowerIsWorse { get; set; }
    public string MinimumSeverity { get; set; } = "Warning";
}
public sealed record ResourceThreshold
{
    public bool Enabled { get; set; } = true;
    public decimal Warning { get; set; } = 80;
    public decimal Critical { get; set; } = 90;
}
public sealed record WindowsServerSettings
{
    public bool UseSsl { get; set; } = true;
    public bool UseWorkerAccount { get; set; } = true;
    public string Username { get; set; } = "";
    public string ProtectedPassword { get; set; } = "";
    public ResourceThreshold Cpu { get; set; } = new();
    public ResourceThreshold Memory { get; set; } = new();
    public ResourceThreshold Disk { get; set; } = new();
    public string Drives { get; set; } = "*";
    public string MinimumSeverity { get; set; } = "Warning";
}
public sealed record SmtpSettings
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string Security { get; set; } = "StartTls";
    public string Username { get; set; } = "";
    public string ProtectedPassword { get; set; } = "";
    public string From { get; set; } = "";
    public string Recipients { get; set; } = "";
    public int ReminderHours { get; set; } = 24;
    public bool Recovery { get; set; } = true;
}
public sealed record MonitorEvent(long Id, DateTimeOffset At, string Name, string Status, string Detail, bool Problem, bool Notify = true);
public sealed record MonitoringSettings
{
    public int ConcurrentChecks { get; set; } = 16;
    public bool IndependentScheduling { get; set; } = true;
    public bool SeparateAlerts { get; set; } = true;
    public int ConcurrentEmails { get; set; } = 2;
    public int EmailTimeoutSeconds { get; set; } = 30;
    public int DefaultTimeoutSeconds { get; set; } = 5;
    public int DefaultWindowsTimeoutSeconds { get; set; } = 30;
    public MonitoringSettings Normalize() => this with {
        ConcurrentChecks=Math.Clamp(ConcurrentChecks,1,64),ConcurrentEmails=Math.Clamp(ConcurrentEmails,1,8),
        EmailTimeoutSeconds=Math.Clamp(EmailTimeoutSeconds,1,120),DefaultTimeoutSeconds=Math.Clamp(DefaultTimeoutSeconds,1,60),
        DefaultWindowsTimeoutSeconds=Math.Clamp(DefaultWindowsTimeoutSeconds,1,60)};
}
public static class Paths
{
    public static string DirectoryPath => AppContext.BaseDirectory;
    public static string Database => Path.Combine(DirectoryPath, "ServerMonitor.db");
    public static string InstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ServerMonitor");
    public static string InstalledExecutable => Path.Combine(InstallDirectory, "ServerMonitor.exe");
    public static void ImportLegacyDatabase(string? directory=null)
    {
        directory??=DirectoryPath;
        var legacy=Path.Combine(directory,"PortSentinel.db");var destination=Path.Combine(directory,"ServerMonitor.db");
        if(!File.Exists(destination) && File.Exists(legacy))
        {
            new Store(legacy).Backup(destination);
            var imported=new Store(destination);imported.Initialize();imported.RequestChecks();
            using var connection=imported.Open();using var cmd=connection.CreateCommand();cmd.CommandText="DELETE FROM Lease";cmd.ExecuteNonQuery();
        }
    }
}
