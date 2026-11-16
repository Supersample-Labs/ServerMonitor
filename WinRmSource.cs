using System.Text.Json;
using System.Text.RegularExpressions;

namespace ServerMonitor;
public sealed record WinRmSourceSnapshot(string PowerShellVersion="",bool CimAvailable=false,string ServiceStatus="Unknown",string StartupType="Unknown",string TrustedHosts="",bool TrustedHostsReadable=false,string Error="");
public static class WinRmSource
{
    internal const string InspectScript="""
    $ErrorActionPreference='Stop'
    [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
    $result=[ordered]@{PowerShellVersion=$PSVersionTable.PSVersion.ToString();CimAvailable=$false;ServiceStatus='Unknown';StartupType='Unknown';TrustedHosts='';TrustedHostsReadable=$false;Error=''}
    try { Get-Command Get-CimInstance,New-CimSession,New-CimSessionOption -ErrorAction Stop | Out-Null; $result.CimAvailable=$true } catch { $result.Error=$_.Exception.Message }
    try {
        $service=Get-Service WinRM -ErrorAction Stop
        $result.ServiceStatus=[string]$service.Status
        $result.StartupType=[string]$service.StartType
        if ($service.Status -eq 'Running') {
            Import-Module Microsoft.WSMan.Management -ErrorAction Stop
            $result.TrustedHosts=[string](Get-Item -LiteralPath 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value
            $result.TrustedHostsReadable=$true
        }
    } catch { $result.Error+=(' '+$_.Exception.Message) }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
    """;
    public static async Task<WinRmSourceSnapshot> Inspect(CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            var output=await WindowsProbe.Execute(InspectScript,"{}",deadline.Token);
            if(output.ExitCode!=0)throw new IOException("Windows PowerShell could not inspect this PC's WinRM prerequisites.");
            return JsonSerializer.Deserialize<WinRmSourceSnapshot>(output.Output,WindowsProbe.JsonOptions)??throw new IOException("No readiness report returned.");
        }
        catch(OperationCanceledException) when(!ct.IsCancellationRequested){return new(Error:"The local readiness check exceeded 12 seconds. Verify Windows PowerShell 5.1 is available and allowed to run.");}
        catch(Exception ex) when(ex is IOException or JsonException or System.ComponentModel.Win32Exception){return new(Error:ex.Message);}
    }
    public static bool IsTrusted(string entries,string host) => !string.IsNullOrWhiteSpace(host) && entries.Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Any(entry=>Regex.IsMatch(host,"^"+Regex.Escape(entry).Replace("\\*",".*").Replace("\\?",".")+"$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant));
    public static bool NeedsAttention(WinRmSourceSnapshot snapshot,string host,bool useSsl) => !snapshot.CimAvailable || snapshot.ServiceStatus!="Running" || snapshot.StartupType!="Automatic" || snapshot.Error.Length>0 || !useSsl && (!snapshot.TrustedHostsReadable || !IsTrusted(snapshot.TrustedHosts,host));
    public static string Report(WinRmSourceSnapshot snapshot,string host,bool useSsl,bool workerAccount)
    {
        string trust=useSsl?"Not required for HTTPS (server certificate must be trusted and match its hostname).":!snapshot.TrustedHostsReadable?"Could not read the source PC's TrustedHosts setting.":IsTrusted(snapshot.TrustedHosts,host)?$"'{host}' matches an existing TrustedHosts entry.":$"'{host}' is not listed. HTTP with a local/workgroup account requires this trust; domain Kerberos may work without it.";
        return $"Source PC: {Environment.MachineName}\r\nInspection account: {Environment.UserDomainName}\\{Environment.UserName}\r\nDestination: {(host.Length==0?"Not entered":host)}\r\nTransport: {(useSsl?"HTTPS":"HTTP")}\r\n\r\nWindows PowerShell: {(snapshot.PowerShellVersion.Length==0?"Unavailable / not confirmed":snapshot.PowerShellVersion)}\r\nCIM cmdlets: {(snapshot.CimAvailable?"Available":"Unavailable / not confirmed")}\r\nLocal WinRM service: {snapshot.ServiceStatus} (startup: {snapshot.StartupType})\r\nTrustedHosts: {trust}\r\n"+
            (snapshot.Error.Length==0?"":"\r\nInspection error: "+snapshot.Error+"\r\n")+
            "\r\nThe local WinRM service is needed to manage/read this PC's WSMan configuration. Starting it does not create an inbound listener. This inspection makes no system changes.\r\n"+
            (workerAccount?"\r\nAuthentication uses the active worker account. The Windows service runs as LocalService by default and normally lacks remote account credentials. This desktop inspection does not prove the service account has access.\r\n":"\r\nUse the destination computer name in a local username, for example SURFACE\\Administrator.\r\n")+
            "\r\nConfigure this PC requests Windows administrator approval to set local WinRM to Automatic, start it, and add only the selected HTTP destination to TrustedHosts. Existing trust entries are preserved. The app and monitoring service keep their normal accounts.\r\n\r\nRun Test Windows resources to verify actual destination authentication and all enabled resource queries. A local readiness check alone cannot confirm remote listener, permissions, or data access.";
    }
    public static string SetupCommands(string host,bool useSsl)
    {
        if(!useSsl && Uri.CheckHostName(host)==UriHostNameType.Unknown)throw new ArgumentException("Enter a valid destination hostname or IP before generating HTTP trust commands.");
        string commands="# Run Windows PowerShell as administrator ON THE SOURCE PC running Server Monitor.\r\n# Start local WinRM and keep it available after reboot. This does not create a listener or change firewall rules.\r\nSet-Service -Name WinRM -StartupType Automatic -ErrorAction Stop\r\nStart-Service -Name WinRM -ErrorAction Stop\r\nImport-Module Microsoft.WSMan.Management -ErrorAction Stop\r\n";
        if(!useSsl)
        {
            string quoted=host.Replace("'","''");
            commands+=$"\r\n# Trust only this named destination for HTTP/local-account authentication; preserve existing entries.\r\n$destination = '{quoted}'\r\n$existing = (Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction Stop).Value\r\nif (@($existing -split ',' | ForEach-Object {{ $_.Trim() }}) -notcontains $destination) {{\r\n    Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value $destination -Concatenate -ErrorAction Stop\r\n}}\r\nGet-Item WSMan:\\localhost\\Client\\TrustedHosts\r\n";
        }
        return commands;
    }
}
