using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ServerMonitor;
public sealed record WindowsDisk(string Name,decimal? Size,decimal? FreeSpace);
public sealed record WindowsSnapshot(decimal? CpuPercent,decimal? MemoryTotalKB,decimal? MemoryFreeKB,List<WindowsDisk>? Disks,string? QueryError=null);
public static class WindowsProbe
{
    // All queries are fixed read-only CIM queries. Host and credentials are JSON on stdin, never executable text or command-line arguments.
    internal const string QueryScript="""
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $session = $null
    try {
        $config = [Console]::In.ReadToEnd() | ConvertFrom-Json
        $options = New-CimSessionOption -UseSsl:([bool]$config.UseSsl)
        $arguments = @{ComputerName=[string]$config.Host; Port=[int]$config.Port; SessionOption=$options; Authentication='Negotiate'; OperationTimeoutSec=[int]$config.TimeoutSeconds; ErrorAction='Stop'}
        if (-not $config.UseWorkerAccount) {
            $secure = ConvertTo-SecureString -String ([string]$config.Password) -AsPlainText -Force
            $arguments.Credential = New-Object System.Management.Automation.PSCredential([string]$config.Username, $secure)
        }
        $session = New-CimSession @arguments
        $result = [ordered]@{CpuPercent=$null; MemoryTotalKB=$null; MemoryFreeKB=$null; Disks=@()}
        if ($config.Cpu) {
            $processor = Get-CimInstance -CimSession $session -Namespace root/cimv2 -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name = '_Total'" -Property PercentProcessorTime -ErrorAction Stop | Select-Object -First 1
            $result.CpuPercent = $processor.PercentProcessorTime
        }
        if ($config.Memory) {
            $os = Get-CimInstance -CimSession $session -Namespace root/cimv2 -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -ErrorAction Stop | Select-Object -First 1
            $result.MemoryTotalKB = $os.TotalVisibleMemorySize
            $result.MemoryFreeKB = $os.FreePhysicalMemory
        }
        if ($config.Disk) {
            $result.Disks = @(Get-CimInstance -CimSession $session -Namespace root/cimv2 -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -Property DeviceID,Size,FreeSpace -ErrorAction Stop | ForEach-Object { @{Name=$_.DeviceID; Size=$_.Size; FreeSpace=$_.FreeSpace} })
        }
        [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 4 -Compress))
    } catch {
        [Console]::Out.WriteLine((@{QueryError=$_.Exception.Message} | ConvertTo-Json -Compress))
        exit 1
    } finally {
        if ($null -ne $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
    """;
    public static void Validate(WindowsServerSettings settings)
    {
        if(!settings.Cpu.Enabled && !settings.Memory.Enabled && !settings.Disk.Enabled)throw new ArgumentException("Enable at least one Windows resource metric.");
        foreach(var pair in new[]{("CPU",settings.Cpu),("Memory",settings.Memory),("Disk",settings.Disk)})
            if(pair.Item2.Enabled && (pair.Item2.Warning<0 || pair.Item2.Critical>100 || pair.Item2.Warning>=pair.Item2.Critical))throw new ArgumentException($"{pair.Item1}: set 0 ≤ warning < critical ≤ 100 percent used.");
        if(settings.MinimumSeverity is not ("Warning" or "Critical" or "None"))throw new ArgumentException("Choose a minimum Windows alert severity.");
        if(settings.Disk.Enabled)_=DriveNames(settings.Drives);
        if(!settings.UseWorkerAccount && (string.IsNullOrWhiteSpace(settings.Username)||string.IsNullOrEmpty(settings.ProtectedPassword)))throw new ArgumentException("Enter a Windows username and password, or use the worker's Windows account.");
        if(settings.Username.Length>256 || settings.Username.Any(char.IsControl))throw new ArgumentException("Enter a valid Windows username (DOMAIN\\user or user@domain).");
    }
    public static string[] DriveNames(string value)
    {
        if(value.Trim()=="*")return [];
        var drives=value.Split(',',StringSplitOptions.TrimEntries).Select(d=>d.ToUpperInvariant()).ToArray();
        if(drives.Length==0 || drives.Any(d=>!Regex.IsMatch(d,@"^[A-Z]:$",RegexOptions.CultureInvariant)))throw new ArgumentException("Enter * for all fixed drives, or drive letters such as C:, D:.");
        return drives.Distinct().ToArray();
    }
    public static decimal UsedPercent(decimal? total,decimal? free,string metric)
    {
        if(!total.HasValue || !free.HasValue || total<=0 || free<0 || free>total)throw new IOException($"{metric}: unavailable or invalid capacity data.");
        return 100m*(1m-free.Value/total.Value);
    }
    public static CheckResult Evaluate(WindowsServerSettings settings,WindowsSnapshot snapshot,DateTimeOffset now,long latency=0)
    {
        Validate(settings);
        if(!string.IsNullOrWhiteSpace(snapshot.QueryError))throw new IOException("WinRM query failed: "+snapshot.QueryError);
        var readings=new List<(string Name,decimal Value,ResourceThreshold Threshold)>();
        if(settings.Cpu.Enabled)
        {
            if(snapshot.CpuPercent is not >=0 or >100)throw new IOException("CPU utilization is missing or outside 0–100 percent.");
            readings.Add(("CPU",snapshot.CpuPercent.Value,settings.Cpu));
        }
        if(settings.Memory.Enabled)readings.Add(("Memory",UsedPercent(snapshot.MemoryTotalKB,snapshot.MemoryFreeKB,"Memory"),settings.Memory));
        if(settings.Disk.Enabled)
        {
            var all=snapshot.Disks??[];var requested=DriveNames(settings.Drives);
            if(all.Count==0)throw new IOException("No fixed drive capacity data returned.");
            foreach(var drive in requested)if(!all.Any(d=>string.Equals(d.Name,drive,StringComparison.OrdinalIgnoreCase)))throw new IOException($"Disk {drive}: requested drive was not returned by the server.");
            var selected=all.Where(d=>requested.Length==0 || requested.Contains(d.Name,StringComparer.OrdinalIgnoreCase)).OrderBy(d=>d.Name,StringComparer.OrdinalIgnoreCase);
            foreach(var disk in selected)readings.Add(($"Disk {disk.Name}",UsedPercent(disk.Size,disk.FreeSpace,$"Disk {disk.Name}"),settings.Disk));
        }
        var status=Health.Healthy;
        var details=readings.Select(r=>{
            var level=r.Value>=r.Threshold.Critical?Health.Critical:r.Value>=r.Threshold.Warning?Health.Warning:Health.Healthy;
            if(level==Health.Critical || level==Health.Warning && status==Health.Healthy)status=level;
            return $"{r.Name}: {r.Value.ToString("0.##",CultureInfo.InvariantCulture)}% used ({level}; warning ≥{r.Threshold.Warning.ToString(CultureInfo.InvariantCulture)}%, critical ≥{r.Threshold.Critical.ToString(CultureInfo.InvariantCulture)}%)";
        }).ToArray();
        return new(status,"Windows resources via WinRM; "+string.Join("; ",details),now,latency);
    }
    internal static readonly JsonSerializerOptions JsonOptions=new(){PropertyNameCaseInsensitive=true,NumberHandling=JsonNumberHandling.AllowReadingFromString};
    public static WindowsSnapshot Parse(string json) => JsonSerializer.Deserialize<WindowsSnapshot>(json,JsonOptions)??throw new IOException("Windows resource query returned no data.");
    public static async Task<CheckResult> Run(MonitorCheck check,Stopwatch watch,CancellationToken ct)
    {
        Validate(check.Windows);
        var w=check.Windows;
        var request=new {check.Host,check.Port,check.TimeoutSeconds,w.UseSsl,w.UseWorkerAccount,w.Username,Password=w.UseWorkerAccount?"":Secret.Unprotect(w.ProtectedPassword),Cpu=w.Cpu.Enabled,Memory=w.Memory.Enabled,Disk=w.Disk.Enabled};
        var output=await Execute(QueryScript,JsonSerializer.Serialize(request),ct);
        WindowsSnapshot snapshot;
        try{snapshot=Parse(output.Output);}catch(JsonException){throw new IOException("Windows PowerShell returned an invalid resource response. Verify Windows PowerShell 5.1 and the CIM cmdlets are available.");}
        if(output.ExitCode!=0 && string.IsNullOrWhiteSpace(snapshot.QueryError))throw new IOException("Windows PowerShell could not complete the WinRM query. Verify credentials, listener, and CIM permissions.");
        return Evaluate(w,snapshot,DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
    }
    internal static async Task<(int ExitCode,string Output)> Execute(string script,string json,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var executable=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","WindowsPowerShell","v1.0","powershell.exe");
        var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
        // A PowerShell 7 parent can pass incompatible module paths to Windows PowerShell 5.1.
        start.Environment["PSModulePath"]=Path.Combine(Path.GetDirectoryName(executable)!,"Modules");
        foreach(var argument in new[]{"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(script))})start.ArgumentList.Add(argument);
        using var process=new Process{StartInfo=start};process.Start();
        using var registration=ct.Register(()=>Kill(process));
        var output=ReadBounded(process.StandardOutput,1024*1024,process,ct);var error=ReadBounded(process.StandardError,32768,process,ct);
        try
        {
            await process.StandardInput.WriteAsync(json.AsMemory(),ct);process.StandardInput.Close();
            await Task.WhenAll(output,error,process.WaitForExitAsync(ct));ct.ThrowIfCancellationRequested();
            return (process.ExitCode,await output);
        }
        catch(Exception) when(ct.IsCancellationRequested){throw new OperationCanceledException(ct);}
        finally
        {
            Kill(process);
            try{await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));}catch(Exception ex) when(ex is TimeoutException or InvalidOperationException){}
            // Observe pipe tasks even when writing stdin or waiting for the child was canceled.
            try{await Task.WhenAll(output,error);}catch(Exception ex) when(ex is OperationCanceledException or IOException or ObjectDisposedException){}
        }
    }
    static async Task<string> ReadBounded(StreamReader reader,int limit,Process process,CancellationToken ct)
    {
        var result=new StringBuilder();var buffer=new char[4096];int read;
        while((read=await reader.ReadAsync(buffer.AsMemory(),ct))>0)
        {
            if(result.Length+read>limit){Kill(process);throw new IOException("Windows resource query exceeded its output limit.");}
            result.Append(buffer,0,read);
        }
        return result.ToString();
    }
    static void Kill(Process process){try{if(!process.HasExited)process.Kill(entireProcessTree:true);}catch(Exception ex) when(ex is InvalidOperationException or System.ComponentModel.Win32Exception){} }
}
