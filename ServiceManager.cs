using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;

namespace ServerMonitor;
public static class ServiceManager
{
    public const string Name="ServerMonitorService";
    public static bool LegacyInstalled()
    {
        try{using var legacy=new ServiceController("PortSentinelMonitor");_=legacy.Status;return true;}
        catch(InvalidOperationException){return false;}
    }
    public static string Status()
    {
        try {using var svc=new ServiceController(Name);return svc.Status.ToString();}
        catch(InvalidOperationException){return "Not installed";}
        catch(Exception ex){return "Unavailable: "+ex.Message;}
    }
    public static bool Exists()=>Status()!="Not installed";
    public static bool IsRunning()=>Status() is "Running" or "StartPending" or "ContinuePending";
    public static bool IsInstalledLocation()=>string.Equals(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),Path.TrimEndingDirectorySeparator(Paths.InstallDirectory),StringComparison.OrdinalIgnoreCase);
    static void VerifyServicePath()
    {
        if(!Exists())return;
        var binary=Microsoft.Win32.Registry.GetValue($@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{Name}","ImagePath",null) as string;
        if(!string.Equals(binary,$"\"{Paths.InstalledExecutable}\" --service",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("A different service already uses the Server Monitor service name. Its configuration will not be changed.");
    }
    public static async Task Elevate(string action)
    {
        var p=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"};
        p.ArgumentList.Add(action);p.ArgumentList.Add("--owner");p.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
        using var process=Process.Start(p)??throw new IOException("Could not start the administrator action.");
        await process.WaitForExitAsync();if(process.ExitCode!=0)throw new InvalidOperationException("The service action failed or was cancelled. See the administrator error dialog for details.");
    }
    static void Command(params string[] args)
    {
        using var p=new Process {StartInfo=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"sc.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}};
        foreach(var a in args)p.StartInfo.ArgumentList.Add(a);p.Start();var output=p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd();p.WaitForExit();if(p.ExitCode!=0)throw new IOException(output.Trim());
    }
    static void ProtectDirectory(string ownerSid)
    {
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})
            acl.AddAccessRule(new(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        foreach(var sid in new[]{new SecurityIdentifier(ownerSid),new SecurityIdentifier(WellKnownSidType.LocalServiceSid,null)})
            acl.AddAccessRule(new(sid,FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));new DirectoryInfo(Paths.InstallDirectory).SetAccessControl(acl);
    }
    static void AllowData(string path,string ownerSid)
    {
        if(File.Exists(path) && (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("The installation contains a linked data file. Use a clean service installation folder.");
        if(!File.Exists(path))File.WriteAllBytes(path,[]);
        var info=new FileInfo(path);var acl=new FileSecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})acl.AddAccessRule(new(sid,FileSystemRights.FullControl,AccessControlType.Allow));
        foreach(var sid in new[]{new SecurityIdentifier(ownerSid),new SecurityIdentifier(WellKnownSidType.LocalServiceSid,null)})
            acl.AddAccessRule(new(sid,FileSystemRights.Modify,AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));
        info.SetAccessControl(acl);
    }
    public static void Install(string ownerSid)
    {
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("Administrator rights are required to install the service.");
        if(LegacyInstalled())throw new InvalidOperationException("Remove the earlier Port Sentinel service using the earlier app before installing the Server Monitor service.");
        _=new SecurityIdentifier(ownerSid);VerifyServicePath();
        if(Directory.Exists(Paths.InstallDirectory))
        {
            var directory=new DirectoryInfo(Paths.InstallDirectory);
            if((directory.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("The service folder must not be a junction or symbolic link.");
            var existingOwner=directory.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            if(!Equals(existingOwner,new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null))&&!Equals(existingOwner,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)))throw new IOException("The service folder already exists and is not owned by Administrators or SYSTEM. Rename it before installing Server Monitor.");
        }
        Directory.CreateDirectory(Paths.InstallDirectory);ProtectDirectory(ownerSid);
        if(!IsInstalledLocation())
        {
            if(Exists())throw new InvalidOperationException("The installed service already exists. Launch its installed ServerMonitor.exe to manage it.");
            if(File.Exists(Paths.InstalledExecutable)&&(File.GetAttributes(Paths.InstalledExecutable)&FileAttributes.ReparsePoint)!=0)throw new IOException("The installed executable must not be a linked file.");
            File.Copy(Environment.ProcessPath!,Paths.InstalledExecutable,true);
            var targetDb=Path.Combine(Paths.InstallDirectory,"ServerMonitor.db");
            if(File.Exists(targetDb)&&(File.GetAttributes(targetDb)&FileAttributes.ReparsePoint)!=0)throw new IOException("The installed database must not be a linked file.");
            if(!File.Exists(targetDb))new Store(Paths.Database).Backup(targetDb);
        }
        var database=Path.Combine(Paths.InstallDirectory,"ServerMonitor.db");
        foreach(var datafile in new[]{database,database+"-journal"})if(File.Exists(datafile)&&(File.GetAttributes(datafile)&FileAttributes.ReparsePoint)!=0)throw new IOException("The service database and journal must not be linked files.");
        new Store(database).Initialize();
        AllowData(database,ownerSid);AllowData(database+"-journal",ownerSid);
        if(!Exists())Command("create",Name,"binPath=",$"\"{Paths.InstalledExecutable}\" --service","start=","auto","obj=","NT AUTHORITY\\LocalService","DisplayName=","Server Monitor");
        else Command("config",Name,"start=","auto");
        Command("description",Name,"Monitors configured TCP/UDP endpoints and TLS certificates. Sends SMTP alerts without an interactive sign-in.");
        Command("failure",Name,"reset=","86400","actions=","restart/60000/restart/60000/restart/60000");
        using var service=new ServiceController(Name);service.Refresh();
        if(service.Status!=ServiceControllerStatus.Running){if(service.Status==ServiceControllerStatus.StopPending)service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(35));service.Start();service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(35));}
    }
    public static void Remove()
    {
        if(!Exists())return;VerifyServicePath();using var service=new ServiceController(Name);
        if(service.Status!=ServiceControllerStatus.Stopped){if(service.Status!=ServiceControllerStatus.StopPending)service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(40));}
        Command("delete",Name);
    }
}
public sealed class MonitorService : ServiceBase
{
    CancellationTokenSource? cancel;Task? task;
    public MonitorService(){ServiceName=ServiceManager.Name;CanStop=true;CanShutdown=true;AutoLog=true;}
    protected override void OnStart(string[] args)
    {
        var store=new Store(Paths.Database);store.Initialize();store.Event("Windows service","Started","Background monitoring started.");
        cancel=new();task=Task.Run(()=>new MonitorEngine(store,true).Run(cancel.Token));
    }
    protected override void OnStop()
    {
        try{RequestAdditionalTime(30000);}catch(InvalidOperationException){}
        cancel?.Cancel();try{task?.GetAwaiter().GetResult();}catch(OperationCanceledException){}
        try{new Store(Paths.Database).Event("Windows service","Stopped","Background monitoring stopped.");}catch{}
        cancel?.Dispose();
    }
    protected override void OnShutdown()=>OnStop();
}
