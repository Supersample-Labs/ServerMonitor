using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace ServerMonitor;
public sealed record WinRmSetupResult(bool Success,bool Canceled,string Message);
public static class WinRmSourceSetup
{
    public const string Action="--configure-winrm-source";
    internal const string SuccessMarker="SERVER_MONITOR_WINRM_CONFIGURED";
    public static (string Host,bool UseSsl) ParseArguments(string[] args)
    {
        if(args.Length!=3 || args[0]!=Action || args[1] is not ("http" or "https"))throw new ArgumentException("Invalid WinRM source setup arguments.");
        if(Uri.CheckHostName(args[2])==UriHostNameType.Unknown)throw new ArgumentException("Enter a destination hostname or IP without a URL, path, wildcard, or port.");
        return(args[2],args[1]=="https");
    }
    public static ProcessStartInfo ElevationStartInfo(string executable,string host,bool useSsl)
    {
        _=ParseArguments([Action,useSsl?"https":"http",host]);
        if(string.Equals(Path.GetFileName(executable),"dotnet.exe",StringComparison.OrdinalIgnoreCase) || !Path.IsPathFullyQualified(executable) || !string.Equals(Path.GetExtension(executable),".exe",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Run the packaged ServerMonitor.exe to configure this PC.");
        var start=new ProcessStartInfo(executable){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
        start.ArgumentList.Add(Action);start.ArgumentList.Add(useSsl?"https":"http");start.ArgumentList.Add(host);return start;
    }
    public static async Task<WinRmSetupResult> Configure(string host,bool useSsl)
    {
        var start=ElevationStartInfo(Environment.ProcessPath??"",host,useSsl);
        try
        {
            // ShellExecute waits for UAC consent; keep the desktop UI responsive while Windows asks the user.
            using var process=await Task.Run(()=>Process.Start(start))??throw new IOException("Could not start the administrator setup helper.");
            await process.WaitForExitAsync();
            return process.ExitCode==0?new(true,false,"Source WinRM configuration completed. Checking readiness again…"):new(false,false,"Source setup did not complete. Review the administrator error, then recheck this PC. Any completed service changes remain in effect; it is safe to retry.");
        }
        catch(Win32Exception ex) when(ex.NativeErrorCode==1223){return new(false,true,"Windows administrator approval was canceled. The setup helper did not run.");}
    }
    public static string ConfigurationScript(string host,bool useSsl)
    {
        _=ParseArguments([Action,useSsl?"https":"http",host]);
        // Consent is collected by the app's Configure button and Windows UAC. The noninteractive helper must not prompt a second time.
        var commands=WinRmSource.SetupCommands(host,useSsl).Replace("-Concatenate -ErrorAction Stop","-Concatenate -Force -ErrorAction Stop").Replace("Start-Service -Name WinRM -ErrorAction Stop","Start-Service -Name WinRM -ErrorAction Stop\n$starting=Get-Service -Name WinRM -ErrorAction Stop\n$starting.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))");
        string verifyTrust=useSsl?"":$"\n$verifiedHosts=(Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction Stop).Value\nif (@($verifiedHosts -split ',' | ForEach-Object {{ $_.Trim() }}) -notcontains '{host.Replace("'","''")}') {{ throw 'The selected destination could not be verified in TrustedHosts.' }}\n";
        return "$ErrorActionPreference='Stop'\n"+commands+"\n$winrm=Get-Service -Name WinRM -ErrorAction Stop\n$winrm.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))\n$winrm.Refresh()\nif ([string]$winrm.StartType -ne 'Automatic') { throw 'WinRM startup mode could not be verified as Automatic.' }\n"+verifyTrust+"\n[Console]::Out.WriteLine('"+SuccessMarker+"')\n";
    }
    public static int RunElevated(string[] args)
    {
        try
        {
            var request=ParseArguments(args);
            using var identity=WindowsIdentity.GetCurrent();
            if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("WinRM source setup requires administrator permission. Use Configure this PC and approve the Windows prompt.");
            using var gate=new Mutex(false,@"Global\ServerMonitor.WinRmSourceSetup");
            bool acquired=false;
            try
            {
                try{acquired=gate.WaitOne(TimeSpan.FromSeconds(30));}catch(AbandonedMutexException){acquired=true;}
                if(!acquired)throw new IOException("Another WinRM source setup is running. Wait for it to finish and retry.");
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(90));
                var result=Task.Run(()=>WindowsProbe.Execute(ConfigurationScript(request.Host,request.UseSsl),"{}",deadline.Token)).GetAwaiter().GetResult();
                if(result.ExitCode!=0 || !result.Output.Contains(SuccessMarker,StringComparison.Ordinal))throw new IOException("Windows could not finish configuring local WinRM. Service or TrustedHosts settings may be controlled by policy. Recheck this PC for the current state; existing trust entries were preserved.");
                return 0;
            }
            finally{if(acquired)gate.ReleaseMutex();}
        }
        catch(Exception ex){MessageBox.Show(ex.Message,"Server Monitor — WinRM source setup failed",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
}
