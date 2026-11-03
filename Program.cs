using System.Diagnostics;
using System.ServiceProcess;

namespace ServerMonitor;
static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if(args.Contains("--self-test"))return SelfTests.Run();
        if(args.Contains("--service"))
        {
            try{ServiceBase.Run(new MonitorService());return 0;}catch{return 1;}
        }
        ApplicationConfiguration.Initialize();
        if(args.Contains("--install-service")||args.Contains("--remove-service"))
        {
            try
            {
                if(args.Contains("--install-service")){var i=Array.IndexOf(args,"--owner");if(i<0||i+1>=args.Length)throw new ArgumentException("Missing installing user identity.");ServiceManager.Install(args[i+1]);}
                else ServiceManager.Remove();return 0;
            }
            catch(Exception ex){MessageBox.Show(ex.Message,"Server Monitor — service action failed",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        }
        try
        {
            if(ServiceManager.LegacyInstalled())throw new InvalidOperationException("The earlier Port Sentinel service is still installed. Remove it using the earlier app before starting Server Monitor. See the upgrade steps in README.md to retain your monitors and SMTP settings.");
            // Launch the installed copy after a service installation so desktop and service always share one database.
            if(!ServiceManager.IsInstalledLocation() && ServiceManager.Exists() && File.Exists(Paths.InstalledExecutable))
            {Process.Start(new ProcessStartInfo(Paths.InstalledExecutable){UseShellExecute=true});return 0;}
            using var instance=new Mutex(true,"Local\\ServerMonitorUI-"+Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Paths.Database.ToUpperInvariant())))[..20],out var created);
            if(!created){MessageBox.Show("Server Monitor is already running in this session. Look for its shield icon in the system tray.","Server Monitor");return 0;}
            Paths.ImportLegacyDatabase();var store=new Store(Paths.Database);store.Initialize();Application.Run(new MainForm(store,args.Contains("--tray")));return 0;
        }
        catch(Exception ex){MessageBox.Show($"Server Monitor could not start.\n\n{ex.Message}\n\nDatabase: {Paths.Database}\nExtract the portable app to a writable folder, or launch the installed copy.","Server Monitor",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
}
