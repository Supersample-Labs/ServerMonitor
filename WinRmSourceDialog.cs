namespace ServerMonitor;
public sealed class WinRmSourceDialog : Form
{
    readonly string host;readonly bool useSsl,workerAccount;
    readonly DetailsViewer viewer=new(false);
    readonly Button recheck=Ui.Button("Recheck this PC"),setup=Ui.Button("View setup commands"),configure=Ui.Button("Configure this PC (admin)",primary:true);
    readonly List<Button> closingButtons=[];
    readonly CancellationTokenSource lifetime=new();
    bool checking,configuring;
    bool CanConfigure => Uri.CheckHostName(host)!=UriHostNameType.Unknown;
    public WinRmSourceDialog(string hostname,bool https,bool useWorkerAccount,bool duringSave=false)
    {
        host=hostname;useSsl=https;workerAccount=useWorkerAccount;Text="WinRM source PC readiness";Font=new("Segoe UI",10);BackColor=Color.White;Size=new(1000,730);MinimumSize=new(800,500);StartPosition=FormStartPosition.CenterParent;MinimizeBox=false;
        viewer.Padding=new(14);viewer.ShowDetails("Checking this PC…","Inspecting Windows PowerShell, CIM cmdlets, the local WinRM service, and HTTP trust for the selected destination. Configure this PC requests Windows administrator approval before setting WinRM to Automatic, starting it, and adding the selected HTTP destination to TrustedHosts. Existing trust entries are preserved.");Controls.Add(viewer);
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=duringSave?96:65,Padding=new(12,6,6,4),FlowDirection=FlowDirection.RightToLeft};
        var close=Ui.Button(duringSave?"Continue saving":"Close",(_,_)=>{DialogResult=DialogResult.OK;Close();});closingButtons.Add(close);buttons.Controls.Add(close);
        if(duringSave){var back=Ui.Button("Back to monitor",(_,_)=>{DialogResult=DialogResult.Cancel;Close();});closingButtons.Add(back);buttons.Controls.Add(back);CancelButton=back;}else CancelButton=close;
        buttons.Controls.AddRange([configure,recheck,setup]);Controls.Add(buttons);
        setup.Enabled=useSsl || CanConfigure;configure.Enabled=false;
        recheck.Click+=async(_,_)=>await Check();configure.Click+=async(_,_)=>await Configure();setup.Click+=(_,_)=>{using var commands=new DetailsDialog("Source PC setup commands","Review these commands, then run in Windows PowerShell as administrator on the source PC",WinRmSource.SetupCommands(host,useSsl),formatReadings:false);commands.ShowDialog(this);};
        Shown+=async(_,_)=>await Check();FormClosing+=(_,e)=>{if(configuring)e.Cancel=true;};FormClosed+=(_,_)=>lifetime.Cancel();
    }
    async Task Check()
    {
        if(checking)return;checking=true;recheck.Enabled=configure.Enabled=false;
        try
        {
            var snapshot=await WinRmSource.Inspect(lifetime.Token);
            if(!IsDisposed)viewer.ShowDetails(WinRmSource.NeedsAttention(snapshot,host,useSsl)?"Source PC: review the items below":"Source PC: local prerequisites checked",WinRmSource.Report(snapshot,host,useSsl,workerAccount));
        }
        catch(OperationCanceledException) when(lifetime.IsCancellationRequested){}
        catch(Exception ex){if(!IsDisposed)viewer.ShowDetails("Source PC check failed",ex.Message);}
        finally{checking=false;if(!IsDisposed){recheck.Enabled=!configuring;configure.Enabled=!configuring&&CanConfigure;}}
    }
    async Task Configure()
    {
        if(configuring || checking || !CanConfigure)return;
        configuring=true;configure.Enabled=recheck.Enabled=setup.Enabled=false;foreach(var button in closingButtons)button.Enabled=false;
        viewer.ShowDetails("Waiting for Windows administrator approval…",$"Configure this source PC for {host}.\r\n\r\nThe approved helper sets local WinRM startup to Automatic and starts the service."+(useSsl?" HTTPS leaves TrustedHosts unchanged.":$" It adds only '{host}' to TrustedHosts and preserves existing entries.")+"\r\n\r\nThe app and monitoring service retain their normal accounts. Setup does not create a listener or change firewall rules. Cancel the Windows prompt to decline setup.");
        try
        {
            var result=await WinRmSourceSetup.Configure(host,useSsl);
            await Check();
            if(!IsDisposed && !result.Success)viewer.ShowDetails(result.Canceled?"Source setup canceled":"Source setup incomplete",result.Message+"\r\n\r\n"+viewer.FullText);
        }
        catch(Exception ex){if(!IsDisposed)viewer.ShowDetails("Source setup could not run",ex.Message+"\r\n\r\nRecheck this PC or use View setup commands for manual configuration.");}
        finally
        {
            configuring=false;if(!IsDisposed){configure.Enabled=CanConfigure;recheck.Enabled=true;setup.Enabled=useSsl||CanConfigure;foreach(var button in closingButtons)button.Enabled=true;}
        }
    }
    protected override void Dispose(bool disposing){if(disposing){lifetime.Cancel();lifetime.Dispose();}base.Dispose(disposing);}
}
