using System.Diagnostics;
using Microsoft.Win32;

namespace ServerMonitor;
public sealed class MainForm : Form
{
    readonly Store store;readonly bool startHidden;CancellationTokenSource cancellation=new();Task? worker;
    readonly System.Windows.Forms.Timer refreshTimer=new(){Interval=2000};readonly NotifyIcon tray=new(){Visible=true,Text="Server Monitor",Icon=AppIcons.Tray};
    readonly DataGridView checks=Ui.Grid(),events=Ui.Grid();readonly TextBox search=new(){Width=230,PlaceholderText="Filter by host or name…"};readonly CheckBox issues=new(){Text="Problems only",AutoSize=true,Margin=new(10,9,10,0)};
    readonly Label summary=Ui.Label("No monitors yet",13,true),workerLabel=Ui.Label("Starting monitor…",9),serviceLabel=Ui.Label("",11,true),footer=Ui.Label("",9);
    readonly Button install,remove;readonly CheckBox startup=new(){Text="Start the tray app when I sign in",AutoSize=true};
    long lastEvent;bool exiting,refreshing;string fingerprint="";List<MonitorCheck> latest=[];
    public MainForm(Store database,bool hidden)
    {
        store=database;startHidden=hidden;Text="Server Monitor — server & certificate monitoring";Icon=AppIcons.Application;Font=new("Segoe UI",10);BackColor=Ui.Paper;ForeColor=Ui.Ink;Size=new(1450,950);MinimumSize=new(1100,750);StartPosition=FormStartPosition.CenterScreen;
        var root=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new(20)};root.RowStyles.Add(new(SizeType.AutoSize));root.RowStyles.Add(new(SizeType.AutoSize));root.RowStyles.Add(new(SizeType.Percent,100));root.RowStyles.Add(new(SizeType.Absolute,46));Controls.Add(root);
        var header=new TableLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=2,Margin=Padding.Empty};header.ColumnStyles.Add(new(SizeType.Percent,100));header.ColumnStyles.Add(new(SizeType.AutoSize));
        var title=new TableLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,RowCount=2,Margin=Padding.Empty};
        title.ColumnStyles.Add(new(SizeType.Percent,100));title.RowStyles.Add(new(SizeType.AutoSize));title.RowStyles.Add(new(SizeType.AutoSize));
        var heading=Ui.Label("SERVER MONITOR",23,true);heading.Name="AppHeading";heading.Margin=new(0,0,12,8);
        var subtitle=Ui.Label("TCP / UDP availability   ·   HTTPS website health   ·   TLS certificate expiry   ·   SMTP alerting",10);subtitle.Name="AppSubtitle";subtitle.Margin=new(0,0,12,18);subtitle.Dock=DockStyle.Fill;
        title.Controls.Add(heading,0,0);title.Controls.Add(subtitle,0,1);header.Controls.Add(title,0,0);var hide=Ui.Button("Hide to tray",(_,_)=>HideToTray());hide.Anchor=AnchorStyles.Top|AnchorStyles.Right;header.Controls.Add(hide,1,0);
        root.Controls.Add(header,0,0);summary.Margin=new(0,4,0,16);root.Controls.Add(summary,0,1);
        var tabs=new TabControl {Dock=DockStyle.Fill,Padding=new(20,10)};root.Controls.Add(tabs,0,2);
        var monitors=new TabPage("Monitors"){BackColor=Color.White,Padding=new(12)};tabs.TabPages.Add(monitors);
        var checkLayout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=3};checkLayout.RowStyles.Add(new(SizeType.Absolute,50));checkLayout.RowStyles.Add(new(SizeType.Percent,100));checkLayout.RowStyles.Add(new(SizeType.Absolute,38));monitors.Controls.Add(checkLayout);
        var toolbar=new FlowLayoutPanel {Dock=DockStyle.Fill,WrapContents=false};toolbar.Controls.Add(Ui.Button("+ Add monitor",(_,_)=>Edit(null),true));toolbar.Controls.Add(Ui.Button("Edit",(_,_)=>Edit(Selected())));toolbar.Controls.Add(Ui.Button("Remove",(_,_)=>Remove()));toolbar.Controls.Add(Ui.Button("Check now",(_,_)=>Safe(()=>{store.RequestChecks();footer.Text="Checks queued for the active worker.";})));toolbar.Controls.Add(search);toolbar.Controls.Add(issues);checkLayout.Controls.Add(toolbar,0,0);
        checks.Columns.Add("Name","MONITOR");checks.Columns.Add("Host","HOST : PORT");checks.Columns.Add("Kind","TYPE");checks.Columns.Add("Status","STATUS");checks.Columns.Add("Expiry","CERTIFICATE EXPIRES");checks.Columns.Add("Latency","MS");checks.Columns.Add("Checked","LAST CHECKED");checks.Columns.Add("Detail","DETAILS");checks.Columns[0].FillWeight=100;checks.Columns[1].FillWeight=120;checks.Columns[2].FillWeight=65;checks.Columns[3].FillWeight=95;checks.Columns[4].FillWeight=110;checks.Columns[5].FillWeight=40;checks.Columns[6].FillWeight=100;checks.Columns[7].FillWeight=180;
        checks.CellDoubleClick+=(_,e)=>{if(e.RowIndex>=0)Edit(Selected());};checkLayout.Controls.Add(checks,0,1);checkLayout.Controls.Add(workerLabel,0,2);search.TextChanged+=(_,_)=>RenderChecks();issues.CheckedChanged+=(_,_)=>RenderChecks();
        var eventPage=new TabPage("Events"){BackColor=Color.White,Padding=new(12)};tabs.TabPages.Add(eventPage);events.Columns.Add("At","TIME");events.Columns.Add("Name","MONITOR");events.Columns.Add("Status","EVENT");events.Columns.Add("Detail","DETAILS");events.Columns[0].FillWeight=100;events.Columns[1].FillWeight=100;events.Columns[2].FillWeight=85;events.Columns[3].FillWeight=300;eventPage.Controls.Add(events);
        var smtp=new TabPage("SMTP alerts"){BackColor=Color.White};smtp.Controls.Add(new SmtpPanel(store));tabs.TabPages.Add(smtp);
        var background=new TabPage("Background & service"){BackColor=Color.White,Padding=new(25),AutoScroll=true};tabs.TabPages.Add(background);
        var serviceContent=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=1};background.Controls.Add(serviceContent);serviceContent.Controls.Add(Ui.Label("Keep watch in the background",20,true));
        var explanation=Ui.Label("Closing the window keeps Server Monitor in the system tray. Monitoring and notifications continue while you are signed in. Use Exit from the tray to stop desktop monitoring.\n\nInstall the Windows service to check hosts and deliver SMTP emails even when no user is signed in. The service starts automatically with Windows. Tray balloons require a signed-in desktop session; SMTP works without one.",11);explanation.MaximumSize=new(950,0);serviceContent.Controls.Add(explanation);serviceContent.Controls.Add(serviceLabel);
        var serviceButtons=new FlowLayoutPanel {AutoSize=true,Dock=DockStyle.Top,Padding=new(0,10,0,0)};install=Ui.Button("Install / start Windows service",async(_,_)=>await ServiceAction(true),true);remove=Ui.Button("Remove Windows service",async(_,_)=>await ServiceAction(false));serviceButtons.Controls.AddRange([install,remove]);serviceContent.Controls.Add(serviceButtons);
        var location=Ui.Label($"Service installation: {Paths.InstallDirectory}\nService name: {ServiceManager.Name}\nDatabase: {store.PathName}\n\nInstalling requests Windows administrator approval, copies the app and your initial configuration into the protected service folder, then opens that installed copy. If a database already exists there, it is retained. Removing the service retains the installed app and database and resumes desktop monitoring.",10);location.MaximumSize=new(950,0);serviceContent.Controls.Add(location);
        try{using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");startup.Checked=key?.GetValue("ServerMonitor")!=null;}catch{}
        startup.Margin=new(0,18,0,12);startup.CheckedChanged+=(_,_)=>Safe(()=>{using var key=Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");if(startup.Checked)key.SetValue("ServerMonitor",$"\"{Environment.ProcessPath}\" --tray");else key.DeleteValue("ServerMonitor",false);});serviceContent.Controls.Add(startup);
        serviceContent.Controls.Add(Ui.Button("Open app folder",(_,_)=>Process.Start(new ProcessStartInfo("explorer.exe"){ArgumentList={Paths.DirectoryPath},UseShellExecute=true})));
        var help=new TabPage("Guide"){BackColor=Color.White,Padding=new(25)};tabs.TabPages.Add(help);var helpText=Ui.Label("STATUS COLORS\nGreen: the TCP/UDP service answered, the TLS certificate is valid and has more than 30 days remaining, and HTTPS returns an accepted HTTP status.\nRed: connection failure, UDP no response, expired/expiring certificate (≤30 days), invalid TLS certificate, or an unexpected HTTP status.\nGray: waiting for a first result or disabled. Selecting a row keeps its health color.\n\nUDP CHECKS\nDNS mode expects a matching DNS response. For other protocols choose Custom and supply the correct request payload. Optionally require a hexadecimal response prefix. Silence can mean filtering or an unsupported probe, so it is labeled NO RESPONSE and triggers an alert rather than being called definitively offline.\n\nHTTPS WEBSITES\nHTTPS combines the connection, TLS certificate, and an anonymous HTTP GET. Default accepted status is 200-399; configure a path such as /health and an exact status range when editing. Redirects are evaluated without following them. All components must pass for a green result.\n\nPRIVATE CERTIFICATES\nSelect Private Certificate to track SAML signing or generic internal certificates by a manually assigned expiration (local date and time). No hostname or certificate file is required. The entry turns red at 30 days or less and when expired, using the same notifications and SMTP reminders. Update its expiration after renewal. This tracks expiry only, without checking certificate validity or trust.\n\nTLS CERTIFICATES\nDirect TLS endpoints only; STARTTLS protocols are not supported. SNI can differ from the connection hostname/IP. Expiry, not-yet-valid, hostname, and chain errors are flagged. Revocation is not checked. An expiry warning remains red even if another TLS validation error is also present (details show it).\n\nALERT DELIVERY\nConfigure an SMTP relay and send a test email. A first failure alerts immediately; successful delivery suppresses repeated emails until the reminder interval or another status transition. Recovery emails are optional. Delivery failures retry after five minutes. Events retain the latest 5,000 entries.\n\nDATA & PORTABILITY\nServerMonitor.db is beside the active executable. The journal file is part of SQLite crash recovery; do not delete it while monitoring. Back up the database with the app and service stopped. SMTP passwords use Windows machine DPAPI, so moving the database to another computer requires re-entering the password. Service mode uses the LocalService account and machine network access.\n\nThe computer must remain powered on and awake. Windows notifications can be suppressed by Focus Assist or notification settings.",10);helpText.MaximumSize=new(1000,0);help.AutoScroll=true;help.Controls.Add(helpText);
        footer.Text=store.PathName;footer.ForeColor=Ui.Muted;root.Controls.Add(footer,0,3);
        var menu=new ContextMenuStrip();menu.Items.Add("Open Server Monitor",null,(_,_)=>Restore());menu.Items.Add("Check now",null,(_,_)=>Safe(store.RequestChecks));menu.Items.Add(new ToolStripSeparator());menu.Items.Add("Exit desktop app",null,(_,_)=>ExitDesktop());tray.ContextMenuStrip=menu;tray.DoubleClick+=(_,_)=>Restore();tray.BalloonTipClicked+=(_,_)=>Restore();
        refreshTimer.Tick+=async(_,_)=>await RefreshData();Shown+=async(_,_)=>{lastEvent=store.Events(0,1).FirstOrDefault()?.Id??0;worker=Task.Run(()=>new MonitorEngine(store,false).Run(cancellation.Token));refreshTimer.Start();await RefreshData();if(startHidden)Hide();};FormClosing+=OnClosing;
    }
    MonitorCheck? Selected()=>checks.CurrentRow?.Tag as MonitorCheck;
    void Safe(Action action){try{action();}catch(Exception ex){MessageBox.Show(this,ex.Message,"Server Monitor",MessageBoxButtons.OK,MessageBoxIcon.Error);}}
    void Edit(MonitorCheck? item){using var dialog=new CheckDialog(item);if(dialog.ShowDialog(this)==DialogResult.OK)Safe(()=>{store.Save(dialog.Value);fingerprint="";_ = RefreshData();});}
    void Remove(){var item=Selected();if(item==null)return;if(MessageBox.Show(this,$"Remove '{item.Name}'? Its historical events will remain.","Remove monitor",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes)Safe(()=>{store.Remove(item.Id);fingerprint="";_=RefreshData();});}
    void RenderChecks()
    {
        long? selected=Selected()?.Id;int scroll=checks.FirstDisplayedScrollingRowIndex;checks.Rows.Clear();
        foreach(var c in latest.Where(c=>(!issues.Checked || c.Enabled&&c.Status is not (Health.Pending or Health.Healthy)) && (c.Name.Contains(search.Text,StringComparison.OrdinalIgnoreCase)||c.Host.Contains(search.Text,StringComparison.OrdinalIgnoreCase))))
        {
            var status=c.Enabled?c.Status:Health.Pending;int i=checks.Rows.Add(c.Name,c.Kind==CheckKind.PrivateCertificate?"Manual expiration":c.Host+":"+c.Port,c.Kind==CheckKind.PrivateCertificate?"Private Certificate":c.Kind.ToString(),c.Enabled?Ui.Display(c.Status):"DISABLED",c.Expires?.LocalDateTime.ToString("yyyy-MM-dd HH:mm")??"—",c.LatencyMs?.ToString()??"—",c.LastChecked?.LocalDateTime.ToString("MM-dd HH:mm:ss")??"Waiting",c.Detail);var row=checks.Rows[i];row.Tag=c;
            row.DefaultCellStyle.BackColor=row.DefaultCellStyle.SelectionBackColor=Ui.Back(status);row.DefaultCellStyle.ForeColor=row.DefaultCellStyle.SelectionForeColor=Ui.Fore(status);row.Cells[1].Style.Font=new Font("Segoe UI",9,FontStyle.Bold);row.Cells[7].ToolTipText=c.Detail;if(c.Id==selected)checks.CurrentCell=row.Cells[0];
        }
        if(scroll>=0&&scroll<checks.Rows.Count)checks.FirstDisplayedScrollingRowIndex=scroll;
    }
    async Task RefreshData()
    {
        if(refreshing||exiting)return;refreshing=true;
        var trayIcon=AppIcons.Tray;if(!ReferenceEquals(tray.Icon,trayIcon))tray.Icon=trayIcon;
        try
        {
            var data=await Task.Run(()=>(Checks:store.Checks(),Events:store.Events(),Worker:store.LeaseOwner(),Service:ServiceManager.Status()));if(exiting||IsDisposed)return;latest=data.Checks;
            var mark=System.Text.Json.JsonSerializer.Serialize(latest);if(mark!=fingerprint){fingerprint=mark;RenderChecks();}
            int healthy=latest.Count(c=>c.Enabled&&c.Status==Health.Healthy),problem=latest.Count(c=>c.Enabled&&c.Status is not (Health.Pending or Health.Healthy));summary.Text=$"{latest.Count} monitors     •     {healthy} healthy     •     {problem} need attention";
            workerLabel.Text=$"Active worker: {data.Worker.Split('·')[0].Trim()}   |   Windows service: {data.Service}   |   Refresh every 2 seconds";serviceLabel.Text="Windows service: "+data.Service;remove.Enabled=data.Service!="Not installed";install.Text=data.Service=="Not installed"?"Install Windows service":"Start Windows service";
            var newEvents=data.Events.Where(e=>e.Id>lastEvent).OrderBy(e=>e.Id).ToArray();if(newEvents.Length>0)lastEvent=newEvents.Max(e=>e.Id);
            var notifications=newEvents.Where(e=>Enum.TryParse<Health>(e.Status,out _)||e.Status=="Email failed").ToArray();
            if(notifications.Length>0){var e=notifications.Last();tray.ShowBalloonTip(6000,$"Server Monitor: {(e.Problem?"attention needed":"healthy")}",notifications.Length==1?$"{e.Name}: {e.Status}\n{e.Detail}":$"{notifications.Length} status changes. Latest: {e.Name} — {e.Status}. Open Server Monitor for details.",e.Problem?ToolTipIcon.Warning:ToolTipIcon.Info);}
            events.Rows.Clear();foreach(var e in data.Events){var i=events.Rows.Add(e.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss"),e.Name,e.Status,e.Detail);events.Rows[i].Cells[3].ToolTipText=e.Detail;if(e.Problem)events.Rows[i].DefaultCellStyle.ForeColor=Color.Firebrick;}
            tray.Text=$"Server Monitor: {healthy} healthy, {problem} problems";
        }
        catch(Exception ex){footer.Text="Refresh failed: "+ex.Message;}
        finally{refreshing=false;}
    }
    void HideToTray(){Hide();tray.ShowBalloonTip(3500,"Server Monitor is still monitoring","Double-click the monitor pulse icon to reopen. Use Exit in the tray menu to stop the desktop app.",ToolTipIcon.Info);}
    void Restore(){Show();WindowState=FormWindowState.Normal;Activate();}
    void OnClosing(object? sender,FormClosingEventArgs e)
    {
        if(e.CloseReason==CloseReason.UserClosing&&!exiting){e.Cancel=true;HideToTray();return;}
        cancellation.Cancel();refreshTimer.Stop();tray.Visible=false;tray.Dispose();
    }
    async void ExitDesktop()
    {
        if(exiting)return;exiting=true;refreshTimer.Stop();cancellation.Cancel();if(worker!=null)try{await worker;}catch{}Close();
    }
    async Task ServiceAction(bool enable)
    {
        install.Enabled=remove.Enabled=false;
        try
        {
            if(enable&&!ServiceManager.IsInstalledLocation())
            {
                cancellation.Cancel();if(worker!=null)await worker;
                await ServiceManager.Elevate("--install-service");
                if(startup.Checked){using var key=Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");key.SetValue("ServerMonitor",$"\"{Paths.InstalledExecutable}\" --tray");}
                Process.Start(new ProcessStartInfo(Paths.InstalledExecutable){UseShellExecute=true});exiting=true;Close();return;
            }
            await ServiceManager.Elevate(enable?"--install-service":"--remove-service");
            footer.Text=enable?"Windows service started. Monitoring continues without a sign-in.":"Windows service removed. Desktop monitoring will resume.";
        }
        catch(Exception ex)
        {
            MessageBox.Show(this,ex.Message,"Service action",MessageBoxButtons.OK,MessageBoxIcon.Error);
            if(cancellation.IsCancellationRequested){cancellation.Dispose();cancellation=new();worker=Task.Run(()=>new MonitorEngine(store,false).Run(cancellation.Token));footer.Text="Service action did not complete; desktop monitoring resumed.";}
        }
        finally{if(!IsDisposed){install.Enabled=remove.Enabled=true;await RefreshData();}}
    }
    protected override void Dispose(bool disposing)
    {
        if(disposing){cancellation.Cancel();refreshTimer.Dispose();tray.Dispose();}
        base.Dispose(disposing);
    }
}
