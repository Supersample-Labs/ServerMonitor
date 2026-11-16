namespace ServerMonitor;
public sealed class MonitoringPanel : UserControl
{
    readonly NumericUpDown checks=Ui.Number(16,1,64),emails=Ui.Number(2,1,8),emailTimeout=Ui.Number(30,1,120),
        timeout=Ui.Number(5,1,60),windowsTimeout=Ui.Number(30,1,60);
    readonly CheckBox independent=new(){Text="Schedule due checks without waiting for the running group",AutoSize=true},
        separate=new(){Text="Deliver email separately from host checks",AutoSize=true};
    readonly Label status=Ui.Label("",9);
    public MonitoringPanel(Store store)
    {
        Dock=DockStyle.Fill;AutoScroll=true;BackColor=Color.White;Padding=new(24);
        var grid=Ui.FormGrid();grid.MaximumSize=new(920,0);grid.ColumnStyles.Add(new(SizeType.Absolute,260));grid.ColumnStyles.Add(new(SizeType.Percent,100));
        Ui.Row(grid,"Concurrent checks (1–64)",checks);Ui.Row(grid,"Independent scheduling",independent);
        Ui.Row(grid,"Separate email queue",separate);Ui.Row(grid,"Concurrent emails (1–8)",emails);
        Ui.Row(grid,"Email timeout (seconds)",emailTimeout);Ui.Row(grid,"New check timeout (seconds)",timeout);
        Ui.Row(grid,"New WinRM timeout (seconds)",windowsTimeout);
        var buttons=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Top};
        buttons.Controls.Add(Ui.Button("Save monitoring settings",(_,_)=>{
            try{store.SaveMonitoring(new(){ConcurrentChecks=(int)checks.Value,IndependentScheduling=independent.Checked,SeparateAlerts=separate.Checked,
                ConcurrentEmails=(int)emails.Value,EmailTimeoutSeconds=(int)emailTimeout.Value,DefaultTimeoutSeconds=(int)timeout.Value,DefaultWindowsTimeoutSeconds=(int)windowsTimeout.Value});
                status.ForeColor=Color.DarkGreen;status.Text="Saved. Active checks finish normally; scheduling mode changes apply after active work finishes. Existing monitor timeouts are unchanged.";}
            catch(Exception ex){status.ForeColor=Color.Firebrick;status.Text=ex.Message;}
        },true));
        buttons.Controls.Add(Ui.Button("Restore recommended values",(_,_)=>{LoadValues(new());status.Text="Recommended values loaded. Select Save monitoring settings to apply.";}));
        var note=Ui.Label("Recommended: 16 concurrent checks, independent scheduling, and 2 separate email workers. Slow or unreachable hosts still occupy a check slot until their timeout. Increase concurrency only as your PC and network allow.\n\nThe email queue keeps the latest pending status per monitor in the database. A recovery before a failure email starts replaces that pending failure; an already sending email may still arrive and is followed by recovery when enabled. Failed delivery retries after five minutes, even between host polls. SMTP must remain reachable for email to arrive.\n\nDisabling independent scheduling waits for the running group before starting another group. Disabling the separate queue sends email within the host-check slot. Timeout defaults apply to newly added monitors; each monitor's interval and timeout remain editable in Add / Edit monitor.",10);
        note.MaximumSize=new(900,0);status.MaximumSize=new(900,0);
        var content=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Top,ColumnCount=1};
        content.Controls.Add(Ui.Label("Monitoring performance",20,true));content.Controls.Add(grid);content.Controls.Add(buttons);content.Controls.Add(status);content.Controls.Add(note);Controls.Add(content);
        separate.CheckedChanged+=(_,_)=>emails.Enabled=separate.Checked;
        LoadValues(store.Monitoring());
    }
    void LoadValues(MonitoringSettings s)
    {
        checks.Value=s.ConcurrentChecks;independent.Checked=s.IndependentScheduling;separate.Checked=s.SeparateAlerts;
        emails.Value=s.ConcurrentEmails;emails.Enabled=s.SeparateAlerts;emailTimeout.Value=s.EmailTimeoutSeconds;
        timeout.Value=s.DefaultTimeoutSeconds;windowsTimeout.Value=s.DefaultWindowsTimeoutSeconds;
    }
}
