namespace ServerMonitor;
public sealed class SmtpPanel : UserControl
{
    readonly Store store;readonly CheckBox enabled=new(){Text="Enable SMTP alerts",AutoSize=true},recovery=new(){Text="Email when a monitor recovers",AutoSize=true},clearPassword=new(){Text="Remove the saved password",AutoSize=true};
    readonly TextBox host=new(),user=new(),password=new(){UseSystemPasswordChar=true,PlaceholderText="Leave blank to keep the saved password"},from=new(),recipients=new();
    readonly ComboBox security=Ui.Combo("StartTls","SslOnConnect","None");readonly NumericUpDown port=Ui.Number(587,1,65535),reminder=Ui.Number(24,1,720);readonly Label status=Ui.Label("",9);readonly Button test;
    public SmtpPanel(Store database)
    {
        status.MaximumSize=new(850,0);store=database;Dock=DockStyle.Fill;AutoScroll=true;BackColor=Color.White;Padding=new(24);
        var grid=Ui.FormGrid();grid.MaximumSize=new(870,0);Ui.Row(grid,"Alerting",enabled);Ui.Row(grid,"SMTP relay",host);Ui.Row(grid,"Port",port);Ui.Row(grid,"Encryption",security);Ui.Row(grid,"Username (optional)",user);Ui.Row(grid,"Password",password);Ui.Row(grid,"",clearPassword);Ui.Row(grid,"From address",from);Ui.Row(grid,"Recipients (; separated)",recipients);Ui.Row(grid,"Repeat alert every (hours)",reminder);Ui.Row(grid,"Recovery alerts",recovery);
        var buttons=new FlowLayoutPanel {AutoSize=true,Dock=DockStyle.Top};buttons.Controls.Add(Ui.Button("Save SMTP settings",(_,_)=>Save(),true));test=Ui.Button("Send test email",async(_,_)=>await Test());buttons.Controls.Add(test);
        var note=Ui.Label("Alerting is optional. Failures send an initial email, then reminders at your interval. Failed deliveries retry after five minutes and appear in the Events tab. STARTTLS is required by default; use None only for a trusted relay that explicitly requires unencrypted SMTP. Passwords are protected by Windows DPAPI for this computer so the Windows service can use them. Database access is restricted in the installed service folder.",9);note.MaximumSize=new(850,0);
        var content=new TableLayoutPanel {AutoSize=true,Dock=DockStyle.Top,ColumnCount=1};content.Controls.Add(Ui.Label("SMTP alert delivery",20,true));content.Controls.Add(grid);content.Controls.Add(buttons);content.Controls.Add(status);content.Controls.Add(note);Controls.Add(content);
        var s=store.Settings();enabled.Checked=s.Enabled;host.Text=s.Host;port.Value=s.Port;security.SelectedItem=s.Security;user.Text=s.Username;from.Text=s.From;recipients.Text=s.Recipients;reminder.Value=s.ReminderHours;recovery.Checked=s.Recovery;
    }
    SmtpSettings Read()
    {
        var previous=store.Settings();return new(){Enabled=enabled.Checked,Host=host.Text.Trim(),Port=(int)port.Value,Security=security.Text,Username=user.Text.Trim(),ProtectedPassword=clearPassword.Checked?"":password.Text.Length>0?Secret.Protect(password.Text):previous.ProtectedPassword,From=from.Text.Trim(),Recipients=recipients.Text.Trim(),ReminderHours=(int)reminder.Value,Recovery=recovery.Checked};
    }
    void Save()
    {
        try{var s=Read();if(s.Enabled)Alerts.Validate(s);store.SaveSettings(s);password.Clear();clearPassword.Checked=false;status.ForeColor=Color.DarkGreen;status.Text="Settings saved. The active worker will use them on its next check.";}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"SMTP settings",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
    }
    async Task Test()
    {
        try
        {
            var s=Read();Alerts.Validate(s);test.Enabled=false;status.Text="Sending test email…";
            await Alerts.Send(s,"[Server Monitor] SMTP test",$"SMTP relay test from {Environment.MachineName} at {DateTimeOffset.Now:O}.\r\nServer Monitor can deliver alerts using these settings.",CancellationToken.None);
            status.ForeColor=Color.DarkGreen;status.Text="Test email accepted by the relay. Save settings to apply them to monitoring.";store.Event("SMTP","Test email sent","Relay accepted the test message.");
        }
        catch(Exception ex){status.ForeColor=Color.Firebrick;status.Text="Delivery failed: "+ex.Message;}
        finally{test.Enabled=true;}
    }
}
