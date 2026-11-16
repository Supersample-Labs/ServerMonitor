namespace ServerMonitor;
public sealed class WindowsSettingsPanel : UserControl
{
    readonly WindowsServerSettings original;
    readonly ComboBox transport=Ui.Combo("HTTPS (certificate validated)","HTTP (Windows authentication)"),identity=Ui.Combo("Use worker's Windows account","Use a specific Windows account"),severity=Ui.Combo("Warning","Critical","None");
    readonly TextBox username=new(){AccessibleName="Windows username"},password=new(){UseSystemPasswordChar=true,AccessibleName="Windows password",PlaceholderText="Enter password"},drives=new(){Text="*"};
    readonly Label passwordHint=Ui.Label("Leave password blank to keep the saved password for this username.",9);
    readonly ThresholdEditor cpu,memory,disk;
    public event EventHandler? TransportChanged;
    public bool UseWorkerAccount => identity.SelectedIndex==0;
    public bool UseSsl => transport.SelectedIndex==0;
    public WindowsSettingsPanel(WindowsServerSettings value)
    {
        original=value;AutoSize=true;BackColor=Color.White;
        cpu=new("CPU",value.Cpu);memory=new("Memory",value.Memory);disk=new("Disk",value.Disk);
        var grid=Ui.FormGrid();grid.Padding=Padding.Empty;
        grid.ColumnStyles.Add(new(SizeType.Absolute,125));grid.ColumnStyles.Add(new(SizeType.Percent,100));
        Ui.Row(grid,"WinRM transport",transport);Ui.Row(grid,"Authentication",identity);Ui.Row(grid,"Windows username",username);Ui.Row(grid,"Password",password);Ui.Row(grid,"",passwordHint);
        Ui.Row(grid,"CPU used %",cpu);Ui.Row(grid,"Memory used %",memory);Ui.Row(grid,"Disk used %",disk);Ui.Row(grid,"Drive letters",drives);Ui.Row(grid,"Minimum severity",severity);Controls.Add(grid);
        passwordHint.MaximumSize=new(280,0);
        transport.SelectedIndex=value.UseSsl?0:1;identity.SelectedIndex=value.UseWorkerAccount?0:1;username.Text=value.Username;drives.Text=value.Drives;severity.SelectedItem=value.MinimumSeverity;
        username.TextChanged+=(_,_)=>UpdatePasswordHint();password.TextChanged+=(_,_)=>UpdatePasswordHint();UpdatePasswordHint();
        identity.SelectedIndexChanged+=(_,_)=>UpdateIdentity();transport.SelectedIndexChanged+=(_,_)=>TransportChanged?.Invoke(this,EventArgs.Empty);UpdateIdentity();
    }
    void UpdatePasswordHint()
    {
        bool retained=original.ProtectedPassword.Length>0 && Secret.SameAccount(original.Username,username.Text,windowsAccount:true);
        password.PlaceholderText=retained?"Saved password — leave blank to keep":"Enter password";
        passwordHint.Text=password.Text.Length>0?"The entered password will replace the saved password when you save.":retained?"Password saved. Leave this field blank to keep it when changing the connection or thresholds.":"Enter a password for this Windows account. Changing accounts requires its password.";
    }
    void UpdateIdentity()
    {
        bool supplied=identity.SelectedIndex==1;
        foreach(var control in new Control[]{username,password,passwordHint})
        {
            if(control.Parent is not TableLayoutPanel parent)continue;
            int row=parent.GetRow(control);foreach(Control sibling in parent.Controls)if(parent.GetRow(sibling)==row)sibling.Visible=supplied;
        }
    }
    public WindowsServerSettings Value()
    {
        bool worker=identity.SelectedIndex==0;string user=username.Text.Trim();
        string saved=worker?"":Secret.KeepOrReplacePassword(original.ProtectedPassword,original.Username,user,password.Text,windowsAccount:true);
        var result=new WindowsServerSettings{UseSsl=UseSsl,UseWorkerAccount=worker,Username=worker?"":user,ProtectedPassword=saved,Cpu=cpu.Value(),Memory=memory.Value(),Disk=disk.Value(),Drives=drives.Text.Trim().ToUpperInvariant(),MinimumSeverity=severity.Text};
        WindowsProbe.Validate(result);return result;
    }
}
public sealed class ThresholdEditor : UserControl
{
    readonly CheckBox enabled=new(){Text="Enabled",AutoSize=true};
    readonly NumericUpDown warning=Ui.Number(80,0,100),critical=Ui.Number(90,0,100);
    public ThresholdEditor(string metric,ResourceThreshold value)
    {
        AutoSize=true;var layout=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=4};
        layout.ColumnStyles.Add(new(SizeType.AutoSize));layout.ColumnStyles.Add(new(SizeType.Percent,50));layout.ColumnStyles.Add(new(SizeType.AutoSize));layout.ColumnStyles.Add(new(SizeType.Percent,50));
        layout.Controls.Add(enabled,0,0);layout.SetColumnSpan(enabled,4);
        var warningLabel=Ui.Label("Warn ≥",9);var criticalLabel=Ui.Label("Critical ≥",9);
        layout.Controls.Add(warningLabel,0,1);layout.Controls.Add(warning,1,1);layout.Controls.Add(criticalLabel,2,1);layout.Controls.Add(critical,3,1);
        warning.Dock=critical.Dock=DockStyle.Fill;warning.DecimalPlaces=critical.DecimalPlaces=1;warning.AccessibleName=metric+" warning percent used";critical.AccessibleName=metric+" critical percent used";enabled.AccessibleName="Monitor "+metric;
        enabled.Checked=value.Enabled;warning.Value=value.Warning;critical.Value=value.Critical;enabled.CheckedChanged+=(_,_)=>{warning.Enabled=critical.Enabled=enabled.Checked;};warning.Enabled=critical.Enabled=enabled.Checked;Controls.Add(layout);
    }
    public ResourceThreshold Value()=>new(){Enabled=enabled.Checked,Warning=warning.Value,Critical=critical.Value};
}
