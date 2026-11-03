namespace ServerMonitor;
public static class Ui
{
    public static readonly Color Ink=Color.FromArgb(24,40,57),Muted=Color.FromArgb(92,108,125),Blue=Color.FromArgb(30,95,171),Paper=Color.FromArgb(244,247,251);
    public static Button Button(string text,EventHandler? click=null,bool primary=false)
    {
        var b=new Button {Text=text,AutoSize=true,MinimumSize=new(95,34),Padding=new(10,4,10,4),FlatStyle=FlatStyle.Flat,BackColor=primary?Blue:Color.White,ForeColor=primary?Color.White:Ink,Margin=new(0,0,8,8)};
        b.FlatAppearance.BorderColor=primary?Blue:Color.FromArgb(201,211,222);if(click!=null)b.Click+=click;return b;
    }
    public static Label Label(string text,int size=10,bool bold=false)=>new(){Text=text,UseMnemonic=false,AutoSize=true,ForeColor=Ink,Font=new("Segoe UI",size,bold?FontStyle.Bold:FontStyle.Regular),Margin=new(0,8,8,8)};
    public static TableLayoutPanel FormGrid()=>new(){Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,Padding=new(8)};
    public static void Row(TableLayoutPanel panel,string label,Control control)
    {
        int row=panel.RowCount++;if(panel.ColumnStyles.Count==0){panel.ColumnStyles.Add(new(SizeType.Absolute,175));panel.ColumnStyles.Add(new(SizeType.Percent,100));}
        panel.RowStyles.Add(new(SizeType.AutoSize));panel.Controls.Add(Label(label),0,row);control.Dock=DockStyle.Top;control.Margin=new(0,6,0,6);panel.Controls.Add(control,1,row);
    }
    public static ComboBox Combo(params string[] options){var c=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList};c.Items.AddRange(options);c.SelectedIndex=0;return c;}
    public static NumericUpDown Number(int value,int min,int max)=>new(){Minimum=min,Maximum=max,Value=value,ThousandsSeparator=true};
    public static DataGridView Grid()=>new(){Dock=DockStyle.Fill,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,AllowUserToResizeRows=false,RowHeadersVisible=false,MultiSelect=false,SelectionMode=DataGridViewSelectionMode.FullRowSelect,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,BackgroundColor=Color.White,BorderStyle=BorderStyle.None,CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal,GridColor=Color.FromArgb(226,232,239),RowTemplate={Height=38},EnableHeadersVisualStyles=false,ColumnHeadersHeight=40,ColumnHeadersDefaultCellStyle=new(){BackColor=Color.FromArgb(231,237,245),ForeColor=Ink,Font=new("Segoe UI",9,FontStyle.Bold)},DefaultCellStyle=new(){Font=new("Segoe UI",9),ForeColor=Ink,SelectionBackColor=Color.FromArgb(215,230,250),SelectionForeColor=Ink}};
    public static string Display(Health s)=>s switch{Health.NoResponse=>"NO RESPONSE",Health.InvalidCertificate=>"INVALID TLS",Health.HttpError=>"HTTP ERROR",Health.Healthy=>"HEALTHY",Health.Pending=>"PENDING",_=>s.ToString().ToUpperInvariant()};
    public static Color Back(Health s)=>s==Health.Healthy?Color.FromArgb(225,245,234):s==Health.Pending?Color.FromArgb(243,245,248):Color.FromArgb(255,230,230);
    public static Color Fore(Health s)=>s==Health.Healthy?Color.FromArgb(20,103,62):s==Health.Pending?Muted:Color.FromArgb(158,36,45);
}
public sealed class CheckDialog : Form
{
    readonly TextBox name=new(),host=new(),sni=new(),httpPath=new(){Text="/"},payload=new(){Multiline=true,Height=65,ScrollBars=ScrollBars.Vertical},expected=new();
    readonly ComboBox kind=Ui.Combo("TCP","UDP","Certificate","HTTPS","Private Certificate"),mode=Ui.Combo("DNS","Custom");
    readonly DateTimePicker expiration=new(){Format=DateTimePickerFormat.Custom,CustomFormat="yyyy-MM-dd HH:mm",Value=DateTime.Today.AddYears(1)};
    readonly NumericUpDown httpMin=Ui.Number(200,200,599),httpMax=Ui.Number(399,200,599);
    readonly NumericUpDown port=Ui.Number(443,1,65535),interval=Ui.Number(60,5,86400),timeout=Ui.Number(5,1,60);
    readonly CheckBox enabled=new(){Text="Enable this monitor",Checked=true,AutoSize=true},hex=new(){Text="Payload is hexadecimal",AutoSize=true};
    readonly MonitorCheck original;public MonitorCheck Value {get;private set;}
    public CheckDialog(MonitorCheck? check=null)
    {
        original=check??new(){Kind=CheckKind.HTTPS};Value=original;Text=check==null?"Add monitor":"Edit monitor";Font=new("Segoe UI",10);BackColor=Color.White;Size=new(650,790);MinimumSize=new(600,650);StartPosition=FormStartPosition.CenterParent;MinimizeBox=false;MaximizeBox=false;
        var scroll=new Panel {Dock=DockStyle.Fill,AutoScroll=true,Padding=new(16)};var grid=Ui.FormGrid();
        Ui.Row(grid,"Display name",name);Ui.Row(grid,"Hostname or IP",host);Ui.Row(grid,"Check type",kind);Ui.Row(grid,"Expiration (local time)",expiration);Ui.Row(grid,"Remote port",port);Ui.Row(grid,"Interval (seconds)",interval);Ui.Row(grid,"Timeout (seconds)",timeout);
        Ui.Row(grid,"TLS server name / SNI",sni);Ui.Row(grid,"HTTPS path",httpPath);Ui.Row(grid,"Accepted HTTP status: min",httpMin);Ui.Row(grid,"Accepted HTTP status: max",httpMax);Ui.Row(grid,"UDP probe",mode);Ui.Row(grid,"UDP payload",payload);Ui.Row(grid,"Payload format",hex);Ui.Row(grid,"Expected reply prefix (hex)",expected);Ui.Row(grid,"",enabled);
        var note=Ui.Label("Private Certificate tracks a manually entered expiration for SAML or internal certificates, without a network connection. It alerts at 30 days or less and when expired. Update the expiration after renewal. Times use this computer's local time zone. HTTPS checks connect, inspect the certificate, and GET the configured path; 200-399 is accepted by default. Certificate-only checks inspect TLS without HTTP. Both use direct TLS, not STARTTLS. Leave SNI blank to use the hostname. UDP DNS mode sends a root NS query; Custom mode requires a protocol-specific payload. A timeout is marked red as NO RESPONSE, not proven offline. Blank reply prefix accepts any nonempty reply.",9);note.MaximumSize=new(550,0);note.Padding=new(4,8,4,8);
        var content=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=1};content.Controls.Add(grid);content.Controls.Add(note);scroll.Controls.Add(content);Controls.Add(scroll);
        var buttons=new FlowLayoutPanel {Dock=DockStyle.Bottom,Height=60,Padding=new(20,10,10,4),FlowDirection=FlowDirection.RightToLeft};var save=Ui.Button("Save monitor",(_,_)=>Save(),true);var cancel=Ui.Button("Cancel",(_,_)=>{DialogResult=DialogResult.Cancel;Close();});buttons.Controls.AddRange([save,cancel]);Controls.Add(buttons);AcceptButton=save;CancelButton=cancel;
        name.Text=original.Name;host.Text=original.Host;kind.SelectedIndex=(int)original.Kind;port.Value=original.Port;interval.Value=original.IntervalSeconds;timeout.Value=original.TimeoutSeconds;sni.Text=original.TlsName;httpPath.Text=original.HttpPath;httpMin.Value=original.HttpStatusMin;httpMax.Value=original.HttpStatusMax;mode.SelectedItem=original.UdpMode;payload.Text=original.Payload;hex.Checked=original.HexPayload;expected.Text=original.ExpectedHex;enabled.Checked=original.Enabled;
        if(original.ManualExpiration.HasValue)expiration.Value=original.ManualExpiration.Value.LocalDateTime;
        kind.SelectedIndexChanged+=(_,_)=>{if(check==null)port.Value=kind.SelectedIndex==1?53:443;UpdateFields();};mode.SelectedIndexChanged+=(_,_)=>UpdateFields();UpdateFields();
    }
    void UpdateFields(){bool manual=kind.SelectedIndex==4;expiration.Enabled=manual;host.Enabled=port.Enabled=timeout.Enabled=!manual;bool udp=kind.SelectedIndex==1;sni.Enabled=kind.SelectedIndex is 2 or 3;httpPath.Enabled=httpMin.Enabled=httpMax.Enabled=kind.SelectedIndex==3;mode.Enabled=udp;payload.Enabled=hex.Enabled=udp&&mode.Text=="Custom";expected.Enabled=udp;}
    void Save()
    {
        try
        {
            string hostname=host.Text.Trim().Trim('[',']');
            if(string.IsNullOrWhiteSpace(name.Text))throw new ArgumentException("Enter a display name.");
            if(kind.SelectedIndex!=4 && (Uri.CheckHostName(hostname)==UriHostNameType.Unknown || hostname.Contains("://")))throw new ArgumentException("Enter a hostname or IP address without a URL, path, or port.");
            if(kind.SelectedIndex is 2 or 3 && sni.Text.Trim().Length>0&&Uri.CheckHostName(sni.Text.Trim())==UriHostNameType.Unknown)throw new ArgumentException("Enter a valid TLS server name.");
            if(kind.SelectedIndex==3){_=Probes.HttpPath(httpPath.Text);if(httpMin.Value>httpMax.Value)throw new ArgumentException("The minimum HTTP status must not exceed the maximum.");}
            if(kind.SelectedIndex==1){if(mode.Text=="Custom"){var bytes=hex.Checked?Probes.Hex(payload.Text):System.Text.Encoding.UTF8.GetBytes(payload.Text);if(bytes.Length is 0 or >4096)throw new ArgumentException("Custom UDP payload must contain 1–4096 bytes.");}if(expected.Text.Trim().Length>0)_=Probes.Hex(expected.Text);}
            Value=original with {Name=name.Text.Trim(),Host=hostname,Port=(int)port.Value,Kind=(CheckKind)kind.SelectedIndex,ManualExpiration=kind.SelectedIndex==4?new DateTimeOffset(DateTime.SpecifyKind(expiration.Value,DateTimeKind.Local)):null,TlsName=sni.Text.Trim(),IntervalSeconds=(int)interval.Value,TimeoutSeconds=(int)timeout.Value,Enabled=enabled.Checked,UdpMode=mode.Text,Payload=payload.Text,HexPayload=hex.Checked,ExpectedHex=expected.Text.Trim(),HttpPath=kind.SelectedIndex==3?Probes.HttpPath(httpPath.Text):original.HttpPath,HttpStatusMin=(int)httpMin.Value,HttpStatusMax=(int)httpMax.Value};DialogResult=DialogResult.OK;Close();
        }
        catch(Exception ex){MessageBox.Show(this,ex.Message,"Check settings",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
    }
}
