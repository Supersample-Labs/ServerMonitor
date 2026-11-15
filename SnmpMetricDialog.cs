namespace ServerMonitor;
public sealed class SnmpMetricDialog : Form
{
    readonly Store? store;
    readonly string host,community;
    readonly int port,timeout;
    readonly TextBox search=new(){PlaceholderText="Search metric names, OIDs, descriptions, or values",Width=440};
    readonly TextBox subtree=new(){Text="1.3.6.1.2.1",Width=220};
    readonly DataGridView grid=Ui.Grid();
    readonly Label status=Ui.Label("Choose a scalar from the catalog or discover live instances on the device.",9),description=Ui.Label("",9);
    readonly Button discover=Ui.Button("Discover metrics"),use=Ui.Button("Use metric",primary:true),import=Ui.Button("Import MIB JSON"),cancelScan=Ui.Button("Cancel scan");
    readonly CancellationTokenSource lifetime=new();
    CancellationTokenSource? scan;
    List<SnmpMetric> catalog;
    List<SnmpReading>? readings;
    public SnmpReading? Value {get;private set;}
    public SnmpMetricDialog(Store? database,string hostname,int remotePort,string snmpCommunity,int timeoutSeconds)
    {
        store=database;host=hostname;port=remotePort;community=snmpCommunity;timeout=timeoutSeconds;
        catalog=store?.Metrics()??SnmpCatalog.BuiltIn.ToList();Text="Choose SNMP metric";Font=new("Segoe UI",10);Size=new(1080,740);MinimumSize=new(850,600);StartPosition=FormStartPosition.CenterParent;BackColor=Color.White;MinimizeBox=false;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=6,Padding=new(16)};
        layout.RowStyles.Add(new(SizeType.Absolute,48));layout.RowStyles.Add(new(SizeType.Absolute,48));layout.RowStyles.Add(new(SizeType.Percent,100));layout.RowStyles.Add(new(SizeType.Absolute,110));layout.RowStyles.Add(new(SizeType.Absolute,65));layout.RowStyles.Add(new(SizeType.Absolute,48));
        var toolbar=new FlowLayoutPanel{Dock=DockStyle.Fill};var showCatalog=Ui.Button("Show catalog",(_,_)=>{readings=null;Render();status.Text="Catalog definitions. Discover table columns to choose a specific instance.";});
        toolbar.Controls.AddRange([search,showCatalog,import]);layout.Controls.Add(toolbar,0,0);
        var scanBar=new FlowLayoutPanel{Dock=DockStyle.Fill};var selectedTree=Ui.Button("Browse selected",async(_,_)=>{if(grid.CurrentRow?.Tag is SnmpReading row){var metric=SnmpCatalog.Match(catalog,row.Oid);subtree.Text=metric?.Oid??row.Oid;await Discover();}});
        scanBar.Controls.AddRange([Ui.Label("Subtree",9),subtree,discover,selectedTree,cancelScan]);layout.Controls.Add(scanBar,0,1);
        grid.Columns.Add("Name","Metric");grid.Columns.Add("Oid","OID / instance");grid.Columns.Add("Value","Current value");grid.Columns.Add("Units","Units");grid.Columns.Add("Type","Kind");
        grid.Columns[0].FillWeight=150;grid.Columns[1].FillWeight=160;grid.Columns[4].FillWeight=70;layout.Controls.Add(grid,0,2);
        description.AutoSize=false;description.Dock=DockStyle.Fill;layout.Controls.Add(description,0,3);status.AutoSize=false;status.Dock=DockStyle.Fill;layout.Controls.Add(status,0,4);
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft};var close=Ui.Button("Cancel",(_,_)=>{DialogResult=DialogResult.Cancel;Close();});buttons.Controls.AddRange([use,close]);layout.Controls.Add(buttons,0,5);Controls.Add(layout);CancelButton=close;
        import.Enabled=store!=null;cancelScan.Enabled=false;search.TextChanged+=(_,_)=>Render();grid.SelectionChanged+=(_,_)=>Selection();grid.CellDoubleClick+=(_,_)=>Choose();use.Click+=(_,_)=>Choose();discover.Click+=async(_,_)=>await Discover();cancelScan.Click+=(_,_)=>scan?.Cancel();import.Click+=(_,_)=>Import();FormClosed+=(_,_)=>lifetime.Cancel();Render();
    }
    void Render()
    {
        grid.Rows.Clear();
        IEnumerable<SnmpReading> rows=readings??catalog.Select(m=>new SnmpReading(m.Scalar?m.Oid+".0":m.Oid,m.Name,"Not tested",m.Units,m.Description,m.Numeric&&m.Units!="text")).ToList();
        foreach(var row in rows.Where(r=>(r.Name+" "+r.Oid+" "+r.Description+" "+r.Value).Contains(search.Text,StringComparison.OrdinalIgnoreCase)))
        {
            bool column=readings==null && catalog.Any(m=>!m.Scalar && m.Oid==row.Oid);
            int i=grid.Rows.Add(row.Name,row.Oid,row.Value,row.Units,column?"Table column":row.Numeric?"Numeric":"Information");grid.Rows[i].Tag=row;grid.Rows[i].Cells[0].ToolTipText=row.Name;grid.Rows[i].Cells[3].ToolTipText=row.Units;
        }
        Selection();
    }
    void Selection()
    {
        var row=grid.CurrentRow?.Tag as SnmpReading;
        description.Text=row==null?"":row.Name+" — "+row.Units+"\n"+row.Description;
        bool column=row!=null && readings==null && catalog.Any(m=>!m.Scalar && m.Oid==row.Oid);
        use.Enabled=scan==null && row?.Numeric==true && !column;
        if(row!=null && !column && readings==null && !row.Numeric)description.Text+="\nDiscover this subtree to inspect live values. Only numeric readings can use thresholds.";
        if(column)description.Text+="\nSelect Browse selected to find the device's instances of this metric.";
    }
    void Choose()
    {
        if(!use.Enabled || grid.CurrentRow?.Tag is not SnmpReading row)return;
        Value=row;DialogResult=DialogResult.OK;Close();
    }
    async Task Discover()
    {
        if(scan!=null)return;
        if(Uri.CheckHostName(host)==UriHostNameType.Unknown){MessageBox.Show(this,"Enter the device hostname or IP in the monitor settings first.","SNMP discovery");return;}
        try
        {
            _=new Lextm.SharpSnmpLib.ObjectIdentifier(subtree.Text.Trim());
            if(string.IsNullOrWhiteSpace(community))throw new ArgumentException("Enter an SNMP community first.");
            scan=CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);discover.Enabled=import.Enabled=false;cancelScan.Enabled=true;use.Enabled=false;
            status.Text="Discovering this device… up to 512 readings / 30 seconds. You can cancel the scan.";
            var result=await SnmpProbe.Discover(host,port,new(){Community=community},subtree.Text.Trim(),timeout,catalog,scan.Token);
            if(IsDisposed)return;readings=result.Readings;Render();status.Text=$"{readings.Count} readings found. {result.Message}";
        }
        catch(OperationCanceledException){if(!IsDisposed)status.Text="Discovery canceled.";}
        catch(Exception ex){if(!IsDisposed)status.Text="Discovery failed: "+ex.Message;}
        finally{scan?.Dispose();scan=null;if(!IsDisposed){discover.Enabled=true;import.Enabled=store!=null;cancelScan.Enabled=false;Selection();}}
    }
    void Import()
    {
        if(store==null)return;
        using var dialog=new OpenFileDialog{Filter="Metric catalog or PySMI JSON (*.json)|*.json",Title="Import metric definitions"};
        if(dialog.ShowDialog(this)!=DialogResult.OK)return;
        try
        {
            if(new FileInfo(dialog.FileName).Length>8*1024*1024)throw new ArgumentException("Catalog must be 8 MiB or smaller.");
            int count=store.ImportMetrics(File.ReadAllText(dialog.FileName));catalog=store.Metrics();readings=null;Render();status.Text=$"Imported {count} definitions. Select a metric or discover its instances.";
        }
        catch(Exception ex){MessageBox.Show(this,ex.Message,"Import metric definitions",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
    }
    protected override void Dispose(bool disposing){if(disposing){lifetime.Cancel();lifetime.Dispose();}base.Dispose(disposing);}
}
