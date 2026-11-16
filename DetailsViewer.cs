namespace ServerMonitor;
public sealed class DetailsViewer : UserControl
{
    readonly bool formatReadings;
    readonly Label heading=Ui.Label("Select a row to read the full result",10,true);
    readonly TextBox body=new(){Multiline=true,ReadOnly=true,WordWrap=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,BackColor=Color.White,BorderStyle=BorderStyle.FixedSingle,MaxLength=0,AccessibleName="Full result details"};
    readonly Button copy=Ui.Button("Copy details"),expand=Ui.Button("Open full details");
    public string FullText => body.Text;
    public string Heading => heading.Text;
    public DetailsViewer(bool allowExpand=true,bool formatReadings=true)
    {
        this.formatReadings=formatReadings;Dock=DockStyle.Fill;Padding=new(0,6,0,0);BackColor=Color.White;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};layout.ColumnStyles.Add(new(SizeType.Percent,100));layout.RowStyles.Add(new(SizeType.Absolute,44));layout.RowStyles.Add(new(SizeType.Percent,100));
        var bar=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};bar.ColumnStyles.Add(new(SizeType.Percent,100));bar.ColumnStyles.Add(new(SizeType.AutoSize));heading.Dock=DockStyle.Fill;heading.AutoSize=false;heading.AutoEllipsis=true;
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,WrapContents=false};copy.AccessibleName="Copy full result details";buttons.Controls.Add(copy);if(allowExpand)buttons.Controls.Add(expand);bar.Controls.Add(heading,0,0);bar.Controls.Add(buttons,1,0);layout.Controls.Add(bar,0,0);layout.Controls.Add(body,0,1);Controls.Add(layout);
        copy.Enabled=expand.Enabled=false;
        copy.Click+=(_,_)=>{if(body.Text.Length>0)try{Clipboard.SetText(heading.Text+Environment.NewLine+body.Text);}catch(Exception ex){MessageBox.Show(this,ex.Message,"Copy details");}};
        expand.Click+=(_,_)=>{using var dialog=new DetailsDialog("Full result details",heading.Text,body.Text);dialog.ShowDialog(this);};
    }
    public static string Format(string detail)
    {
        var result=new System.Text.StringBuilder();int parentheses=0;
        for(int i=0;i<detail.Length;i++)
        {
            char c=detail[i];if(c=='(')parentheses++;else if(c==')' && parentheses>0)parentheses--;
            result.Append(c);
            if(c==';' && parentheses==0 && i+1<detail.Length && detail[i+1]==' '){result.Append(Environment.NewLine);i++;}
        }
        return result.ToString();
    }
    public void ShowDetails(string title,string text)
    {
        string formatted=formatReadings?Format(text):text;
        if(heading.Text!=title)heading.Text=title;
        // Avoid resetting the reader's selection/scroll position on the dashboard's two-second refresh.
        if(body.Text!=formatted)body.Text=formatted;
        copy.Enabled=expand.Enabled=formatted.Length>0;
    }
    public static SplitContainer Below(DataGridView grid,DetailsViewer viewer)
    {
        var split=new SplitContainer{Size=new(1000,500),Dock=DockStyle.Fill,Orientation=Orientation.Horizontal,Panel1MinSize=100,Panel2MinSize=120,SplitterDistance=200};
        split.Panel1.Controls.Add(grid);split.Panel2.Controls.Add(viewer);return split;
    }
}
public sealed class DetailsDialog : Form
{
    public DetailsDialog(string title,string heading,string text,bool formatReadings=true)
    {
        Text=title;Font=new("Segoe UI",10);BackColor=Color.White;Size=new(950,650);MinimumSize=new(650,400);StartPosition=FormStartPosition.CenterParent;MinimizeBox=false;
        var viewer=new DetailsViewer(false,formatReadings){Padding=new(14)};viewer.ShowDetails(heading,text);Controls.Add(viewer);
        var bar=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=50,FlowDirection=FlowDirection.RightToLeft,Padding=new(8)};var close=Ui.Button("Close",(_,_)=>Close());bar.Controls.Add(close);Controls.Add(bar);CancelButton=close;
    }
}
