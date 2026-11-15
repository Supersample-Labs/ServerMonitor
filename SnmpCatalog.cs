using System.Text.Json;

namespace ServerMonitor;
public sealed record SnmpMetric(string Oid,string Name,string Units,string Description,bool Scalar=true,bool Numeric=true);
public static class SnmpCatalog
{
    public static IReadOnlyList<SnmpMetric> BuiltIn { get; } = new List<SnmpMetric>
    {
        new("1.3.6.1.2.1.1.1","System description","text","Device description; informational, cannot use numeric thresholds."),
        new("1.3.6.1.2.1.1.3","System uptime","hundredths of a second","Time since the SNMP management portion restarted. Raw TimeTicks, not seconds."),
        new("1.3.6.1.2.1.1.5","System name","text","Device name; informational, cannot use numeric thresholds."),
        new("1.3.6.1.2.1.2.1","Interface count","interfaces","Number of network interfaces."),
        new("1.3.6.1.2.1.2.2.1.2","Interface description","text","Interface name/description. Discover to select a specific interface.",false),
        new("1.3.6.1.2.1.2.2.1.5","Interface speed","bits per second","Reported interface speed, not measured traffic.",false),
        new("1.3.6.1.2.1.2.2.1.8","Interface operational state","state code","1=up, 2=down, 3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown. Numeric thresholds compare these codes; use warning 2 / critical 3 to flag any non-up state.",false),
        new("1.3.6.1.2.1.2.2.1.10","Interface received octets","cumulative octets","Counter32; cumulative bytes, not throughput. Wraps at 32 bits.",false),
        new("1.3.6.1.2.1.2.2.1.16","Interface sent octets","cumulative octets","Counter32; cumulative bytes, not throughput. Wraps at 32 bits.",false),
        new("1.3.6.1.2.1.31.1.1.1.1","Interface name","text","Interface name. Discover to select an interface.",false),
        new("1.3.6.1.2.1.31.1.1.1.6","Interface received octets (64-bit)","cumulative octets","Counter64; cumulative bytes, not throughput.",false),
        new("1.3.6.1.2.1.31.1.1.1.10","Interface sent octets (64-bit)","cumulative octets","Counter64; cumulative bytes, not throughput.",false),
        new("1.3.6.1.2.1.25.3.3.1.2","Processor utilization","percent","Average processor load over the last minute. Discover to select a processor.",false),
        new("1.3.6.1.2.1.25.2.3.1.3","Storage description","text","Storage description; use to identify the storage index.",false),
        new("1.3.6.1.2.1.25.2.3.1.4","Storage allocation unit","bytes per unit","Multiply storage size/used by this value to obtain bytes.",false),
        new("1.3.6.1.2.1.25.2.3.1.5","Storage size","allocation units","Total capacity in allocation units, not bytes or percent.",false),
        new("1.3.6.1.2.1.25.2.3.1.6","Storage used","allocation units","Used capacity in allocation units, not bytes or percent.",false)
    };
    public static SnmpMetric? Match(IReadOnlyList<SnmpMetric> catalog,string oid) => catalog.Where(m=>m.Scalar?oid==m.Oid+".0":oid.StartsWith(m.Oid+".",StringComparison.Ordinal)).OrderByDescending(m=>m.Oid.Length).FirstOrDefault();
    public static List<SnmpMetric> Parse(string json)
    {
        if(json.Length>8*1024*1024)throw new ArgumentException("Catalog must be 8 MiB or smaller.");
        using var document=JsonDocument.Parse(json);var root=document.RootElement;var metrics=new List<SnmpMetric>();
        if(root.ValueKind==JsonValueKind.Array)
        {
            foreach(var item in root.EnumerateArray())
                metrics.Add(new(Text(item,"oid"),Text(item,"name"),Text(item,"units"),Text(item,"description"),!item.TryGetProperty("scalar",out var scalar)||scalar.GetBoolean(),!item.TryGetProperty("numeric",out var numeric)||numeric.GetBoolean()));
        }
        else if(root.ValueKind==JsonValueKind.Object)
        {
            // PySMI JSON objects describe definition OIDs; scalar instances add .0, table columns need discovery.
            foreach(var property in root.EnumerateObject())
            {
                var item=property.Value;
                if(item.ValueKind!=JsonValueKind.Object || Text(item,"class")!="objecttype")continue;
                string node=Text(item,"nodetype"),access=Text(item,"maxaccess");
                if(node is not ("scalar" or "column") || access is "not-accessible" or "accessible-for-notify" or "write-only")continue;
                metrics.Add(new(Text(item,"oid"),Text(item,"name") is {Length:>0} name?name:property.Name,Text(item,"units"),Text(item,"description"),node=="scalar",item.TryGetProperty("syntax",out var syntax)&&IsNumeric(root,Text(syntax,"type"),0)));
            }
        }
        else throw new ArgumentException("Choose a metric catalog array or a PySMI JSON module.");
        if(metrics.Count is 0 or >10000)throw new ArgumentException("Catalog must contain 1–10,000 accessible scalar or column definitions.");
        foreach(var metric in metrics)
        {
            _=new Lextm.SharpSnmpLib.ObjectIdentifier(metric.Oid);
            if(string.IsNullOrWhiteSpace(metric.Name)||metric.Name.Length>256||metric.Description.Length>16384||metric.Units.Length>128)throw new ArgumentException("Invalid catalog name, units, or description length.");
        }
        if(metrics.Select(m=>m.Oid).Distinct().Count()!=metrics.Count)throw new ArgumentException("Catalog contains duplicate OIDs.");
        return metrics;
    }
    static bool IsNumeric(JsonElement root,string type,int depth)
    {
        if(type is "Integer" or "Integer32" or "INTEGER" or "Counter32" or "Counter64" or "Gauge32" or "Unsigned32" or "TimeTicks")return true;
        return depth<8 && root.TryGetProperty(type,out var definition) && definition.ValueKind==JsonValueKind.Object && definition.TryGetProperty("type",out var parent) && parent.ValueKind==JsonValueKind.Object && IsNumeric(root,Text(parent,"type"),depth+1);
    }
    static string Text(JsonElement item,string name) => item.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString()??"":"";
}
