using System.Diagnostics;
using System.Formats.Asn1;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ServerMonitor;
public static class SnmpProbe
{
    public static void Validate(SnmpSettings settings)
    {
        if(string.IsNullOrWhiteSpace(settings.Community) || Encoding.UTF8.GetByteCount(settings.Community)>255)throw new ArgumentException("SNMP community must contain 1–255 UTF-8 bytes.");
        var writer=new AsnWriter(AsnEncodingRules.BER);writer.WriteObjectIdentifier(settings.Oid);
        if(settings.MinimumSeverity is not ("Warning" or "Critical" or "None"))throw new ArgumentException("Choose a minimum SNMP alert severity.");
        if(settings.LowerIsWorse?settings.Critical>=settings.Warning:settings.Critical<=settings.Warning)throw new ArgumentException("Critical must be above warning for rising values, or below warning for falling values.");
    }
    public static CheckResult Evaluate(SnmpSettings settings,decimal value,DateTimeOffset now,long latency=0)
    {
        bool critical=settings.LowerIsWorse?value<=settings.Critical:value>=settings.Critical;
        bool warning=settings.LowerIsWorse?value<=settings.Warning:value>=settings.Warning;
        var status=critical?Health.Critical:warning?Health.Warning:Health.Healthy;
        return new(status,$"SNMP {(string.IsNullOrWhiteSpace(settings.MetricName)?settings.Oid:settings.MetricName+" ("+settings.Oid+")")} = {value.ToString(CultureInfo.InvariantCulture)} {settings.Units}; warning {(settings.LowerIsWorse?"≤":"≥")} {settings.Warning}; critical {(settings.LowerIsWorse?"≤":"≥")} {settings.Critical}",now,latency);
    }
    public static byte[] Request(SnmpSettings settings,int id) =>
        new GetRequestMessage(id,VersionCode.V2,new OctetString(Encoding.UTF8.GetBytes(settings.Community)),[new Variable(new ObjectIdentifier(settings.Oid))]).ToBytes();

    public static decimal Numeric(ISnmpData data) => data switch
    {
        Integer32 v => v.ToInt32(), Counter32 v => v.ToUInt32(), Counter64 v => v.ToUInt64(),
        Gauge32 v => v.ToUInt32(), TimeTicks v => v.ToUInt32(),
        OctetString v when decimal.TryParse(Encoding.UTF8.GetString(v.GetRaw()),NumberStyles.Float,CultureInfo.InvariantCulture,out var number) => number,
        _ => throw new IOException("SNMP OID is missing or returned a nonnumeric value; choose a numeric metric.")
    };
    public static ISnmpMessage? Response(byte[] packet,SnmpSettings settings,int id)
    {
        var messages=MessageFactory.ParseMessages(packet,new UserRegistry());
        return messages.FirstOrDefault(m=>m.Version==VersionCode.V2 && m.TypeCode()==SnmpType.ResponsePdu && m.RequestId()==id && m.Community().GetRaw().AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(settings.Community)));
    }
    public static decimal? ReadResponse(byte[] packet,SnmpSettings settings,int id)
    {
        var response=Response(packet,settings,id);if(response==null)return null;
        CheckError(response);
        var variables=response.Variables();
        if(variables.Count!=1 || variables[0].Id.ToString()!=settings.Oid)return null;
        return Numeric(variables[0].Data);
    }
    static void CheckError(ISnmpMessage response)
    {
        var pdu=response.Pdu();
        if(pdu.ErrorStatus.ToInt32()!=0)throw new IOException($"SNMP agent returned error {pdu.ErrorStatus.ToInt32()} at variable {pdu.ErrorIndex.ToInt32()}.");
    }
    static async Task<UdpClient> Connect(string host,int port,CancellationToken ct)
    {
        var addresses=await Dns.GetHostAddressesAsync(host,ct);
        if(addresses.Length==0)throw new SocketException((int)SocketError.HostNotFound);
        var socket=new UdpClient(addresses[0].AddressFamily);
        try{socket.Connect(addresses[0],port);return socket;}catch{socket.Dispose();throw;}
    }
    static async Task<ISnmpMessage> Exchange(UdpClient socket,ISnmpMessage request,SnmpSettings settings,CancellationToken ct)
    {
        await socket.SendAsync(request.ToBytes(),ct);
        while(true)
        {
            var packet=await socket.ReceiveAsync(ct);ISnmpMessage? response;
            try{response=Response(packet.Buffer,settings,request.RequestId());}
            catch(Exception ex) when(ex is SnmpException or ArgumentException or IndexOutOfRangeException or System.Formats.Asn1.AsnContentException){continue;}
            if(response==null)continue;CheckError(response);return response;
        }
    }
    public static async Task<CheckResult> Run(MonitorCheck check,Stopwatch watch,CancellationToken ct)
    {
        Validate(check.Snmp);using var socket=await Connect(check.Host,check.Port,ct);
        var request=new GetRequestMessage(RandomNumberGenerator.GetInt32(1,int.MaxValue),VersionCode.V2,new OctetString(Encoding.UTF8.GetBytes(check.Snmp.Community)),[new Variable(new ObjectIdentifier(check.Snmp.Oid))]);
        var response=await Exchange(socket,request,check.Snmp,ct);var variables=response.Variables();
        if(variables.Count!=1 || variables[0].Id.ToString()!=check.Snmp.Oid)throw new IOException("SNMP agent returned an unexpected OID.");
        return Evaluate(check.Snmp,Numeric(variables[0].Data),DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
    }
    public static async Task<SnmpDiscoveryResult> Discover(string host,int port,SnmpSettings settings,string root,int timeoutSeconds,IReadOnlyList<SnmpMetric> catalog,CancellationToken ct,int limit=512)
    {
        _=new ObjectIdentifier(root);using var socket=await Connect(host,port,ct);
        var found=new List<SnmpReading>();string current=root;var elapsed=Stopwatch.StartNew();
        for(int i=0;i<limit;i++)
        {
            var remaining=TimeSpan.FromSeconds(30)-elapsed.Elapsed;if(remaining<=TimeSpan.Zero)return new(found,"Stopped after 30 seconds. Narrow the subtree to discover more.");
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(remaining<TimeSpan.FromSeconds(timeoutSeconds)?remaining:TimeSpan.FromSeconds(timeoutSeconds));
            var request=new GetNextRequestMessage(RandomNumberGenerator.GetInt32(1,int.MaxValue),VersionCode.V2,new OctetString(Encoding.UTF8.GetBytes(settings.Community)),[new Variable(new ObjectIdentifier(current))]);
            ISnmpMessage response;
            try{response=await Exchange(socket,request,settings,deadline.Token);}
            catch(OperationCanceledException) when(!ct.IsCancellationRequested){return new(found,"Device did not reply within the timeout. Results may be incomplete.");}
            catch(IOException ex){return new(found,ex.Message+" Results may be incomplete.");}
            var variables=response.Variables();if(variables.Count!=1)throw new IOException("Invalid SNMP discovery response.");
            var v=variables[0];string oid=v.Id.ToString();
            if(v.Data.TypeCode is SnmpType.EndOfMibView or SnmpType.NoSuchObject or SnmpType.NoSuchInstance || !oid.StartsWith(root+".",StringComparison.Ordinal))return new(found,"Discovery complete.");
            if(CompareOids(oid,current)<=0)throw new IOException("Device returned a non-increasing OID; discovery stopped.");
            current=oid;var metric=SnmpCatalog.Match(catalog,oid);
            decimal? numeric=null;try{numeric=Numeric(v.Data);}catch(IOException){}
            string displayName=metric==null?"Unknown metric":metric.Scalar?metric.Name:metric.Name+" ["+oid[(metric.Oid.Length+1)..]+"]";
            found.Add(new(oid,displayName,numeric?.ToString(CultureInfo.InvariantCulture)??v.Data.ToString()??"",metric?.Units??"raw",metric?.Description??"No catalog definition. Import the vendor MIB JSON for a readable name.",numeric.HasValue));
        }
        return new(found,$"Stopped at {limit} readings. Narrow the subtree to discover more.");
    }
    public static int CompareOids(string a,string b)
    {
        var left=a.Split('.').Select(uint.Parse).ToArray();var right=b.Split('.').Select(uint.Parse).ToArray();
        for(int i=0;i<Math.Min(left.Length,right.Length);i++){int c=left[i].CompareTo(right[i]);if(c!=0)return c;}
        return left.Length.CompareTo(right.Length);
    }
}
public sealed record SnmpReading(string Oid,string Name,string Value,string Units,string Description,bool Numeric);
public sealed record SnmpDiscoveryResult(List<SnmpReading> Readings,string Message);
