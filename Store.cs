using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Text.Json;

namespace ServerMonitor;
public sealed class Store(string path)
{
    public string PathName { get; } = path;
    public SqliteConnection Open()
    {
        var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = PathName, Pooling = false, DefaultTimeout = 15 }.ToString());
        c.Open();
        using var cmd = c.CreateCommand(); cmd.CommandText = "PRAGMA busy_timeout=15000; PRAGMA journal_mode=PERSIST; PRAGMA synchronous=FULL;"; cmd.ExecuteNonQuery();
        return c;
    }
    public void Initialize()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = """
        CREATE TABLE IF NOT EXISTS Checks(
          Id INTEGER PRIMARY KEY, Name TEXT NOT NULL, Host TEXT NOT NULL, Port INTEGER NOT NULL, Kind INTEGER NOT NULL,
          TlsName TEXT NOT NULL, IntervalSeconds INTEGER NOT NULL, TimeoutSeconds INTEGER NOT NULL, Enabled INTEGER NOT NULL,
          UdpMode TEXT NOT NULL, Payload TEXT NOT NULL, HexPayload INTEGER NOT NULL, ExpectedHex TEXT NOT NULL, Revision INTEGER NOT NULL DEFAULT 1,
          Status INTEGER NOT NULL DEFAULT 0, Detail TEXT NOT NULL DEFAULT 'Not checked yet', LastChecked TEXT, Expires TEXT, LatencyMs INTEGER,
          LastAlertStatus TEXT NOT NULL DEFAULT '', LastAlert TEXT, LastAttempt TEXT);
        CREATE TABLE IF NOT EXISTS Settings(Id INTEGER PRIMARY KEY CHECK(Id=1), Json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS Events(Id INTEGER PRIMARY KEY, At TEXT NOT NULL, Name TEXT NOT NULL, Status TEXT NOT NULL, Detail TEXT NOT NULL, Problem INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS Lease(Id INTEGER PRIMARY KEY CHECK(Id=1), Owner TEXT NOT NULL, UntilUtc TEXT NOT NULL);
        """;
        cmd.ExecuteNonQuery();
        using var transaction=c.BeginTransaction();cmd.Transaction=transaction;
        cmd.CommandText="SELECT COUNT(*) FROM pragma_table_info('Checks') WHERE name='HttpPath'";
        if(Convert.ToInt32(cmd.ExecuteScalar())==0)
        {
            cmd.CommandText="ALTER TABLE Checks ADD COLUMN HttpPath TEXT NOT NULL DEFAULT '/'; ALTER TABLE Checks ADD COLUMN HttpStatusMin INTEGER NOT NULL DEFAULT 200; ALTER TABLE Checks ADD COLUMN HttpStatusMax INTEGER NOT NULL DEFAULT 399;";cmd.ExecuteNonQuery();
        }
        cmd.CommandText="SELECT COUNT(*) FROM pragma_table_info('Checks') WHERE name='ManualExpiration'";
        if(Convert.ToInt32(cmd.ExecuteScalar())==0)
        {
            cmd.CommandText="ALTER TABLE Checks ADD COLUMN ManualExpiration TEXT";cmd.ExecuteNonQuery();
        }
        cmd.CommandText="PRAGMA user_version=3";cmd.ExecuteNonQuery();transaction.Commit();
    }
    static void Param(SqliteCommand cmd, string key, object? value) => cmd.Parameters.AddWithValue(key, value ?? DBNull.Value);
    static string? Stamp(DateTimeOffset? v) => v?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    static DateTimeOffset? Date(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : DateTimeOffset.Parse(r.GetString(i), CultureInfo.InvariantCulture);
    public List<MonitorCheck> Checks()
    {
        using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT * FROM Checks ORDER BY Name COLLATE NOCASE,Id";
        using var r = cmd.ExecuteReader(); var list = new List<MonitorCheck>();
        while (r.Read()) list.Add(new() {
            Id=r.GetInt64(0),Name=r.GetString(1),Host=r.GetString(2),Port=r.GetInt32(3),Kind=(CheckKind)r.GetInt32(4),TlsName=r.GetString(5),
            IntervalSeconds=r.GetInt32(6),TimeoutSeconds=r.GetInt32(7),Enabled=r.GetBoolean(8),UdpMode=r.GetString(9),Payload=r.GetString(10),
            HexPayload=r.GetBoolean(11),ExpectedHex=r.GetString(12),Revision=r.GetInt64(13),Status=(Health)r.GetInt32(14),Detail=r.GetString(15),
            LastChecked=Date(r,16),Expires=Date(r,17),LatencyMs=r.IsDBNull(18)?null:r.GetInt64(18),LastAlertStatus=r.GetString(19),LastAlert=Date(r,20),LastAttempt=Date(r,21),HttpPath=r.GetString(r.GetOrdinal("HttpPath")),HttpStatusMin=r.GetInt32(r.GetOrdinal("HttpStatusMin")),HttpStatusMax=r.GetInt32(r.GetOrdinal("HttpStatusMax")),ManualExpiration=Date(r,r.GetOrdinal("ManualExpiration"))
        });
        return list;
    }
    public void Save(MonitorCheck v)
    {
        if(v.Kind==CheckKind.PrivateCertificate && !v.ManualExpiration.HasValue)throw new ArgumentException("Enter the private certificate expiration.");
        using var c=Open(); using var cmd=c.CreateCommand();
        var fields="Name=$n,Host=$h,Port=$p,Kind=$k,TlsName=$t,IntervalSeconds=$i,TimeoutSeconds=$o,Enabled=$e,UdpMode=$u,Payload=$d,HexPayload=$x,ExpectedHex=$q,HttpPath=$hp,HttpStatusMin=$min,HttpStatusMax=$max,ManualExpiration=$manual";
        cmd.CommandText=v.Id==0?"INSERT INTO Checks(Name,Host,Port,Kind,TlsName,IntervalSeconds,TimeoutSeconds,Enabled,UdpMode,Payload,HexPayload,ExpectedHex,HttpPath,HttpStatusMin,HttpStatusMax,ManualExpiration) VALUES($n,$h,$p,$k,$t,$i,$o,$e,$u,$d,$x,$q,$hp,$min,$max,$manual)":$"UPDATE Checks SET {fields},Revision=Revision+1,Status=0,Detail='Configuration changed; waiting for check',LastChecked=NULL,Expires=NULL,LatencyMs=NULL,LastAlertStatus='',LastAlert=NULL,LastAttempt=NULL WHERE Id=$id";
        Param(cmd,"$id",v.Id);Param(cmd,"$n",v.Name);Param(cmd,"$h",v.Host);Param(cmd,"$p",v.Port);Param(cmd,"$k",(int)v.Kind);Param(cmd,"$t",v.TlsName);
        Param(cmd,"$i",v.IntervalSeconds);Param(cmd,"$o",v.TimeoutSeconds);Param(cmd,"$e",v.Enabled);Param(cmd,"$u",v.UdpMode);Param(cmd,"$d",v.Payload);Param(cmd,"$x",v.HexPayload);Param(cmd,"$q",v.ExpectedHex);Param(cmd,"$hp",v.HttpPath);Param(cmd,"$min",v.HttpStatusMin);Param(cmd,"$max",v.HttpStatusMax);Param(cmd,"$manual",Stamp(v.ManualExpiration));cmd.ExecuteNonQuery();
    }
    public void Remove(long id) { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="DELETE FROM Checks WHERE Id=$id";Param(cmd,"$id",id);cmd.ExecuteNonQuery(); }
    public void RequestChecks() { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="UPDATE Checks SET LastChecked=NULL WHERE Enabled=1";cmd.ExecuteNonQuery(); }
    public bool Result(MonitorCheck v, CheckResult result)
    {
        using var c=Open(); using var transaction=c.BeginTransaction(); using var cmd=c.CreateCommand();cmd.Transaction=transaction;
        cmd.CommandText="UPDATE Checks SET Status=$s,Detail=$d,LastChecked=$at,Expires=$ex,LatencyMs=$ms WHERE Id=$id AND Revision=$rev AND Enabled=1";
        Param(cmd,"$s",(int)result.Status);Param(cmd,"$d",result.Detail);Param(cmd,"$at",Stamp(result.CheckedAt));Param(cmd,"$ex",Stamp(result.Expires));Param(cmd,"$ms",result.LatencyMs);Param(cmd,"$id",v.Id);Param(cmd,"$rev",v.Revision);
        var changed=cmd.ExecuteNonQuery()==1;
        if(changed && (v.Status!=result.Status || v.LastChecked==null)) AddEvent(c,transaction,v.Name,result.Status.ToString(),result.Detail,result.Problem);
        transaction.Commit();return changed;
    }
    static void AddEvent(SqliteConnection c,SqliteTransaction? tx,string name,string status,string detail,bool problem)
    {
        using var cmd=c.CreateCommand();cmd.Transaction=tx;cmd.CommandText="INSERT INTO Events(At,Name,Status,Detail,Problem) VALUES($at,$n,$s,$d,$p); DELETE FROM Events WHERE Id < (SELECT COALESCE(MAX(Id),0)-5000 FROM Events);";
        Param(cmd,"$at",Stamp(DateTimeOffset.UtcNow));Param(cmd,"$n",name);Param(cmd,"$s",status);Param(cmd,"$d",detail);Param(cmd,"$p",problem);cmd.ExecuteNonQuery();
    }
    public void Event(string name,string status,string detail,bool problem=false) { using var c=Open();AddEvent(c,null,name,status,detail,problem); }
    public List<MonitorEvent> Events(long after=0,int limit=200)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT Id,At,Name,Status,Detail,Problem FROM Events WHERE Id>$id ORDER BY Id DESC LIMIT $limit";Param(cmd,"$id",after);Param(cmd,"$limit",limit);
        using var r=cmd.ExecuteReader();var list=new List<MonitorEvent>();while(r.Read())list.Add(new(r.GetInt64(0),Date(r,1)!.Value,r.GetString(2),r.GetString(3),r.GetString(4),r.GetBoolean(5)));return list;
    }
    public SmtpSettings Settings() { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT Json FROM Settings WHERE Id=1";return cmd.ExecuteScalar() is string s?JsonSerializer.Deserialize<SmtpSettings>(s)??new():new(); }
    public void SaveSettings(SmtpSettings s) { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO Settings(Id,Json) VALUES(1,$j) ON CONFLICT(Id) DO UPDATE SET Json=excluded.Json";Param(cmd,"$j",JsonSerializer.Serialize(s));cmd.ExecuteNonQuery(); }
    public bool Current(MonitorCheck check) => Checks().Any(c=>c.Id==check.Id && c.Revision==check.Revision && c.Enabled);
    public void AlertAttempt(MonitorCheck check,bool sent,string status)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText=sent?"UPDATE Checks SET LastAttempt=$at,LastAlert=$at,LastAlertStatus=$s WHERE Id=$id AND Revision=$rev":"UPDATE Checks SET LastAttempt=$at WHERE Id=$id AND Revision=$rev";
        Param(cmd,"$at",Stamp(DateTimeOffset.UtcNow));Param(cmd,"$s",status);Param(cmd,"$id",check.Id);Param(cmd,"$rev",check.Revision);cmd.ExecuteNonQuery();
    }
    public bool Lease(string owner)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO Lease(Id,Owner,UntilUtc) VALUES(1,$o,$until) ON CONFLICT(Id) DO UPDATE SET Owner=$o,UntilUtc=$until WHERE Lease.Owner=$o OR Lease.UntilUtc<$now";
        Param(cmd,"$o",owner);Param(cmd,"$until",Stamp(DateTimeOffset.UtcNow.AddSeconds(45)));Param(cmd,"$now",Stamp(DateTimeOffset.UtcNow));return cmd.ExecuteNonQuery()==1;
    }
    public void Release(string owner) { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="DELETE FROM Lease WHERE Owner=$o";Param(cmd,"$o",owner);cmd.ExecuteNonQuery(); }
    public string LeaseOwner() { using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT Owner FROM Lease WHERE UntilUtc>$now";Param(cmd,"$now",Stamp(DateTimeOffset.UtcNow));return cmd.ExecuteScalar() as string??"No active worker"; }
    public void Backup(string destination) { using var source=Open();using var target=new SqliteConnection($"Data Source={destination};Pooling=False");target.Open();source.BackupDatabase(target); }
}
