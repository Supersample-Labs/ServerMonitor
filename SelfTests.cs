using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerMonitor;
public static class SelfTests
{
    static readonly List<string> log=[];
    static void Assert(bool value,string name){if(!value)throw new Exception("FAIL: "+name);log.Add("PASS: "+name);}
    public static int Run()
    {
        var folder=Path.Combine(Path.GetTempPath(),"ServerMonitor-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);int exit=0;
        try{Tests(folder).GetAwaiter().GetResult();log.Add("ALL TESTS PASSED");}
        catch(Exception ex){log.Add(ex.ToString());exit=1;}
        finally{try{Directory.Delete(folder,true);}catch{}File.WriteAllLines(Path.Combine(AppContext.BaseDirectory,"ServerMonitor-selftest.log"),log);}
        return exit;
    }
    static async Task Tests(string folder)
    {
        var now=DateTimeOffset.UtcNow;var clear=SslPolicyErrors.None;
        Assert(Probes.CertificateResult(now.AddDays(31),now.AddDays(-1),clear,now,1).Status==Health.Healthy,"Certificate >30 days is green");
        Assert(Probes.CertificateResult(now.AddDays(30),now.AddDays(-1),clear,now,1).Status==Health.Expiring,"Certificate exactly 30 days is red");
        Assert(Probes.CertificateResult(now.AddSeconds(-1),now.AddDays(-1),clear,now,1).Status==Health.Expired,"Expired certificate is red");
        Assert(Probes.CertificateResult(now.AddDays(90),now.AddDays(-1),SslPolicyErrors.RemoteCertificateNameMismatch,now,1).Status==Health.InvalidCertificate,"TLS hostname mismatch is unhealthy");
        Assert(Probes.CertificateResult(now.AddDays(90),now.AddDays(1),clear,now,1).Status==Health.InvalidCertificate,"Future-dated certificate is unhealthy");
        Assert(Probes.PrivateCertificateResult(now.AddDays(31),now).Status==Health.Healthy,"Private certificate above 30 days is healthy");
        Assert(Probes.PrivateCertificateResult(now.AddDays(30),now).Status==Health.Expiring,"Private certificate exactly 30 days alerts");
        Assert(Probes.PrivateCertificateResult(now.AddDays(30).AddSeconds(1),now).Status==Health.Healthy,"Private certificate just outside threshold remains healthy");
        Assert(Probes.PrivateCertificateResult(now,now).Status==Health.Expired,"Private certificate expires at assigned instant");
        Assert(Probes.PrivateCertificateResult(null,now).Status==Health.Error,"Missing manual expiration is unhealthy");
        var manualDb=new Store(Path.Combine(folder,"manual.db"));manualDb.Initialize();
        var assigned=now.ToOffset(TimeSpan.FromHours(-6)).AddDays(10);
        manualDb.Save(new(){Name="SAML signing",Kind=CheckKind.PrivateCertificate,ManualExpiration=assigned});
        var manual=manualDb.Checks().Single();
        Assert(manual.ManualExpiration==assigned && manual.Host=="","Manual expiration persists independently of host and check results");
        var manualResult=await Probes.Run(manual,CancellationToken.None);
        Assert(manualResult.Status==Health.Expiring && manualResult.Expires==assigned && manualResult.LatencyMs==null,"Private check runs without a network target");
        manualDb.Result(manual,manualResult);manualDb.RequestChecks();
        Assert(manualDb.Checks().Single().ManualExpiration==assigned,"Recheck retains configured expiration");
        manualDb.Save(manual with{ManualExpiration=now.AddDays(90)});
        var renewed=manualDb.Checks().Single();
        Assert((await Probes.Run(renewed,CancellationToken.None)).Status==Health.Healthy && renewed.LastChecked==null,"Renewed private certificate becomes healthy after edit");
        var privateSmtp=new SmtpSettings{Enabled=true,ReminderHours=24};
        Assert(Alerts.ShouldSend(manual,manualResult,privateSmtp,now),"Expiring private certificate uses existing email alerts");
        var privateNotified=manual with{LastAlertStatus="Expiring",LastAlert=now,LastAttempt=now};
        Assert(!Alerts.ShouldSend(privateNotified,manualResult,privateSmtp,now.AddHours(1)) && Alerts.ShouldSend(privateNotified,manualResult,privateSmtp,now.AddHours(24)),"Private certificate reminders respect delivery interval");
        Assert(Alerts.ShouldSend(privateNotified,Probes.PrivateCertificateResult(now,now),privateSmtp,now),"Private certificate expiration transition alerts immediately");
        var healthyCert=Probes.CertificateResult(now.AddDays(90),now.AddDays(-1),clear,now,1);
        var httpsCheck=new MonitorCheck{Kind=CheckKind.HTTPS};
        Assert(Probes.CombineHttps(healthyCert,200,httpsCheck,1).Status==Health.Healthy,"HTTPS 200 plus valid certificate is green");
        Assert(Probes.CombineHttps(healthyCert,500,httpsCheck,1).Status==Health.HttpError,"HTTPS 500 is red even with a healthy certificate");
        Assert(Probes.CombineHttps(healthyCert,302,httpsCheck,1).Status==Health.Healthy,"HTTPS default range accepts redirect responses");
        Assert(Probes.CombineHttps(healthyCert,302,httpsCheck with{HttpStatusMax=299},1).Status==Health.HttpError,"Custom HTTP status range is enforced");
        Assert(Probes.CombineHttps(Probes.CertificateResult(now.AddDays(10),now.AddDays(-1),clear,now,1),200,httpsCheck,1).Status==Health.Expiring,"HTTPS 200 does not hide an expiring certificate");
        Assert(Probes.CombineHttps(Probes.CertificateResult(now.AddDays(90),now.AddDays(-1),SslPolicyErrors.RemoteCertificateChainErrors,now,1),200,httpsCheck,1).Status==Health.InvalidCertificate,"HTTPS 200 does not hide invalid TLS trust");
        Assert(Probes.HttpPath("/health?ready=1")=="/health?ready=1","HTTPS path and query retained");
        bool unsafePath=false;try{_=Probes.HttpPath("/health\r\nHost: other");}catch(ArgumentException){unsafePath=true;}Assert(unsafePath,"HTTP request header injection rejected");
        Assert(Secret.Unprotect(Secret.Protect("temporary-test-password"))=="temporary-test-password","Machine DPAPI password round trip");
        var store=new Store(Path.Combine(folder,"test.db"));store.Initialize();store.Save(new(){Name="Loopback",Host="127.0.0.1",Port=443});var saved=store.Checks().Single();
        Assert(saved.Revision==1&&saved.Status==Health.Pending,"SQLite monitor creation and read");
        saved=saved with{Name="Edited"};store.Save(saved);var edited=store.Checks().Single();Assert(edited.Name=="Edited"&&edited.Revision==2,"SQLite edit invalidates in-flight revision");
        Assert(!store.Result(saved,new(Health.Down,"Stale",now)),"Stale result cannot overwrite edited check");
        Assert(store.Result(edited,new(Health.Healthy,"OK",now,4)),"Current result persisted");Assert(store.Events().Count==1,"Health transition persisted as event");
        Assert(store.Lease("one")&&!store.Lease("two")&&store.Lease("one"),"Cross-process database lease excludes duplicate workers");store.Release("one");Assert(store.Lease("two"),"Lease handoff");store.Release("two");
        var smtp=new SmtpSettings{Enabled=true,Host="127.0.0.1",From="monitor@example.test",Recipients="one@example.test;two@example.test",ReminderHours=24};store.SaveSettings(smtp);Assert(store.Settings().Recipients==smtp.Recipients,"SMTP configuration persisted");
        var down=new CheckResult(Health.Down,"Down",now);Assert(Alerts.ShouldSend(edited,down,smtp,now),"Initial failed check alerts");
        var notified=edited with{LastAlertStatus="Down",LastAlert=now,LastAttempt=now};Assert(!Alerts.ShouldSend(notified,down,smtp,now.AddHours(1)),"Delivered alert is deduplicated");Assert(Alerts.ShouldSend(notified,down,smtp,now.AddHours(24)),"Reminder after configured interval");Assert(Alerts.ShouldSend(notified,new(Health.Healthy,"OK",now),smtp,now.AddMinutes(1)),"Recovery email transition");Assert(!Alerts.ShouldSend(edited with{LastAttempt=now},down,smtp,now.AddMinutes(1)),"Failed email retry is throttled");
        store.Backup(Path.Combine(folder,"backup.db"));Assert(new Store(Path.Combine(folder,"backup.db")).Checks().Count==1,"SQLite consistent backup");
        var old=new Store(Path.Combine(folder,"legacy.db"));old.Initialize();old.Save(new(){Name="Legacy certificate",Host="localhost",Kind=CheckKind.Certificate});
        using(var db=old.Open()){using var command=db.CreateCommand();command.CommandText="ALTER TABLE Checks DROP COLUMN ManualExpiration;ALTER TABLE Checks DROP COLUMN HttpPath;ALTER TABLE Checks DROP COLUMN HttpStatusMin;ALTER TABLE Checks DROP COLUMN HttpStatusMax;PRAGMA user_version=1;";command.ExecuteNonQuery();}
        old.Initialize();var migrated=old.Checks().Single();
        Assert(migrated.Kind==CheckKind.Certificate && migrated.Name=="Legacy certificate" && migrated.HttpPath=="/" && migrated.HttpStatusMax==399 && migrated.ManualExpiration==null,"Existing database migrates without changing certificate-only monitors");
        var transfer=Path.Combine(folder,"upgrade");Directory.CreateDirectory(transfer);store.Backup(Path.Combine(transfer,"PortSentinel.db"));Paths.ImportLegacyDatabase(transfer);
        var imported=new Store(Path.Combine(transfer,"ServerMonitor.db"));
        Assert(imported.Checks().Count==1 && imported.Settings().Host==smtp.Host && imported.LeaseOwner()=="No active worker","Renamed database import preserves checks and SMTP settings without stale worker ownership");
        var websiteDb=new Store(Path.Combine(folder,"website.db"));websiteDb.Initialize();websiteDb.Save(new(){Name="Website",Host="localhost",Kind=CheckKind.HTTPS,HttpPath="/health",HttpStatusMin=201,HttpStatusMax=204});var websiteSaved=websiteDb.Checks().Single();
        Assert(websiteSaved.Kind==CheckKind.HTTPS && websiteSaved.HttpPath=="/health" && websiteSaved.HttpStatusMin==201 && websiteSaved.HttpStatusMax==204,"HTTPS path and status range persist in SQLite");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(35));var ct=deadline.Token;
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
        var accept=listener.AcceptTcpClientAsync(ct).AsTask();var tcp=await Probes.Run(new(){Host="127.0.0.1",Port=port,Kind=CheckKind.TCP},ct);using(var accepted=await accept){}listener.Stop();
        Assert(tcp.Status==Health.Healthy,"Live TCP loopback listener detected");var closed=await Probes.Run(new(){Host="127.0.0.1",Port=port,Kind=CheckKind.TCP,TimeoutSeconds=1},ct);Assert(closed.Status==Health.Down,"Closed TCP port is red");
        using(var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0)))
        {
            int udpPort=((IPEndPoint)udp.Client.LocalEndPoint!).Port;
            var echo=Task.Run(async()=>{var packet=await udp.ReceiveAsync(ct);await udp.SendAsync(new byte[]{0x4F,0x4B},packet.RemoteEndPoint,ct);},ct);
            var response=await Probes.Run(new(){Host="127.0.0.1",Port=udpPort,Kind=CheckKind.UDP,UdpMode="Custom",Payload="PING",ExpectedHex="4f4b",TimeoutSeconds=2},ct);await echo;Assert(response.Status==Health.Healthy,"Custom UDP payload and expected response prefix");
            var silent=await Probes.Run(new(){Host="127.0.0.1",Port=udpPort,Kind=CheckKind.UDP,UdpMode="Custom",Payload="PING",TimeoutSeconds=1},ct);Assert(silent.Status==Health.NoResponse,"Silent UDP port is inconclusive NoResponse");
        }
        using(var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0)))
        {
            int udpPort=((IPEndPoint)udp.Client.LocalEndPoint!).Port;
            var dns=Task.Run(async()=>{var packet=await udp.ReceiveAsync(ct);packet.Buffer[2]|=128;await udp.SendAsync(packet.Buffer,packet.RemoteEndPoint,ct);},ct);
            var response=await Probes.Run(new(){Host="127.0.0.1",Port=udpPort,Kind=CheckKind.UDP,UdpMode="DNS",TimeoutSeconds=2},ct);await dns;Assert(response.Status==Health.Healthy,"DNS UDP probe validates matching response");
        }
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("localhost");request.CertificateExtensions.Add(san.Build());using var ephemeral=request.CreateSelfSigned(now.AddDays(-1),now.AddDays(10));using var cert=X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx),null,X509KeyStorageFlags.Exportable);
        var tlsListener=new TcpListener(IPAddress.Loopback,0);tlsListener.Start();int tlsPort=((IPEndPoint)tlsListener.LocalEndpoint).Port;
        var tlsServer=Task.Run(async()=>{using var connection=await tlsListener.AcceptTcpClientAsync(ct);using var stream=new SslStream(connection.GetStream());await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=cert},ct);},ct);
        var tlsResult=await Probes.Run(new(){Host="127.0.0.1",TlsName="localhost",Port=tlsPort,Kind=CheckKind.Certificate,TimeoutSeconds=5},ct);await tlsServer;tlsListener.Stop();Assert(tlsResult.Status==Health.Expiring && tlsResult.Expires.HasValue,"Live TLS handshake captures expiring certificate");
        var website=await Https(cert,"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",ct);
        Assert(website.Result.Status==Health.Expiring && website.Result.Detail.Contains("HTTP 200") && website.Request.Contains("GET /health?ready=1 HTTP/1.1"),"Live HTTPS GET checks the chosen path and retains certificate warning");
        Assert(website.Request.Contains("Host: localhost:"),"HTTPS uses the configured TLS name for the Host header");
        var failedWebsite=await Https(cert,"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n",ct);
        Assert(failedWebsite.Result.Status==Health.HttpError && failedWebsite.Result.Expires.HasValue && failedWebsite.Result.Detail.Contains("HTTP 500"),"Live HTTPS 500 is red and retains certificate expiry");
        var redirect=await Https(cert,"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n",ct);
        Assert(redirect.Result.Status==Health.Expiring && redirect.Result.Detail.Contains("HTTP 302"),"Live HTTPS evaluates a redirect without following it");
        var malformed=await Https(cert,"not-http\r\n\r\n",ct);
        Assert(malformed.Result.Status==Health.HttpError,"Malformed HTTPS response is unhealthy");
        var truncated=await Https(cert,"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",ct);
        Assert(truncated.Result.Status==Health.HttpError,"Truncated HTTP headers cannot appear healthy");
        var relay=new TcpListener(IPAddress.Loopback,0);relay.Start();smtp=smtp with{Port=((IPEndPoint)relay.LocalEndpoint).Port,Security="None"};
        string received="";
        var smtpServer=Task.Run(async()=>
        {
            using var connection=await relay.AcceptTcpClientAsync(ct);await using var stream=connection.GetStream();using var reader=new StreamReader(stream,Encoding.ASCII,false,1024,true);await using var writer=new StreamWriter(stream,Encoding.ASCII,1024,true){AutoFlush=true,NewLine="\r\n"};
            await writer.WriteLineAsync("220 localhost test relay");bool data=false;while(await reader.ReadLineAsync(ct) is string line)
            {
                if(data){if(line=="."){data=false;await writer.WriteLineAsync("250 queued");}else received+=line+"\n";continue;}
                if(line.StartsWith("EHLO")){await writer.WriteLineAsync("250-localhost");await writer.WriteLineAsync("250 8BITMIME");}
                else if(line.StartsWith("DATA")){data=true;await writer.WriteLineAsync("354 send message");}
                else if(line.StartsWith("QUIT")){await writer.WriteLineAsync("221 bye");break;}
                else await writer.WriteLineAsync("250 OK");
            }
        },ct);
        await Alerts.Send(smtp,"Server Monitor integration test","Local test message only.",ct);await smtpServer;relay.Stop();Assert(received.Contains("integration test")&&received.Contains("Local test message"),"SMTP delivery to local fake relay");
        store.Remove(edited.Id);Assert(store.Checks().Count==0,"Remove monitor");
        using(var dialog=new CheckDialog())
        using(var settings=new SmtpPanel(store))
        using(var window=new MainForm(store,false))
            Assert(dialog.Controls.Count>0 && settings.Controls.Count>0 && window.Controls.Count>0,"WinForms monitor, SMTP, and dashboard constructors initialize successfully");
        log.Add("Service install/remove is implemented but not executed by self-tests; no permanent service changes were made.");
    }
    static async Task<(CheckResult Result,string Request)> Https(X509Certificate2 certificate,string response,CancellationToken ct)
    {
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;string request="";
        try
        {
            var server=Task.Run(async()=>{
                using var connection=await listener.AcceptTcpClientAsync(ct);using var stream=new SslStream(connection.GetStream());
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate},ct);
                using var reader=new StreamReader(stream,Encoding.ASCII,false,1024,true);
                while(await reader.ReadLineAsync(ct) is string line){request+=line+"\n";if(line.Length==0)break;}
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response),ct);
            },ct);
            var result=await Probes.Run(new(){Host="127.0.0.1",TlsName="localhost",Port=port,Kind=CheckKind.HTTPS,HttpPath="/health?ready=1",TimeoutSeconds=5},ct);
            await server;return (result,request);
        }
        finally{listener.Stop();}
    }
}
