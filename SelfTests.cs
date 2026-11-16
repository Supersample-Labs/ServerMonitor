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
        await EngineTests.Run(folder,Assert);
        var now=DateTimeOffset.UtcNow;var clear=SslPolicyErrors.None;
        await SnmpTests(folder,now);
        await WindowsTests(folder,now);
        await SourceReadinessTests();
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
        using(var db=old.Open()){using var command=db.CreateCommand();command.CommandText="ALTER TABLE Checks DROP COLUMN WindowsJson;ALTER TABLE Checks DROP COLUMN SnmpJson;ALTER TABLE Events DROP COLUMN Notify;ALTER TABLE Checks DROP COLUMN ManualExpiration;ALTER TABLE Checks DROP COLUMN HttpPath;ALTER TABLE Checks DROP COLUMN HttpStatusMin;ALTER TABLE Checks DROP COLUMN HttpStatusMax;PRAGMA user_version=1;";command.ExecuteNonQuery();}
        old.Initialize();var migrated=old.Checks().Single();
        Assert(migrated.Kind==CheckKind.Certificate && migrated.Name=="Legacy certificate" && migrated.HttpPath=="/" && migrated.HttpStatusMax==399 && migrated.ManualExpiration==null && migrated.Snmp==new SnmpSettings() && migrated.Windows==new WindowsServerSettings(),"Existing database migrates without changing certificate-only monitors");
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
        // Construct WinForms only after asynchronous checks: controls may install a synchronization context without a message loop.
        string savedCiphertext=Secret.Protect("password-retention-test");
        Assert(Secret.KeepOrReplacePassword(savedCiphertext,@"SURFACE\Administrator",@"surface\administrator","",windowsAccount:true)==savedCiphertext,"Windows credential survives a blank edit and account-name casing changes");
        Assert(Secret.KeepOrReplacePassword(savedCiphertext,"user","different","",windowsAccount:true)=="","Changing Windows accounts does not reuse the previous account's password");
        string replaced=Secret.KeepOrReplacePassword(savedCiphertext,"user","user","replacement-test");
        Assert(replaced!="replacement-test" && Secret.Unprotect(replaced)=="replacement-test","Entered replacement password is encrypted before persistence");
        Assert(Secret.KeepOrReplacePassword(savedCiphertext,"user","user","",remove:true)=="","Explicit password removal clears the saved credential");
        var smtpCredentials=new SmtpSettings{Username="smtp-test-user",ProtectedPassword=savedCiphertext};store.SaveSettings(smtpCredentials);
        using(var smtpEditor=new SmtpPanel(store))Assert(smtpEditor.Read().ProtectedPassword==savedCiphertext,"SMTP connection edits retain a saved password without re-entry");
        var windowsSaved=new WindowsServerSettings{UseWorkerAccount=false,Username=@"DOMAIN\monitor",ProtectedPassword=Secret.Protect("test-only-password")};
        using(var panel=new WindowsSettingsPanel(windowsSaved))
        {
            Assert(panel.Value()==windowsSaved,"Editing Windows settings preserves the saved password when blank");
            IEnumerable<Control> Descendants(Control root){foreach(Control child in root.Controls){yield return child;foreach(var nested in Descendants(child))yield return nested;}}
            var user=Descendants(panel).OfType<TextBox>().Single(t=>t.AccessibleName=="Windows username");
            var password=Descendants(panel).OfType<TextBox>().Single(t=>t.AccessibleName=="Windows password");
            Assert(password.PlaceholderText.Contains("Saved password"),"Windows edit form visibly indicates that a password is already saved");
            user.Text=user.Text.ToLowerInvariant();Assert(panel.Value().ProtectedPassword==windowsSaved.ProtectedPassword,"Editing username casing retains the existing Windows credential");
            password.Text="replacement-ui-test";Assert(Secret.Unprotect(panel.Value().ProtectedPassword)=="replacement-ui-test","Windows edit form replaces a password only when a new one is entered");
        }
        using(var windowsDialog=new CheckDialog(new(){Kind=CheckKind.WindowsServer,Host="server.example.test",Windows=windowsSaved}))Assert(windowsDialog.Controls.Count>0,"Windows server monitor dialog initializes");
        using(var picker=new SnmpMetricDialog(new Store(Path.Combine(folder,"snmp.db")),"127.0.0.1",161,"public",1))Assert(picker.Controls.Count>0,"SNMP metric picker initializes with persisted catalog");
        using(var details=new DetailsViewer())
        {
            string longResult="CPU: 53%; Memory: 71%; "+new string('x',50000)+"; Disk Z: 95% used";
            Assert(DetailsViewer.Format("CPU: 53% (Healthy; warning 80%); Memory: 71%").Contains("(Healthy; warning 80%);"+Environment.NewLine+"Memory"),"Resource readings stay on separate lines with thresholds kept together");
            details.ShowDetails("All readings",longResult);
            Assert(details.FullText.Length>50000 && details.FullText.Contains("Disk Z: 95% used") && details.FullText.Contains(Environment.NewLine),"Full details viewer retains long results and separates check readings");
            TextBox? FindTextBox(Control parent){foreach(Control child in parent.Controls){if(child is TextBox text)return text;var nested=FindTextBox(child);if(nested!=null)return nested;}return null;}
            var textbox=FindTextBox(details)!;textbox.Select(10,5);details.ShowDetails("All readings",longResult);
            Assert(textbox.SelectionStart==10 && textbox.SelectionLength==5,"Unchanged refresh preserves details text selection");
        }
        using(var commandsViewer=new DetailsViewer(false,false)){string script=WinRmSource.SetupCommands("surface",false);commandsViewer.ShowDetails("Setup commands",script);Assert(commandsViewer.FullText==script,"Setup command viewer preserves executable text exactly");}
        using(var sourceDialog=new WinRmSourceDialog("surface",false,false))Assert(sourceDialog.Controls.Count>0,"Source PC readiness dialog initializes without changing configuration");
        log.Add("Service install/remove is implemented but not executed by self-tests; no permanent service changes were made.");
    }
    static async Task SourceReadinessTests()
    {
        var ready=new WinRmSourceSnapshot("5.1",true,"Running","Automatic","surface,server.example.test",true);
        Assert(!WinRmSource.NeedsAttention(ready,"surface",false),"WinRM source readiness accepts available CIM, running service, and named HTTP trust");
        Assert(WinRmSource.NeedsAttention(ready with{ServiceStatus="Stopped"},"surface",false),"WinRM source readiness identifies a stopped local service");
        Assert(WinRmSource.NeedsAttention(ready with{CimAvailable=false},"surface",true),"WinRM source readiness identifies missing CIM cmdlets");
        Assert(WinRmSource.NeedsAttention(ready,"other",false) && !WinRmSource.NeedsAttention(ready,"other",true),"HTTP trust is checked separately from HTTPS certificate authentication");
        Assert(!WinRmSource.IsTrusted("surface2","surface") && WinRmSource.IsTrusted(" SERVER.EXAMPLE.TEST , *.example.net ","server.example.test") && WinRmSource.IsTrusted("*.example.net","one.example.net"),"TrustedHosts matching respects names, whitespace, case, and wildcard entries");
        Assert(WinRmSource.NeedsAttention(ready with{TrustedHostsReadable=false},"surface",false),"Unreadable source trust is reported as unknown, not ready");
        string commands=WinRmSource.SetupCommands("surface",false);
        Assert(commands.Contains("'surface'") && commands.Contains("-Concatenate") && commands.Contains("Start-Service") && !commands.Contains("quickconfig") && !commands.Contains("Enable-PSRemoting"),"Source setup commands preserve trust and avoid creating listeners");
        Assert(!WinRmSource.SetupCommands("surface",true).Contains("Set-Item"),"HTTPS source setup does not modify TrustedHosts");
        bool invalid=false;try{WinRmSource.SetupCommands("surface';throw 'bad",false);}catch(ArgumentException){invalid=true;}Assert(invalid,"Invalid destinations cannot become setup commands");
        Assert(WinRmSource.Report(ready,"surface",false,true).Contains("LocalService") && WinRmSource.Report(ready,"surface",false,false).Contains("Inspection account"),"Readiness report distinguishes desktop inspection and service account access");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(35));
        Assert(WinRmSource.NeedsAttention(ready with{StartupType="Manual"},"surface",false),"Automatic readiness check identifies startup mode that needs unattended setup");
        foreach(var arguments in new[]{new[]{WinRmSourceSetup.Action,"http","surface"},new[]{WinRmSourceSetup.Action,"https","server.example.test"}})
            Assert(WinRmSourceSetup.ParseArguments(arguments).Host==arguments[2],"Elevated setup accepts only a destination and transport");
        foreach(var arguments in new[]{new[]{WinRmSourceSetup.Action,"http","*"},new[]{WinRmSourceSetup.Action,"http","surface';throw 'bad"},new[]{WinRmSourceSetup.Action,"ftp","surface"},new[]{WinRmSourceSetup.Action,"http","surface","extra"}})
        {
            bool rejected=false;try{WinRmSourceSetup.ParseArguments(arguments);}catch(ArgumentException){rejected=true;}Assert(rejected,"Elevated setup rejects wildcard, injection, unexpected mode, or extra arguments");
        }
        var elevation=WinRmSourceSetup.ElevationStartInfo(Path.Combine(AppContext.BaseDirectory,"ServerMonitor.exe"),"surface",false);
        Assert(elevation.UseShellExecute && elevation.Verb=="runas" && elevation.ArgumentList.SequenceEqual(new[]{WinRmSourceSetup.Action,"http","surface"}),"Configure this PC requests UAC for a constrained helper without credentials or script arguments");
        const string setupMocks="""
        Add-Type -AssemblyName System.ServiceProcess
        $script:trusted='existing.example.test';$script:additions=0;$script:startup='Manual';$script:running='Stopped'
        function Set-Service { param($Name,$StartupType,$ErrorAction) if($Name -ne 'WinRM'){throw 'Unexpected service'};$script:startup=$StartupType }
        function Start-Service { param($Name,$ErrorAction) if($Name -ne 'WinRM'){throw 'Unexpected service'};$script:running='Running' }
        function Get-Service {
            param($Name,$ErrorAction)
            $service=[pscustomobject]@{Status=$script:running;StartType=$script:startup}
            $service | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {param($status,$timeout) if($this.Status -ne [string]$status){throw 'Service did not start'}}
            $service | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
            return $service
        }
        function Get-Item {param($Path,$ErrorAction) if($Path -ne 'WSMan:\localhost\Client\TrustedHosts'){throw 'Unexpected setting'};[pscustomobject]@{Value=$script:trusted} }
        function Set-Item {
            param($Path,$Value,[switch]$Concatenate,[switch]$Force,$ErrorAction)
            if($Path -ne 'WSMan:\localhost\Client\TrustedHosts' -or $Value -ne 'surface' -or -not $Concatenate -or -not $Force){throw 'Unexpected trust change'}
            $script:trusted+=','+$Value;$script:additions++
        }
        """;
        string configured=WinRmSourceSetup.ConfigurationScript("surface",false);
        var setupRun=await WindowsProbe.Execute(setupMocks+"\ntry {\n"+configured+"\n"+configured+"\n[Console]::Out.WriteLine('TRUST='+$script:trusted+';ADDS='+$script:additions)\n} catch {[Console]::Out.WriteLine($_.Exception.Message);exit 1}","{}",deadline.Token);
        Assert(setupRun.ExitCode==0 && setupRun.Output.Contains(WinRmSourceSetup.SuccessMarker) && setupRun.Output.Contains("TRUST=existing.example.test,surface;ADDS=1"),"Mocked elevated setup preserves existing trust, adds one exact host, verifies startup, and is idempotent: "+setupRun.Output);
        string https=WinRmSourceSetup.ConfigurationScript("surface",true);
        var httpsRun=await WindowsProbe.Execute(setupMocks+"\n"+https+"\n[Console]::Out.WriteLine('ADDS='+$script:additions)","{}",deadline.Token);
        Assert(httpsRun.ExitCode==0 && httpsRun.Output.Contains("ADDS=0"),"Mocked HTTPS setup starts the service without modifying TrustedHosts");
        var rejectedRun=await WindowsProbe.Execute(setupMocks+"\nfunction Set-Service {throw 'Mock policy blocks this change'}\n"+configured,"{}",deadline.Token);
        Assert(rejectedRun.ExitCode!=0 && !rejectedRun.Output.Contains(WinRmSourceSetup.SuccessMarker),"Blocked setup is not reported as successful");
        var local=await WinRmSource.Inspect(deadline.Token);
        Assert(local.PowerShellVersion.StartsWith("5.1",StringComparison.Ordinal) && local.CimAvailable,"Read-only source inspection executes Windows PowerShell and verifies real CIM cmdlets");
        string syntaxScript="$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+Convert.ToBase64String(Encoding.UTF8.GetBytes(commands))+"')),[ref]$tokens,[ref]$errors);if($errors.Count){exit 1};[Console]::Out.WriteLine('valid')";
        var syntax=await WindowsProbe.Execute(syntaxScript,"{}",deadline.Token);Assert(syntax.ExitCode==0 && syntax.Output.Contains("valid"),"Generated source setup commands parse without being executed");
    }
    static async Task WindowsTests(string folder,DateTimeOffset now)
    {
        var settings=new WindowsServerSettings();var normal=new WindowsSnapshot(20,1000,500,[new("C:",1000,500),new("D:",2000,1000)]);
        Assert(WindowsProbe.Evaluate(settings,normal,now).Status==Health.Healthy,"Windows CPU, memory, and disks below thresholds are healthy");
        Assert(WindowsProbe.Evaluate(settings,normal with{CpuPercent=80},now).Status==Health.Warning && WindowsProbe.Evaluate(settings,normal with{CpuPercent=90},now).Status==Health.Critical,"Windows CPU thresholds include equality");
        Assert(WindowsProbe.Evaluate(settings,normal with{MemoryFreeKB=200},now).Status==Health.Warning && WindowsProbe.Evaluate(settings,normal with{MemoryFreeKB=100},now).Status==Health.Critical,"Windows physical memory used percentage triggers thresholds");
        Assert(WindowsProbe.Evaluate(settings,normal with{Disks=[new("C:",1000,200)]},now).Status==Health.Warning && WindowsProbe.Evaluate(settings,normal with{Disks=[new("C:",1000,100)]},now).Status==Health.Critical,"Windows disk used percentage triggers thresholds");
        Assert(WindowsProbe.Evaluate(settings,normal with{CpuPercent=80,Disks=[new("C:",1000,50)]},now).Status==Health.Critical,"Worst Windows resource determines overall severity");
        var cpuOnly=settings with{Memory=new(){Enabled=false},Disk=new(){Enabled=false}};
        Assert(WindowsProbe.Evaluate(cpuOnly,new(10,null,null,null),now).Status==Health.Healthy,"Disabled Windows metrics do not require unavailable readings");
        Assert(WindowsProbe.Evaluate(settings with{Drives="c:"},normal with{Disks=[new("C:",1000,500),new("D:",1000,0)]},now).Status==Health.Healthy,"Windows drive selection excludes unrelated full drives");
        foreach(var bad in new[]{normal with{CpuPercent=null},normal with{MemoryTotalKB=0},normal with{MemoryFreeKB=1001},normal with{Disks=[new("C:",0,0)]},normal with{Disks=[]},normal with{QueryError="Access denied"}})
        {
            bool failed=false;try{_=WindowsProbe.Evaluate(settings,bad,now);}catch(IOException){failed=true;}Assert(failed,"Missing, invalid, or inaccessible Windows data cannot report healthy");
        }
        bool missing=false;try{WindowsProbe.Evaluate(settings with{Drives="Z:"},normal,now);}catch(IOException){missing=true;}Assert(missing,"Missing configured Windows drive is an error");
        foreach(var bad in new[]{settings with{Cpu=new(){Warning=90,Critical=80}},settings with{Cpu=new(){Warning=-1}},settings with{Cpu=new(){Critical=101}},settings with{Cpu=new(){Enabled=false},Memory=new(){Enabled=false},Disk=new(){Enabled=false}},settings with{Drives="C:;throw 'bad'"},settings with{UseWorkerAccount=false}})
        {
            bool failed=false;try{WindowsProbe.Validate(bad);}catch(ArgumentException){failed=true;}Assert(failed,"Invalid Windows configuration rejected");
        }
        var check=new MonitorCheck{Kind=CheckKind.WindowsServer,Name="Windows resources",Host="server.example.test",Port=5986,TimeoutSeconds=30,Windows=settings with{UseWorkerAccount=false,Username=@"DOMAIN\monitor",ProtectedPassword=Secret.Protect("test-only-password"),Drives="C:, D:",Cpu=new(){Warning=70,Critical=85}}};
        var db=new Store(Path.Combine(folder,"windows.db"));db.Initialize();db.Save(check);var saved=db.Checks().Single();
        Assert(saved.Windows==check.Windows && Secret.Unprotect(saved.Windows.ProtectedPassword)=="test-only-password","Windows thresholds, selection, and protected credential persist");
        var warning=WindowsProbe.Evaluate(settings,normal with{CpuPercent=80},now);var critical=WindowsProbe.Evaluate(settings,normal with{CpuPercent=90},now);var smtp=new SmtpSettings{Enabled=true};
        var criticalOnly=saved with{Windows=settings with{MinimumSeverity="Critical"}};
        Assert(!Alerts.ShouldSend(criticalOnly,warning,smtp,now) && Alerts.ShouldSend(criticalOnly,critical,smtp,now),"Windows notification minimum severity filters warnings");
        var disabled=saved with{Windows=settings with{MinimumSeverity="None"}};
        Assert(!Alerts.ShouldSend(disabled,new(Health.Error,"Access denied",now),smtp,now),"Windows None suppresses resource and query-error notifications");
        Assert(Alerts.ShouldSend(criticalOnly,new(Health.Error,"Access denied",now),smtp,now),"Windows authentication and query failures alert at Critical minimum");
        Assert(Alerts.ShouldSend(criticalOnly with{LastAlertStatus="Critical",LastAlert=now,LastAttempt=now},WindowsProbe.Evaluate(settings,normal,now),smtp,now),"Windows resources use recovery email handling");
        db.Save(criticalOnly with{Id=saved.Id});saved=db.Checks().Single();db.Result(saved,warning);Assert(!db.Events().Single().Notify,"Windows warnings below minimum remain visible without desktop notification");
        var parsed=WindowsProbe.Parse("""{"CpuPercent":"12","MemoryTotalKB":1000,"MemoryFreeKB":250,"Disks":[{"Name":"C:","Size":"1000","FreeSpace":200}]}""");
        Assert(parsed.CpuPercent==12 && WindowsProbe.Evaluate(settings,parsed,now).Status==Health.Warning,"Windows JSON numeric strings and disk array parse correctly");
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var echo=await WindowsProbe.Execute("[Console]::InputEncoding=New-Object System.Text.UTF8Encoding($false);[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);[Console]::Out.WriteLine([Console]::In.ReadToEnd())","{\"message\":\"test £ input\"}",timeout.Token);
        Assert(echo.ExitCode==0 && echo.Output.Contains("test £ input"),"Hidden Windows PowerShell helper receives JSON via stdin with UTF-8");
        string astScript="$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+Convert.ToBase64String(Encoding.UTF8.GetBytes(WindowsProbe.QueryScript))+"')),[ref]$tokens,[ref]$errors);if($errors.Count){exit 1};[Console]::Out.WriteLine('valid')";
        var syntax=await WindowsProbe.Execute(astScript,"{}",timeout.Token);Assert(syntax.ExitCode==0 && syntax.Output.Contains("valid"),"WinRM query script parses in Windows PowerShell 5.1");
        const string mocks="""
        function New-CimSession { param($ComputerName,$Port,$SessionOption,$Authentication,$OperationTimeoutSec,$ErrorAction,$Credential)
            if ($SessionOption.GetType().Name -ne 'WSManSessionOptions') { throw 'Expected WSMan options' }
            if ($Authentication -ne 'Negotiate') { throw 'Expected Windows authentication' }
            if ($null -ne $Credential -and $Credential.GetNetworkCredential().Password -ne 'test-only') { throw 'Credential pipe error' }
            return 'test-session'
        }
        function Get-CimInstance { param($CimSession,$Namespace,$ClassName,$Filter,$Property,$ErrorAction)
            switch ($ClassName) {
                'Win32_PerfFormattedData_PerfOS_Processor' { [pscustomobject]@{PercentProcessorTime=42} }
                'Win32_OperatingSystem' { [pscustomobject]@{TotalVisibleMemorySize=1000;FreePhysicalMemory=300} }
                'Win32_LogicalDisk' { [pscustomobject]@{DeviceID='C:';Size=1000;FreeSpace=200} }
                default { throw 'Unexpected CIM query' }
            }
        }
        function Remove-CimSession { param($CimSession,$ErrorAction) }
        """;
        var scriptRequest="""{"Host":"test.invalid","Port":5986,"TimeoutSeconds":5,"UseSsl":true,"UseWorkerAccount":false,"Username":"test","Password":"test-only","Cpu":true,"Memory":true,"Disk":true}""";
        var queried=await WindowsProbe.Execute(mocks+"\n"+WindowsProbe.QueryScript,scriptRequest,timeout.Token);
        var sample=WindowsProbe.Parse(queried.Output);
        Assert(queried.ExitCode==0 && sample.QueryError==null && sample.CpuPercent==42 && sample.Disks?.Single().Name=="C:","WinRM query script binds real WSMan options, credentials, and CIM result serialization: "+sample.QueryError);
        using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(500));bool canceled=false;var elapsed=System.Diagnostics.Stopwatch.StartNew();
        try{await WindowsProbe.Execute("Start-Sleep -Seconds 30","{}",cancel.Token);}catch(OperationCanceledException){canceled=true;}
        Assert(canceled && elapsed.Elapsed<TimeSpan.FromSeconds(6),"Windows timeout cancels and terminates its query process");
    }
    static async Task SnmpTests(string folder,DateTimeOffset now)
    {
        var config=new SnmpSettings();SnmpProbe.Validate(config);
        Assert(SnmpProbe.Evaluate(config,79,now).Status==Health.Healthy && SnmpProbe.Evaluate(config,80,now).Status==Health.Warning && SnmpProbe.Evaluate(config,90,now).Status==Health.Critical,"SNMP inclusive rising thresholds");
        var falling=config with{LowerIsWorse=true,Warning=20,Critical=10};
        Assert(SnmpProbe.Evaluate(falling,21,now).Status==Health.Healthy && SnmpProbe.Evaluate(falling,20,now).Status==Health.Warning && SnmpProbe.Evaluate(falling,10,now).Status==Health.Critical,"SNMP inclusive falling thresholds");
        bool invalid=false;try{SnmpProbe.Validate(config with{Critical=80});}catch(ArgumentException){invalid=true;}Assert(invalid,"SNMP rejects overlapping thresholds");
        var monitor=new MonitorCheck{Name="SNMP",Kind=CheckKind.SNMP,Host="127.0.0.1",Port=161,Snmp=config with{MinimumSeverity="Critical"}};
        var smtp=new SmtpSettings{Enabled=true};
        Assert(!Alerts.ShouldSend(monitor,SnmpProbe.Evaluate(config,80,now),smtp,now) && Alerts.ShouldSend(monitor,SnmpProbe.Evaluate(config,90,now),smtp,now),"SNMP minimum email severity enforced");
        Assert(Alerts.ShouldSend(monitor,new(Health.NoResponse,"timeout",now),smtp,now) && !Alerts.ShouldSend(monitor with{Snmp=config with{MinimumSeverity="None"}},new(Health.Error,"error",now),smtp,now),"SNMP failures alert unless disabled");
        var db=new Store(Path.Combine(folder,"snmp.db"));db.Initialize();db.Save(monitor);var saved=db.Checks().Single();
        Assert(saved.Snmp==monitor.Snmp && saved.Kind==CheckKind.SNMP,"SNMP configuration round trip");
        db.Result(saved,SnmpProbe.Evaluate(config,80,now));Assert(!db.Events().Single().Notify,"SNMP below minimum severity remains visible without desktop notification");
        db.Result(db.Checks().Single(),SnmpProbe.Evaluate(config,90,now));Assert(db.Events().First().Notify,"SNMP critical desktop notification enabled");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));var ct=deadline.Token;
        using var agent=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var server=Task.Run(async()=>{
            var request=await agent.ReceiveAsync(ct);var r=new System.Formats.Asn1.AsnReader(request.Buffer,System.Formats.Asn1.AsnEncodingRules.BER).ReadSequence();
            Assert(r.ReadInteger()==1 && Encoding.UTF8.GetString(r.ReadOctetString())==config.Community,"SNMP v2c request version and community");
            var pdu=r.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific,0,true));int id=(int)pdu.ReadInteger();pdu.ReadInteger();pdu.ReadInteger();var v=pdu.ReadSequence().ReadSequence();
            Assert(v.ReadObjectIdentifier()==config.Oid,"SNMP GET requests configured OID");
            await agent.SendAsync(SnmpResponse(config,id+1,99),request.RemoteEndPoint,ct);
            await agent.SendAsync(SnmpResponse(config,id,90),request.RemoteEndPoint,ct);
        },ct);
        var result=await Probes.Run(monitor with{Port=((IPEndPoint)agent.Client.LocalEndPoint!).Port,TimeoutSeconds=2},ct);Assert(result.Status==Health.Critical,"SNMP probe result: "+result.Detail);await server;
        Assert(result.Status==Health.Critical && result.Detail.Contains("90"),"Live SNMP GET ignores unrelated ID and evaluates numeric response");
        var silent=await Probes.Run(monitor with{Port=((IPEndPoint)agent.Client.LocalEndPoint!).Port,TimeoutSeconds=1},ct);
        Assert(silent.Status==Health.NoResponse,"SNMP timeout is NoResponse");
        bool malformed=false;try{SnmpProbe.ReadResponse(new byte[]{0x30,0x7f},config,1);}catch(Lextm.SharpSnmpLib.SnmpException){malformed=true;}Assert(malformed,"Malformed SNMP packet rejected");
        Assert(SnmpProbe.ReadResponse(SnmpResponse(config,1,18446744073709551615m),config,1)==18446744073709551615m,"SNMP Counter64 retains unsigned precision");
        await SnmpDiscoveryTests(db,ct);
    }
    static async Task SnmpDiscoveryTests(Store db,CancellationToken ct)
    {
        const string json="""
        {"temp":{"class":"objecttype","nodetype":"scalar","name":"Example temperature","oid":"1.3.6.1.4.1.32473.1","units":"degrees C","syntax":{"type":"Integer32"},"maxaccess":"read-only","description":"Example temperature."},
         "column":{"class":"objecttype","nodetype":"column","name":"Example load","oid":"1.3.6.1.4.1.32473.2.1","units":"percent","syntax":{"type":"Gauge32"},"maxaccess":"read-only"},
         "table":{"class":"objecttype","nodetype":"table","name":"skip","oid":"1.3.6.1.4.1.32473.2","maxaccess":"not-accessible"}}
        """;
        Assert(db.ImportMetrics(json)==2,"PySMI JSON imports readable scalars and columns, skips table containers");
        var catalog=db.Metrics();
        Assert(catalog.Single(m=>m.Name=="Example temperature").Numeric,"PySMI numeric syntax supports direct scalar selection");
        Assert(SnmpCatalog.Match(catalog,"1.3.6.1.4.1.32473.1.0")?.Units=="degrees C" && SnmpCatalog.Match(catalog,"1.3.6.1.4.1.32473.2.1.4")?.Name=="Example load","Catalog resolves scalar and table instances");
        Assert(SnmpCatalog.Match(catalog,"1.3.6.1.4.1.32473.10.0")==null,"Catalog matching respects OID boundaries");
        int count=catalog.Count;bool rejected=false;try{db.ImportMetrics("[{\"oid\":\"bad\",\"name\":\"Bad\"}]");}catch(ArgumentException){rejected=true;}
        Assert(rejected&&db.Metrics().Count==count,"Invalid catalog import leaves persisted definitions intact");
        var roundTrip=System.Text.Json.JsonSerializer.Serialize(new[]{new SnmpMetric("1.3.6.1.4.1.32473.3","Example metric","raw","Custom scalar")},new System.Text.Json.JsonSerializerOptions{PropertyNamingPolicy=System.Text.Json.JsonNamingPolicy.CamelCase});
        Assert(db.ImportMetrics(roundTrip)==1 && db.Metrics().Count==count+1,"Simple catalog array imports and persists");
        using var agent=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var config=new SnmpSettings();
        var server=Task.Run(async()=>{
            var values=new List<Lextm.SharpSnmpLib.Variable>{new(new Lextm.SharpSnmpLib.ObjectIdentifier("1.3.6.1.4.1.32473.1.0"),new Lextm.SharpSnmpLib.Integer32(42)),new(new Lextm.SharpSnmpLib.ObjectIdentifier("1.3.6.1.4.1.32473.2.1.4"),new Lextm.SharpSnmpLib.Gauge32(75)),new(new Lextm.SharpSnmpLib.ObjectIdentifier("1.3.6.1.4.1.32473.2.1.5"),new Lextm.SharpSnmpLib.OctetString("device text")),new(new Lextm.SharpSnmpLib.ObjectIdentifier("1.3.6.1.4.1.32474.1.0"),new Lextm.SharpSnmpLib.Integer32(0))};
            foreach(var value in values)
            {
                var packet=await agent.ReceiveAsync(ct);var request=Lextm.SharpSnmpLib.Messaging.MessageFactory.ParseMessages(packet.Buffer,new Lextm.SharpSnmpLib.Security.UserRegistry()).Single();
                Assert(request.Scope.Pdu.TypeCode==Lextm.SharpSnmpLib.SnmpType.GetNextRequestPdu,"Discovery uses SNMP GET NEXT");
                var response=new Lextm.SharpSnmpLib.Messaging.ResponseMessage(request.Scope.Pdu.RequestId.ToInt32(),Lextm.SharpSnmpLib.VersionCode.V2,new Lextm.SharpSnmpLib.OctetString("public"),Lextm.SharpSnmpLib.ErrorCode.NoError,0,[value]);
                await agent.SendAsync(response.ToBytes(),packet.RemoteEndPoint,ct);
            }
        },ct);
        var discovery=await SnmpProbe.Discover("127.0.0.1",((IPEndPoint)agent.Client.LocalEndPoint!).Port,config,"1.3.6.1.4.1.32473",1,catalog,ct);await server;
        Assert(discovery.Readings.Count==3 && discovery.Readings[0].Name=="Example temperature" && discovery.Readings[1].Name=="Example load [4]","Live discovery names catalog metrics and preserves table indices");
        Assert(discovery.Readings[1].Value=="75" && !discovery.Readings[2].Numeric && discovery.Message=="Discovery complete.","Discovery retains live numeric/text values and stops at subtree boundary");
        var incomplete=await SnmpProbe.Discover("127.0.0.1",((IPEndPoint)agent.Client.LocalEndPoint!).Port,config,"1.3.6.1.4.1.32473",1,catalog,ct);
        Assert(incomplete.Readings.Count==0 && incomplete.Message.Contains("timeout",StringComparison.OrdinalIgnoreCase),"Discovery timeout reports incomplete scan");
        using var canceled=new CancellationTokenSource();canceled.Cancel();bool stopped=false;
        try{await SnmpProbe.Discover("127.0.0.1",161,config,"1.3.6.1",1,catalog,canceled.Token);}catch(OperationCanceledException){stopped=true;}
        Assert(stopped,"Discovery cancellation stops network work");
    }
    static byte[] SnmpResponse(SnmpSettings settings,int id,decimal value)
    {
        var w=new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.BER);w.PushSequence();w.WriteInteger(1);w.WriteOctetString(Encoding.UTF8.GetBytes(settings.Community));
        var tag=new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific,2,true);w.PushSequence(tag);w.WriteInteger(id);w.WriteInteger(0);w.WriteInteger(0);w.PushSequence();w.PushSequence();w.WriteObjectIdentifier(settings.Oid);
        w.WriteInteger(new System.Numerics.BigInteger(value),new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.Application,6));w.PopSequence();w.PopSequence();w.PopSequence(tag);w.PopSequence();return w.Encode();
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
