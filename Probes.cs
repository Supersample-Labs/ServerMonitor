using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerMonitor;
public static class Probes
{
    public static string HttpPath(string value)
    {
        if(string.IsNullOrWhiteSpace(value))return "/";
        if(!value.StartsWith('/') || value.StartsWith("//") || value.Contains('#') || value.Contains('\\') || value.Any(c=>char.IsControl(c)))
            throw new ArgumentException("Enter a path such as / or /health, without a fragment, hostname, or control characters.");
        return new Uri("https://monitor.invalid"+value,UriKind.Absolute).PathAndQuery;
    }
    public static CheckResult CombineHttps(CheckResult certificate,int status,MonitorCheck check,long latency)
    {
        bool accepted=status>=check.HttpStatusMin && status<=check.HttpStatusMax;
        return certificate with {Status=accepted?certificate.Status:Health.HttpError,CheckedAt=DateTimeOffset.UtcNow,LatencyMs=latency,
            Detail=$"TCP connected; HTTP {status} {(accepted?"accepted":"outside expected range")} ({check.HttpStatusMin}–{check.HttpStatusMax}); {certificate.Detail}"};
    }
    public static byte[] Hex(string text) => Convert.FromHexString(string.Concat(text.Where(c=>!char.IsWhiteSpace(c) && c!='-')));
    public static CheckResult CertificateResult(DateTimeOffset expires,DateTimeOffset notBefore,SslPolicyErrors errors,DateTimeOffset now,long latency)
    {
        var days=(expires-now).TotalDays;
        var detail=$"Expires {expires.LocalDateTime:yyyy-MM-dd HH:mm zzz} ({Math.Ceiling(days):0} days); TLS validation: {errors}";
        var status=expires<=now?Health.Expired:days<=30?Health.Expiring:errors!=SslPolicyErrors.None || notBefore>now?Health.InvalidCertificate:Health.Healthy;
        return new(status,detail,now,latency,expires);
    }
    public static CheckResult PrivateCertificateResult(DateTimeOffset? expires,DateTimeOffset now)
    {
        if(!expires.HasValue)return new(Health.Error,"Private certificate expiration has not been configured",now);
        var days=(expires.Value-now).TotalDays;
        return new(expires<=now?Health.Expired:days<=30?Health.Expiring:Health.Healthy,
            $"Manually tracked certificate; expires {expires.Value.LocalDateTime:yyyy-MM-dd HH:mm zzz} ({Math.Ceiling(days):0} days remaining)",now,Expires:expires);
    }
    public static async Task<CheckResult> Run(MonitorCheck check,CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if(check.Kind==CheckKind.PrivateCertificate)return PrivateCertificateResult(check.ManualExpiration,DateTimeOffset.UtcNow);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(check.TimeoutSeconds));var ct=timeout.Token;var watch=Stopwatch.StartNew();
        try
        {
            if(check.Kind==CheckKind.UDP)return await Udp(check,watch,ct);
            using var client=new TcpClient();await client.ConnectAsync(check.Host,check.Port,ct);
            if(check.Kind==CheckKind.TCP)return new(Health.Healthy,"TCP connection accepted",DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
            X509Certificate2? certificate=null;SslPolicyErrors errors=SslPolicyErrors.RemoteCertificateNotAvailable;
            using var ssl=new SslStream(client.GetStream(),false,(_,cert,_,policy)=>{
                errors=policy;
                if(cert!=null)certificate=X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                // Monitor inspection: validation errors always remain unhealthy. HTTPS sends only an anonymous GET.
                return cert!=null;
            });
            try
            {
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost=string.IsNullOrWhiteSpace(check.TlsName)?check.Host:check.TlsName,CertificateRevocationCheckMode=X509RevocationMode.NoCheck },ct);
                if(certificate==null)return new(Health.Error,"TLS peer did not provide a certificate",DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
                var result=CertificateResult(certificate.NotAfter.ToUniversalTime(),certificate.NotBefore.ToUniversalTime(),errors,DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
                if(check.Kind!=CheckKind.HTTPS)return result;
                try
                {
                    var status=await HttpStatus(ssl,check,ct);
                    return CombineHttps(result,status,check,watch.ElapsedMilliseconds);
                }
                catch(OperationCanceledException) when(cancellation.IsCancellationRequested){throw;}
                catch(Exception ex)
                {
                    var detail=ex is OperationCanceledException?$"HTTP response timed out within the {check.TimeoutSeconds}s total check timeout":$"HTTP response failed: {ex.Message}";
                    return result with {Status=Health.HttpError,CheckedAt=DateTimeOffset.UtcNow,LatencyMs=watch.ElapsedMilliseconds,Detail=$"TCP connected; {detail}; {result.Detail}"};
                }
            }
            finally { certificate?.Dispose(); }
        }
        catch(OperationCanceledException) when(!cancellation.IsCancellationRequested)
        {return new(check.Kind==CheckKind.UDP?Health.NoResponse:Health.Down,$"No response within {check.TimeoutSeconds}s"+(check.Kind==CheckKind.UDP?". UDP silence is inconclusive; check the probe payload and firewall.":" (DNS, connection, or TLS timeout)."),DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);}
        catch(SocketException ex) { return new(Health.Down,$"{ex.SocketErrorCode}: {ex.Message}",DateTimeOffset.UtcNow,watch.ElapsedMilliseconds); }
        catch(OperationCanceledException) { throw; }
        catch(Exception ex) { return new(Health.Error,$"{ex.GetType().Name}: {ex.Message}",DateTimeOffset.UtcNow,watch.ElapsedMilliseconds); }
    }
    static async Task<int> HttpStatus(SslStream stream,MonitorCheck check,CancellationToken ct)
    {
        string host=string.IsNullOrWhiteSpace(check.TlsName)?check.Host:check.TlsName;
        if(host.Any(c=>char.IsControl(c)||char.IsWhiteSpace(c)) || host.Contains('/') || host.Contains('\\'))throw new ArgumentException("Invalid HTTP host.");
        if(IPAddress.TryParse(host,out var ip)){if(ip.AddressFamily==AddressFamily.InterNetworkV6)host="["+host+"]";}
        else host=new System.Globalization.IdnMapping().GetAscii(host);
        if(check.Port!=443)host+=":"+check.Port;
        var request=$"GET {HttpPath(check.HttpPath)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ServerMonitor/1.1\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request),ct);
        var budget=new[]{32768};
        for(int informational=0;informational<6;informational++)
        {
            string line=await ReadLine(stream,budget,ct);
            var parts=line.Split(' ',StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length<2 || parts[0] is not ("HTTP/1.0" or "HTTP/1.1") || !int.TryParse(parts[1],out int status) || status is <100 or >599)
                throw new IOException("The peer did not return a valid HTTP/1.x status line.");
            // Read complete headers; a truncated response must not pass the check.
            while((await ReadLine(stream,budget,ct)).Length>0){}
            if(status>=200)return status;
            if(status==101)throw new IOException("Unexpected HTTP protocol upgrade (101).");
        }
        throw new IOException("Too many informational HTTP responses.");
    }
    static async Task<string> ReadLine(Stream stream,int[] budget,CancellationToken ct)
    {
        var text=new StringBuilder();var buffer=new byte[1];
        while(budget[0]-->0)
        {
            if(await stream.ReadAsync(buffer,ct)==0)throw new IOException("The connection closed before the HTTP headers were complete.");
            if(buffer[0]==10)return text.ToString().TrimEnd('\r');
            if(text.Length>=8192)throw new IOException("HTTP header line exceeded 8 KiB.");
            text.Append((char)buffer[0]);
        }
        throw new IOException("HTTP headers exceeded 32 KiB.");
    }
    static async Task<CheckResult> Udp(MonitorCheck check,Stopwatch watch,CancellationToken ct)
    {
        var addresses=await Dns.GetHostAddressesAsync(check.Host,ct);
        if(addresses.Length==0)throw new SocketException((int)SocketError.HostNotFound);
        using var socket=new UdpClient(addresses[0].AddressFamily);socket.Connect(addresses[0],check.Port);
        byte[] payload;
        if(check.UdpMode=="DNS")
        {
            // A standard root NS query. A matching DNS response proves the UDP service answered.
            payload=new byte[] {0,0,1,0,0,1,0,0,0,0,0,0,0,0,2,0,1};RandomNumberGenerator.Fill(payload.AsSpan(0,2));
        }
        else payload=check.HexPayload?Hex(check.Payload):Encoding.UTF8.GetBytes(check.Payload);
        await socket.SendAsync(payload,ct);
        var expected=string.IsNullOrWhiteSpace(check.ExpectedHex)?Array.Empty<byte>():Hex(check.ExpectedHex);
        while(true)
        {
            var response=await socket.ReceiveAsync(ct);
            if(check.UdpMode=="DNS" && (response.Buffer.Length<12 || response.Buffer[0]!=payload[0] || response.Buffer[1]!=payload[1] || (response.Buffer[2]&128)==0))continue;
            if(expected.Length>0 && !response.Buffer.AsSpan().StartsWith(expected))continue;
            if(response.Buffer.Length==0)continue;
            return new(Health.Healthy,$"UDP response received ({response.Buffer.Length} bytes, {check.UdpMode} probe)",DateTimeOffset.UtcNow,watch.ElapsedMilliseconds);
        }
    }
}
