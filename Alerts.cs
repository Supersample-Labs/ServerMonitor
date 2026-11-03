using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using MailKit.Security;
using MimeKit;

namespace ServerMonitor;
public static class Secret
{
    [StructLayout(LayoutKind.Sequential)] struct Blob {public int Size;public IntPtr Data;}
    [DllImport("crypt32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CryptProtectData(ref Blob input,string description,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);
    [DllImport("crypt32.dll",SetLastError=true)] static extern bool CryptUnprotectData(ref Blob input,IntPtr description,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    static byte[] Transform(byte[] bytes,bool protect)
    {
        var input=new Blob {Size=bytes.Length,Data=Marshal.AllocHGlobal(bytes.Length)};Blob output=default;
        try {Marshal.Copy(bytes,0,input.Data,bytes.Length);var ok=protect?CryptProtectData(ref input,"Server Monitor SMTP",IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,5,out output):CryptUnprotectData(ref input,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output);if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());var result=new byte[output.Size];Marshal.Copy(output.Data,result,0,result.Length);return result;}
        finally {for(int i=0;i<bytes.Length;i++)Marshal.WriteByte(input.Data,i,0);Marshal.FreeHGlobal(input.Data);if(output.Data!=IntPtr.Zero)LocalFree(output.Data);}
    }
    public static string Protect(string value)=>string.IsNullOrEmpty(value)?"":Convert.ToBase64String(Transform(Encoding.UTF8.GetBytes(value),true));
    public static string Unprotect(string value)=>string.IsNullOrEmpty(value)?"":Encoding.UTF8.GetString(Transform(Convert.FromBase64String(value),false));
}
public static class Alerts
{
    public static void Validate(SmtpSettings s)
    {
        if(string.IsNullOrWhiteSpace(s.Host)||s.Host.Any(char.IsWhiteSpace)||s.Host.Contains("://"))throw new ArgumentException("Enter the SMTP relay hostname, without a URL or port.");
        if(s.Port is <1 or >65535)throw new ArgumentException("SMTP port must be 1–65535.");
        _=MailboxAddress.Parse(s.From);if(Recipients(s).Count==0)throw new ArgumentException("Enter at least one recipient.");
        if(!new[]{"StartTls","SslOnConnect","None"}.Contains(s.Security))throw new ArgumentException("Select an SMTP encryption mode.");
    }
    static List<MailboxAddress> Recipients(SmtpSettings s)=>s.Recipients.Split([';',','],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Select(MailboxAddress.Parse).ToList();
    public static async Task Send(SmtpSettings s,string subject,string body,CancellationToken ct)
    {
        Validate(s);using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var msg=new MimeMessage();msg.From.Add(MailboxAddress.Parse(s.From));foreach(var recipient in Recipients(s))msg.To.Add(recipient);
        msg.Subject=subject;msg.Body=new TextPart("plain") {Text=body};
        using var client=new MailKit.Net.Smtp.SmtpClient {Timeout=30000};
        var options=s.Security switch {"SslOnConnect"=>SecureSocketOptions.SslOnConnect,"None"=>SecureSocketOptions.None,_=>SecureSocketOptions.StartTls};
        await client.ConnectAsync(s.Host,s.Port,options,deadline.Token);
        if(!string.IsNullOrWhiteSpace(s.Username))await client.AuthenticateAsync(s.Username,Secret.Unprotect(s.ProtectedPassword),deadline.Token);
        await client.SendAsync(msg,deadline.Token);await client.DisconnectAsync(true,deadline.Token);
    }
    public static bool ShouldSend(MonitorCheck c,CheckResult r,SmtpSettings s,DateTimeOffset now)
    {
        if(!s.Enabled)return false;
        // Failed deliveries retry after five minutes. Successful deliveries do not delay transitions.
        if(c.LastAttempt.HasValue && (!c.LastAlert.HasValue || c.LastAttempt>c.LastAlert) && now-c.LastAttempt<TimeSpan.FromMinutes(5))return false;
        if(!r.Problem)return s.Recovery && c.LastAlertStatus!="" && c.LastAlertStatus!=Health.Healthy.ToString();
        return c.LastAlertStatus!=r.Status.ToString() || !c.LastAlert.HasValue || now-c.LastAlert>=TimeSpan.FromHours(s.ReminderHours);
    }
}
