namespace ServerMonitor;
public sealed class MonitorEngine(Store store,bool service)
{
    readonly string owner=$"{(service?"Windows service":"Desktop")} · {Environment.ProcessId} · {Guid.NewGuid():N}";
    public async Task Run(CancellationToken ct)
    {
        while(!ct.IsCancellationRequested)
        {
            try
            {
                if(!service && ServiceManager.IsRunning()) {await Task.Delay(2000,ct);continue;}
                if(!store.Lease(owner)) {await Task.Delay(2000,ct);continue;}
                using var session=CancellationTokenSource.CreateLinkedTokenSource(ct);
                var renew=Renew(session);
                try
                {
                    while(!session.IsCancellationRequested)
                    {
                        if(!service && ServiceManager.IsRunning())break;
                        if(!store.Lease(owner)){session.Cancel();break;}
                        var due=store.Checks().Where(c=>c.Enabled && (!c.LastChecked.HasValue || DateTimeOffset.UtcNow-c.LastChecked>=TimeSpan.FromSeconds(c.IntervalSeconds))).ToArray();
                        await Parallel.ForEachAsync(due,new ParallelOptions {MaxDegreeOfParallelism=8,CancellationToken=session.Token},async(check,token)=>await Check(check,token));
                        await Task.Delay(1000,session.Token);
                    }
                }
                finally {session.Cancel();try{await renew;}catch(OperationCanceledException){}store.Release(owner);}
            }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            catch(Exception ex)
            {
                try{store.Event("Monitor","Engine error",ex.Message,true);}catch{System.Diagnostics.Trace.WriteLine(ex);}
                try{await Task.Delay(5000,ct);}catch(OperationCanceledException){break;}
            }
        }
    }
    async Task Renew(CancellationTokenSource session)
    {
        try{while(!session.IsCancellationRequested){await Task.Delay(10000,session.Token);if(!store.Lease(owner)){session.Cancel();return;}}}
        catch(OperationCanceledException) when(session.IsCancellationRequested){}
        catch{session.Cancel();}
    }
    async Task Check(MonitorCheck check,CancellationToken ct)
    {
        var result=await Probes.Run(check,ct);ct.ThrowIfCancellationRequested();
        if(store.LeaseOwner()!=owner || !store.Result(check,result))return;
        var smtp=store.Settings();
        if(!Alerts.ShouldSend(check,result,smtp,DateTimeOffset.UtcNow)||!store.Current(check))return;
        var subject=$"[Server Monitor] {result.Status}: {check.Name}";
        var target=check.Kind==CheckKind.PrivateCertificate?"Private certificate (manual expiration)":$"{check.Kind} check: {check.Host}:{check.Port}";
        var body=$"{check.Name}\r\n{target}\r\nStatus: {result.Status}\r\n{result.Detail}\r\nChecked: {result.CheckedAt:O}\r\nMonitor computer: {Environment.MachineName}\r\n\r\nUDP 'NoResponse' means the probe received no valid reply; it does not prove the host is offline.";
        try {await Alerts.Send(smtp,subject,body,ct);store.AlertAttempt(check,true,result.Status.ToString());store.Event(check.Name,"Email sent",subject);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
        catch(Exception ex){store.AlertAttempt(check,false,result.Status.ToString());store.Event(check.Name,"Email failed",$"{ex.GetType().Name}: {ex.Message}",true);}
    }
}
