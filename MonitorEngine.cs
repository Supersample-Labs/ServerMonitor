namespace ServerMonitor;
public sealed class MonitorEngine(Store store,bool service,
    Func<MonitorCheck,CancellationToken,Task<CheckResult>>? probe=null,
    Func<SmtpSettings,string,string,CancellationToken,int,Task>? send=null)
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
                var checks=new Dictionary<long,Task>();var emails=new Dictionary<long,Task>();
                var applied=store.Monitoring();
                try
                {
                    while(!session.IsCancellationRequested)
                    {
                        if(!service && ServiceManager.IsRunning())break;
                        if(!store.Lease(owner)){session.Cancel();break;}
                        foreach(var id in checks.Where(p=>p.Value.IsCompleted).Select(p=>p.Key).ToArray()){await checks[id];checks.Remove(id);}
                        foreach(var id in emails.Where(p=>p.Value.IsCompleted).Select(p=>p.Key).ToArray()){await emails[id];emails.Remove(id);}
                        var settings=store.Monitoring();var snapshot=store.Checks();var smtp=store.Settings();var now=DateTimeOffset.UtcNow;
                        if((settings.SeparateAlerts!=applied.SeparateAlerts || settings.IndependentScheduling!=applied.IndependentScheduling) && checks.Count+emails.Count>0)
                        {
                            await Task.WhenAny(checks.Values.Concat(emails.Values).Append(Task.Delay(250,session.Token)));
                            continue;
                        }
                        applied=settings;
                        // Oldest completed checks go first. Never overlap a monitor with itself.
                        if(settings.IndependentScheduling || checks.Count==0)
                        {
                            foreach(var check in snapshot.Where(c=>c.Enabled && !checks.ContainsKey(c.Id) &&
                                (settings.SeparateAlerts || !emails.ContainsKey(c.Id)) &&
                                (!c.LastChecked.HasValue || now-c.LastChecked>=TimeSpan.FromSeconds(c.IntervalSeconds)))
                                .OrderBy(c=>c.LastChecked).ThenBy(c=>c.Id).Take(Math.Max(0,settings.ConcurrentChecks-checks.Count)))
                                checks.Add(check.Id,Task.Run(()=>Guard(()=>Check(check,settings,session.Token),session.Token)));
                        }
                        // Persisted results form a bounded, latest-state alert queue: one pending status per monitor.
                        // Reading fresh delivery state also preserves suppression/retry behavior across restarts.
                        if(settings.SeparateAlerts)
                        {
                            foreach(var check in snapshot.Where(c=>c.Enabled && c.LastChecked.HasValue && !emails.ContainsKey(c.Id))
                                .OrderBy(c=>c.LastAttempt).ThenBy(c=>c.LastChecked).ThenBy(c=>c.Id))
                            {
                                if(emails.Count>=settings.ConcurrentEmails)break;
                                var result=StoredResult(check);
                                if(Alerts.ShouldSend(check,result,smtp,now))
                                    emails.Add(check.Id,Task.Run(()=>Guard(()=>Send(check,result,settings,session.Token),session.Token)));
                            }
                        }
                        var active=checks.Values.Concat(emails.Values).ToArray();
                        await Task.WhenAny(active.Append(Task.Delay(250,session.Token)));
                        session.Token.ThrowIfCancellationRequested();
                    }
                }
                finally
                {
                    session.Cancel();
                    try{await Task.WhenAll(checks.Values.Concat(emails.Values).Append(renew));}
                    catch(OperationCanceledException) when(session.IsCancellationRequested){}
                    finally{store.Release(owner);}
                }
            }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            catch(Exception ex)
            {
                LogError(ex);
                try{await Task.Delay(5000,ct);}catch(OperationCanceledException){break;}
            }
        }
    }
    static CheckResult StoredResult(MonitorCheck check)=>new(check.Status,check.Detail,check.LastChecked!.Value,check.LatencyMs,check.Expires);
    async Task Guard(Func<Task> action,CancellationToken ct)
    {
        try{await action();}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception ex){LogError(ex);await Task.Delay(1000,ct);}
    }
    void LogError(Exception ex)
    {
        try{store.Event("Monitor","Engine error",ex.Message,true);}catch{System.Diagnostics.Trace.WriteLine(ex);}
    }
    async Task Renew(CancellationTokenSource session)
    {
        try{while(!session.IsCancellationRequested){await Task.Delay(10000,session.Token);if(!store.Lease(owner)){session.Cancel();return;}}}
        catch(OperationCanceledException) when(session.IsCancellationRequested){}
        catch{session.Cancel();}
    }
    async Task Check(MonitorCheck check,MonitoringSettings settings,CancellationToken ct)
    {
        var result=await (probe??Probes.Run)(check,ct);ct.ThrowIfCancellationRequested();
        if(store.LeaseOwner()!=owner || !store.Result(check,result))return;
        if(!settings.SeparateAlerts)
        {
            var current=store.Checks().FirstOrDefault(c=>c.Id==check.Id && c.Revision==check.Revision && c.Enabled);
            if(current!=null)await Send(current,result,settings,ct);
        }
    }
    async Task Send(MonitorCheck check,CheckResult result,MonitoringSettings settings,CancellationToken ct)
    {
        // Refresh before sending: do not send an obsolete queued status after recovery, edit, or removal.
        var current=store.Checks().FirstOrDefault(c=>c.Id==check.Id && c.Revision==check.Revision && c.Enabled);
        if(current==null || !current.LastChecked.HasValue || current.Status!=result.Status || store.LeaseOwner()!=owner)return;
        result=StoredResult(current);check=current;
        var smtp=store.Settings();
        if(!Alerts.ShouldSend(check,result,smtp,DateTimeOffset.UtcNow))return;
        var subject=$"[Server Monitor] {result.Status}: {check.Name}";
        var target=check.Kind==CheckKind.PrivateCertificate?"Private certificate (manual expiration)":$"{check.Kind} check: {check.Host}:{check.Port}";
        var body=$"{check.Name}\r\n{target}\r\nStatus: {result.Status}\r\n{result.Detail}\r\nChecked: {result.CheckedAt:O}\r\nMonitor computer: {Environment.MachineName}\r\n\r\nUDP 'NoResponse' means the probe received no valid reply; it does not prove the host is offline.";
        try
        {
            await (send??Alerts.Send)(smtp,subject,body,ct,settings.EmailTimeoutSeconds);
            store.AlertAttempt(check,true,result.Status.ToString());store.Event(check.Name,"Email sent",subject);
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
        catch(Exception ex){store.AlertAttempt(check,false,result.Status.ToString());store.Event(check.Name,"Email failed",$"{ex.GetType().Name}: {ex.Message}",true);}
    }
}
