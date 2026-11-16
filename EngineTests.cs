using System.Collections.Concurrent;

namespace ServerMonitor;
internal static class EngineTests
{
    static async Task Until(Func<bool> condition)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while(!condition())await Task.Delay(40,deadline.Token);
    }
    static TaskCompletionSource Gate()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    static CheckResult Result(Health health=Health.Healthy)=>new(health,"Simulated result",DateTimeOffset.UtcNow,1);
    public static async Task Run(string folder,Action<bool,string> assert)
    {
        var store=new Store(Path.Combine(folder,"engine.db"));store.Initialize();
        assert(store.Monitoring() is {ConcurrentChecks:16,SeparateAlerts:true,IndependentScheduling:true,ConcurrentEmails:2,DefaultTimeoutSeconds:5,DefaultWindowsTimeoutSeconds:30},"Recommended monitoring defaults apply to existing databases");
        store.SaveSettings(new(){Host="preserved relay"});
        store.SaveMonitoring(new(){ConcurrentChecks=2,DefaultTimeoutSeconds=4});
        assert(new Store(store.PathName).Monitoring() is {ConcurrentChecks:2,DefaultTimeoutSeconds:4} && store.Settings().Host=="preserved relay","Monitoring settings persist separately from SMTP settings");
        store.SaveMonitoring(new(){ConcurrentChecks=999,ConcurrentEmails=0,EmailTimeoutSeconds=-1});
        assert(store.Monitoring() is {ConcurrentChecks:64,ConcurrentEmails:1,EmailTimeoutSeconds:1},"Monitoring settings enforce safe bounds");
        store.SaveMonitoring(new(){ConcurrentChecks=2});
        foreach(var name in new[]{"Slow","Fast","Waiting"})store.Save(new(){Name=name,Host="test",IntervalSeconds=1});
        var slow=store.Checks().Single(c=>c.Name=="Slow").Id;
        var counts=new ConcurrentDictionary<long,int>();var active=new ConcurrentDictionary<long,int>();var overlap=0;var peak=0;var running=0;
        var release=Gate();
        async Task<CheckResult> Probe(MonitorCheck check,CancellationToken ct)
        {
            counts.AddOrUpdate(check.Id,1,(_,v)=>v+1);
            if(active.AddOrUpdate(check.Id,1,(_,v)=>v+1)>1)Interlocked.Exchange(ref overlap,1);
            var current=Interlocked.Increment(ref running);int previous;
            do{previous=peak;if(current<=previous)break;}while(Interlocked.CompareExchange(ref peak,current,previous)!=previous);
            try{if(check.Id==slow)await release.Task.WaitAsync(ct);else await Task.Delay(30,ct);return Result();}
            finally{active.AddOrUpdate(check.Id,0,(_,v)=>v-1);Interlocked.Decrement(ref running);}
        }
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(store,true,Probe).Run(cancel.Token);
            try
            {
                await Until(()=>counts.Count==3 && counts.Where(p=>p.Key!=slow).Any(p=>p.Value>=2));
                assert(!release.Task.IsCompleted && overlap==0 && peak==2,"Due checks repeat while another probe is blocked, with bounded concurrency and no self-overlap");
                store.SaveMonitoring(store.Monitoring() with{ConcurrentChecks=1});
                release.TrySetResult();await Until(()=>Volatile.Read(ref running)==0);
            }
            finally{cancel.Cancel();release.TrySetResult();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        assert(store.LeaseOwner()=="No active worker" && running==0,"Shutdown drains probes before releasing the database lease");

        var alerts=new Store(Path.Combine(folder,"engine-alerts.db"));alerts.Initialize();
        alerts.SaveMonitoring(new(){ConcurrentChecks=1,ConcurrentEmails=1,EmailTimeoutSeconds=7});
        alerts.SaveSettings(new(){Enabled=true,Recovery=true});
        alerts.Save(new(){Name="Alert target",Host="test",IntervalSeconds=1});
        var sendStarted=Gate();var finishEmail=Gate();var subjects=new ConcurrentQueue<string>();int polls=0;int recovered=0;int emailCalls=0;int timeout=0;
        Task<CheckResult> AlertProbe(MonitorCheck c,CancellationToken ct){Interlocked.Increment(ref polls);return Task.FromResult(Result(Volatile.Read(ref recovered)==0?Health.Down:Health.Healthy));}
        async Task Sender(SmtpSettings s,string subject,string body,CancellationToken ct,int seconds)
        {
            Interlocked.Increment(ref emailCalls);timeout=seconds;subjects.Enqueue(subject);sendStarted.TrySetResult();await finishEmail.Task.WaitAsync(ct);
        }
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(alerts,true,AlertProbe,Sender).Run(cancel.Token);
            try
            {
                await sendStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));await Until(()=>Volatile.Read(ref polls)>=3);
                assert(emailCalls==1 && timeout==7,"Blocked email does not block polling, uses configured timeout, and is not duplicated");
                Interlocked.Exchange(ref recovered,1);alerts.RequestChecks();await Until(()=>alerts.Checks().Single().Status==Health.Healthy);
                finishEmail.TrySetResult();await Until(()=>subjects.Count==2 && alerts.Checks().Single().LastAlertStatus=="Healthy");
                assert(subjects.First().Contains("Down") && subjects.Last().Contains("Healthy"),"Recovery during email delivery is sent after the accepted failure alert");
            }
            finally{cancel.Cancel();finishEmail.TrySetResult();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        // A persisted failure must send after restart even when its next network poll is hours away.
        var target=alerts.Checks().Single();alerts.Result(target,Result(Health.Down));
        alerts.Save(target with{IntervalSeconds=86400});target=alerts.Checks().Single();alerts.Result(target,Result(Health.Down));
        using(var cancel=new CancellationTokenSource())
        {
            int unexpectedPolls=0;var delivered=Gate();
            var worker=new MonitorEngine(new Store(alerts.PathName),true,(c,ct)=>{Interlocked.Increment(ref unexpectedPolls);return Task.FromResult(Result());},
                (s,subject,body,ct,seconds)=>{delivered.TrySetResult();return Task.CompletedTask;}).Run(cancel.Token);
            try
            {
                await delivered.Task.WaitAsync(TimeSpan.FromSeconds(10));await Until(()=>alerts.Checks().Single().LastAlertStatus=="Down");
                assert(unexpectedPolls==0,"Pending persisted failure delivers after restart without waiting for another probe");
            }
            finally{cancel.Cancel();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        // Simulate 100 unreachable endpoints with a controlled delayed response, not external traffic.
        var load=new Store(Path.Combine(folder,"engine-load.db"));load.Initialize();
        for(int i=0;i<100;i++)load.Save(new(){Name=$"Host {i:000}",Host="test",IntervalSeconds=3600});
        int loadActive=0,loadPeak=0,finished=0;
        async Task<CheckResult> LoadProbe(MonitorCheck c,CancellationToken ct)
        {
            var current=Interlocked.Increment(ref loadActive);int previous;
            do{previous=loadPeak;if(current<=previous)break;}while(Interlocked.CompareExchange(ref loadPeak,current,previous)!=previous);
            try{await Task.Delay(150,ct);Interlocked.Increment(ref finished);return Result(Health.NoResponse);}
            finally{Interlocked.Decrement(ref loadActive);}
        }
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(load,true,LoadProbe).Run(cancel.Token);
            try{await Until(()=>load.Checks().Count(c=>c.Status==Health.NoResponse)==100);assert(finished==100 && loadPeak<=16 && loadPeak>1,"100 simulated unreachable checks complete within the configured concurrency limit");}
            finally{cancel.Cancel();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        var retry=new Store(Path.Combine(folder,"engine-retry.db"));retry.Initialize();retry.SaveSettings(new(){Enabled=true});
        retry.Save(new(){Name="Retry",Host="test",IntervalSeconds=86400});retry.Result(retry.Checks().Single(),Result(Health.Down));
        int attempts=0;
        Task FailedSend(SmtpSettings s,string subject,string body,CancellationToken ct,int seconds)
        {Interlocked.Increment(ref attempts);throw new IOException("Simulated unavailable relay");}
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(retry,true,send:FailedSend).Run(cancel.Token);
            try{await Until(()=>retry.Checks().Single().LastAttempt.HasValue);}
            finally{cancel.Cancel();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(retry,true,send:FailedSend).Run(cancel.Token);
            try{await Task.Delay(600);assert(attempts==1,"Failed email cooldown survives restart and prevents rapid retry loops");}
            finally{cancel.Cancel();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        using(var connection=retry.Open())
        using(var command=connection.CreateCommand())
        {
            command.CommandText="UPDATE Checks SET LastAttempt=$at";
            command.Parameters.AddWithValue("$at",DateTimeOffset.UtcNow.AddMinutes(-6).ToString("O"));command.ExecuteNonQuery();
        }
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(retry,true,send:FailedSend).Run(cancel.Token);
            try{await Until(()=>Volatile.Read(ref attempts)==2);assert(true,"Expired email retry is attempted without another network poll");}
            finally{cancel.Cancel();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        var modes=new Store(Path.Combine(folder,"engine-modes.db"));modes.Initialize();
        modes.SaveMonitoring(new(){ConcurrentChecks=2,IndependentScheduling=false,SeparateAlerts=false});
        foreach(var name in new[]{"First","Second","Third"})modes.Save(new(){Name=name,Host="test",IntervalSeconds=86400});
        var groupGate=Gate();var modeStarted=new ConcurrentDictionary<string,bool>();
        async Task<CheckResult> GroupProbe(MonitorCheck c,CancellationToken ct)
        {modeStarted[c.Name]=true;if(c.Name=="First")await groupGate.Task.WaitAsync(ct);return Result();}
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(modes,true,GroupProbe).Run(cancel.Token);
            try
            {
                await Until(()=>modeStarted.Count==2);await Task.Delay(400);
                assert(!modeStarted.ContainsKey("Third"),"Disabling independent scheduling waits for the running group");
                modes.SaveMonitoring(modes.Monitoring() with{IndependentScheduling=true,SeparateAlerts=true});
                groupGate.TrySetResult();await Until(()=>modeStarted.Count==3);
                assert(true,"Scheduling and alert mode settings change live after active work drains");
            }
            finally{cancel.Cancel();groupGate.TrySetResult();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        modes.SaveMonitoring(new(){ConcurrentChecks=1,SeparateAlerts=false});modes.SaveSettings(new(){Enabled=true});
        modes.RequestChecks();var inlineStarted=Gate();var inlineRelease=Gate();modeStarted.Clear();
        async Task InlineSend(SmtpSettings s,string subject,string body,CancellationToken ct,int seconds)
        {inlineStarted.TrySetResult();await inlineRelease.Task.WaitAsync(ct);}
        using(var cancel=new CancellationTokenSource())
        {
            var worker=new MonitorEngine(modes,true,(c,ct)=>{modeStarted[c.Name]=true;return Task.FromResult(Result(Health.Down));},InlineSend).Run(cancel.Token);
            try
            {
                await inlineStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));await Task.Delay(400);
                assert(modeStarted.Count==1,"Disabling the separate email queue keeps delivery within the polling slot");
            }
            finally{cancel.Cancel();inlineRelease.TrySetResult();await worker.WaitAsync(TimeSpan.FromSeconds(10));}
        }
        RenderSettings(load,assert);
    }
    static void RenderSettings(Store store,Action<bool,string> assert)
    {
        Exception? failure=null;
        var thread=new Thread(()=>{
            try
            {
                Application.SetHighDpiMode(HighDpiMode.SystemAware);Application.EnableVisualStyles();
                using var form=new Form{ClientSize=new(1100,790),Font=new("Segoe UI",10),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new(-32000,-32000)};
                using var panel=new MonitoringPanel(store);form.Controls.Add(panel);form.Show();form.PerformLayout();panel.PerformLayout();
                using var bitmap=new Bitmap(panel.Width,panel.Height);panel.DrawToBitmap(bitmap,panel.ClientRectangle);
                bitmap.Save(Path.Combine(AppContext.BaseDirectory,"ServerMonitor-settings-preview.png"));
            }
            catch(Exception ex){failure=ex;}
        });
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure!=null)throw failure;assert(true,"Monitoring settings panel renders successfully");
    }
}
