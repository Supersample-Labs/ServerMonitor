using Microsoft.Win32;
namespace ServerMonitor;
public static class AppIcons
{
    public static Icon Application { get; } = Load("Black",new Size(32,32));
    static readonly Icon blackTray=Load("Black",SystemInformation.SmallIconSize);
    static readonly Icon whiteTray=Load("White",SystemInformation.SmallIconSize);
    public static Icon Tray
    {
        get
        {
            try
            {
                using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                return key?.GetValue("SystemUsesLightTheme") is int light && light==0?whiteTray:blackTray;
            }
            catch{return blackTray;}
        }
    }
    static Icon Load(string variant,Size size)
    {
        using var stream=typeof(AppIcons).Assembly.GetManifestResourceStream($"ServerMonitor.Assets.MonitorPulse-{variant}.ico")
            ??throw new InvalidOperationException("Application icon resource is missing.");
        using var source=new Icon(stream,size);
        return (Icon)source.Clone();
    }
}
