using QuickLook.Common.Plugin;
using System.IO;
using System.Windows;
using QuickLook.Plugin.PcapViewer.UI;

namespace QuickLook.Plugin.PcapViewer;

public sealed class Plugin : IViewer
{
    private PcapViewerControl _control;

    public int Priority => 0;

    public void Init()
    {
    }

    public bool CanHandle(string path)
    {
        if (Directory.Exists(path))
            return false;

        var ext = Path.GetExtension(path);
        return !string.IsNullOrEmpty(ext) &&
               ext.Equals(".pcap", System.StringComparison.OrdinalIgnoreCase);
    }

    public void Prepare(string path, ContextObject context)
    {
        context.PreferredSize = new Size { Width = 1000, Height = 750 };
    }

    public void View(string path, ContextObject context)
    {
        context.IsBusy = true;

        _control = new PcapViewerControl();
        _control.LoadFile(path);

        context.ViewerContent = _control;
        context.Title = Path.GetFileName(path);
        context.IsBusy = false;
    }

    public void Cleanup()
    {
        _control?.Dispose();
        _control = null;
    }
}