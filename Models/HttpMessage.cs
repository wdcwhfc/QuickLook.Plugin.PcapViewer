namespace QuickLook.Plugin.PcapViewer.Models;

using System.Collections.Generic;

internal sealed class HttpMessage
{
    public bool IsRequest { get; set; }
    public string Method { get; set; }
    public string Uri { get; set; }
    public string Version { get; set; }
    public int StatusCode { get; set; }
    public string ReasonPhrase { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
    public byte[] Body { get; set; } = System.Array.Empty<byte>();
    public bool IsTruncated { get; set; }

    public override string ToString()
    {
        if (IsRequest)
            return $"{Method} {Uri} {Version}";
        return $"{Version} {StatusCode} {ReasonPhrase}";
    }
}