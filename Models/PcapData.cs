namespace QuickLook.Plugin.PcapViewer.Models;

using System;
// using System.Net;

internal enum TransportProtocol { TCP, UDP, ICMP }

internal sealed class PacketRecord
{
    public DateTime Timestamp { get; set; }
    public byte[] Data { get; set; }
    public int OriginalLength { get; set; }
    public bool IsFromClientToServer { get; set; }
}
