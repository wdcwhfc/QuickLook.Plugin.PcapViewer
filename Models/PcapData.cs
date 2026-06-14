namespace QuickLook.Plugin.PcapViewer.Models;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

internal enum TransportProtocol { TCP, UDP, ICMP }

internal sealed class SessionInfo
{
    public TransportProtocol Protocol { get; set; }
    public IPAddress SourceIP { get; set; }
    public IPAddress DestIP { get; set; }
    public int SourcePort { get; set; }
    public int DestPort { get; set; }
    public bool IsHandshakeComplete { get; set; }
    public bool IsFromClientToServer { get; set; } // true if source is the client/initiator
}

internal sealed class PacketRecord
{
    public DateTime Timestamp { get; set; }
    public byte[] Data { get; set; }
    public int OriginalLength { get; set; }
    public bool IsFromClientToServer { get; set; }
}

internal sealed class TcpSession
{
    public SessionInfo Info { get; set; }
    public List<PacketRecord> ClientPackets { get; set; } = new();
    public List<PacketRecord> ServerPackets { get; set; } = new();
    public byte[] ClientPayload { get; set; } = Array.Empty<byte>();
    public byte[] ServerPayload { get; set; } = Array.Empty<byte>();
    public bool IsTruncated { get; set; }
}

internal sealed class UdpSession
{
    public SessionInfo Info { get; set; }
    public List<PacketRecord> ClientPackets { get; set; } = new();
    public List<PacketRecord> ServerPackets { get; set; } = new();
    public byte[] ClientPayload { get; set; } = Array.Empty<byte>();
    public byte[] ServerPayload { get; set; } = Array.Empty<byte>();
    public bool IsTruncated { get; set; }
}

internal sealed class IcmpMessage
{
    public byte Type { get; set; }
    public byte Code { get; set; }
    public byte[] Payload { get; set; }
    public DateTime Timestamp { get; set; }
}

internal sealed class IcmpSession
{
    public IPAddress SourceIP { get; set; }
    public IPAddress DestIP { get; set; }
    public List<IcmpMessage> Messages { get; set; } = new();
    public bool IsFromClientToServer { get; set; }
}