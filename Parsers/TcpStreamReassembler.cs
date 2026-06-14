namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Collections.Generic;
using System.Net;
using QuickLook.Plugin.PcapViewer.Models;

internal static class TcpStreamReassembler
{
    private const int MaxSessionBytes = 1_000_000;

    public static ReassemblyResult ReassembleStreams(List<PacketRecord> tcpPackets,
        IPAddress clientIP, int clientPort, IPAddress serverIP, int serverPort)
    {
        var clientSegments = new List<Segment>();
        var serverSegments = new List<Segment>();

        var ethOff = 0;

        foreach (var pkt in tcpPackets)
        {
            var etherType = PacketHeaderParser.ParseEthernet(pkt.Data, out ethOff);
            if (etherType == 0) continue;

            var protocol = PacketHeaderParser.ParseIPv4(pkt.Data, ethOff,
                out _, out _, out _, out _, out var l4Offset);
            if (protocol != PacketHeaderParser.TcpProtocol) continue;

            PacketHeaderParser.ParseTcp(pkt.Data, l4Offset,
                out _, out _, out var seqNum, out _, out _, out var tcpDataOff, out var dataLen);

            if (tcpDataOff == 0 || dataLen == 0) continue;

            var payload = new byte[dataLen];
            Buffer.BlockCopy(pkt.Data, l4Offset + tcpDataOff, payload, 0, dataLen);

            if (pkt.IsFromClientToServer)
                clientSegments.Add(new Segment { Seq = seqNum, Data = payload });
            else
                serverSegments.Add(new Segment { Seq = seqNum, Data = payload });
        }

        clientSegments.Sort((a, b) => a.Seq.CompareTo(b.Seq));
        serverSegments.Sort((a, b) => a.Seq.CompareTo(b.Seq));

        var clientResult = MergePayloads(clientSegments);
        var serverResult = MergePayloads(serverSegments);

        return new ReassemblyResult
        {
            ClientData = clientResult.Data,
            ServerData = serverResult.Data,
            IsTruncated = clientResult.IsTruncated || serverResult.IsTruncated,
        };
    }

    private static MergeResult MergePayloads(List<Segment> segments)
    {
        if (segments.Count == 0)
            return new MergeResult { Data = Array.Empty<byte>(), IsTruncated = false };

        var deduped = new List<Segment>();
        var seenSeqs = new HashSet<uint>();
        foreach (var seg in segments)
        {
            if (seenSeqs.Add(seg.Seq))
                deduped.Add(seg);
        }

        if (deduped.Count == 0)
            return new MergeResult { Data = Array.Empty<byte>(), IsTruncated = false };

        long totalSize = 0;
        foreach (var seg in deduped)
            totalSize += seg.Data.Length;

        if (totalSize > MaxSessionBytes)
        {
            var result = new List<byte>();
            bool truncated = false;
            foreach (var seg in deduped)
            {
                if (result.Count + seg.Data.Length > MaxSessionBytes)
                {
                    var remaining = MaxSessionBytes - result.Count;
                    if (remaining > 0)
                    {
                        var part = new byte[remaining];
                        Buffer.BlockCopy(seg.Data, 0, part, 0, remaining);
                        result.AddRange(part);
                    }
                    truncated = true;
                    break;
                }
                result.AddRange(seg.Data);
            }
            return new MergeResult { Data = result.ToArray(), IsTruncated = truncated };
        }

        var merged = new List<byte>();
        foreach (var seg in deduped)
            merged.AddRange(seg.Data);

        return new MergeResult { Data = merged.ToArray(), IsTruncated = false };
    }

    internal sealed class Segment
    {
        public uint Seq;
        public byte[] Data;
    }

    internal sealed class MergeResult
    {
        public byte[] Data;
        public bool IsTruncated;
    }
}

internal sealed class ReassemblyResult
{
    public byte[] ClientData { get; set; } = Array.Empty<byte>();
    public byte[] ServerData { get; set; } = Array.Empty<byte>();
    public bool IsTruncated { get; set; }
}