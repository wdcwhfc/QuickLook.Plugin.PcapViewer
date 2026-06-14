namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using QuickLook.Plugin.PcapViewer.Models;

internal sealed class SessionIdentifier
{
    private class TcpConnTracker
    {
        public IPAddress SrcIP, DstIP;
        public int SrcPort, DstPort;
        public bool SeenSyn;
        public bool SeenSynAck;
        public bool SeenAck;
        public bool HasPayload;
        public int FirstPayloadPacketIndex = -1;
        public int FirstSynPacketIndex = -1;
    }

    public static IdentifyResult Identify(PcapReader reader)
    {
        var packets = new List<PacketRecord>();
        var tcpTrackers = new List<TcpConnTracker>();

        int firstUdpPacketIndex = -1;
        int firstIcmpPacketIndex = -1;
        int firstUdpClientPort = 0, firstUdpServerPort = 0;
        IPAddress firstUdpSrc = null, firstUdpDst = null;
        IPAddress firstIcmpSrc = null, firstIcmpDst = null;

        int index = 0;
        foreach (var rawPacket in reader.ReadPackets())
        {
            var etherType = PacketHeaderParser.ParseEthernet(rawPacket.Data, out var ethPayloadOffset);
            if (etherType == 0) { index++; continue; }

            var ipPayloadOffset = ethPayloadOffset;
            var protocol = ParseL3(rawPacket.Data, ref ipPayloadOffset);
            if (protocol == 0) { index++; continue; }

            if (protocol == PacketHeaderParser.TcpProtocol)
            {
                PacketHeaderParser.ParseTcp(rawPacket.Data, ipPayloadOffset,
                    out var srcPort, out var dstPort, out var seqNum, out var ackNum, out var flags,
                    out var dataOffset, out var dataLen);
                if (dataOffset == 0) { index++; continue; }

                ExtractIPs(rawPacket.Data, ethPayloadOffset, out var srcIP, out var dstIP);
                if (srcIP == null) { index++; continue; }

                var tracker = FindOrCreateTcpTracker(tcpTrackers, srcIP, dstIP, srcPort, dstPort, flags, ref index);

                if (tracker != null)
                {
                    rawPacket.IsFromClientToServer = srcIP.Equals(tracker.SrcIP);

                    if ((flags & PacketHeaderParser.TcpSyn) != 0 && (flags & PacketHeaderParser.TcpAck) == 0)
                    {
                        tracker.SeenSyn = true;
                        if (tracker.FirstSynPacketIndex < 0)
                            tracker.FirstSynPacketIndex = index;
                    }
                    else if ((flags & PacketHeaderParser.TcpSyn) != 0 && (flags & PacketHeaderParser.TcpAck) != 0)
                    {
                        tracker.SeenSynAck = true;
                    }
                    else if ((flags & PacketHeaderParser.TcpAck) != 0 && tracker.SeenSyn && tracker.SeenSynAck)
                    {
                        tracker.SeenAck = true;
                    }

                    if ((flags & PacketHeaderParser.TcpPsh) != 0 || dataLen > 0)
                    {
                        tracker.HasPayload = true;
                        if (tracker.FirstPayloadPacketIndex < 0)
                            tracker.FirstPayloadPacketIndex = index;
                    }

                    packets.Add(rawPacket);
                }
            }
            else if (protocol == PacketHeaderParser.UdpProtocol)
            {
                PacketHeaderParser.ParseUdp(rawPacket.Data, ipPayloadOffset,
                    out var srcPort, out var dstPort, out var length);

                if (length > 8)
                {
                    if (firstUdpPacketIndex < 0)
                    {
                        firstUdpPacketIndex = index;
                        ExtractIPs(rawPacket.Data, ethPayloadOffset, out firstUdpSrc, out firstUdpDst);
                        firstUdpClientPort = srcPort;
                        firstUdpServerPort = dstPort;
                        rawPacket.IsFromClientToServer = true;
                    }
                    else
                    {
                        ExtractIPs(rawPacket.Data, ethPayloadOffset, out var src, out var dst);
                        if (src != null && dst != null && ((src.Equals(firstUdpSrc) && dst.Equals(firstUdpDst)) || (src.Equals(firstUdpDst) && dst.Equals(firstUdpSrc))))
                        {
                            rawPacket.IsFromClientToServer = src.Equals(firstUdpSrc);
                        }
                        else
                        {
                            index++; continue;
                        }
                    }
                    packets.Add(rawPacket);
                }
            }
            else if (protocol == PacketHeaderParser.IcmpProtocol)
            {
                PacketHeaderParser.ParseIcmp(rawPacket.Data, ipPayloadOffset,
                    out var icmpType, out var icmpCode, out _);

                if (firstIcmpPacketIndex < 0)
                {
                    firstIcmpPacketIndex = index;
                    ExtractIPs(rawPacket.Data, ethPayloadOffset, out firstIcmpSrc, out firstIcmpDst);
                    rawPacket.IsFromClientToServer = true;
                    packets.Add(rawPacket);
                }
                else
                {
                    ExtractIPs(rawPacket.Data, ethPayloadOffset, out var src, out var dst);
                    if (src != null && dst != null &&
                        ((src.Equals(firstIcmpSrc) && dst.Equals(firstIcmpDst)) ||
                         (src.Equals(firstIcmpDst) && dst.Equals(firstIcmpSrc))))
                    {
                        rawPacket.IsFromClientToServer = src.Equals(firstIcmpSrc);
                        packets.Add(rawPacket);
                    }
                }
            }

            index++;
        }

        // Determine which session to use
        var completedTcp = tcpTrackers
            .Where(t => t.SeenSyn && t.SeenSynAck && t.SeenAck && t.HasPayload)
            .OrderBy(t => t.FirstPayloadPacketIndex)
            .FirstOrDefault();

        if (completedTcp != null)
        {
            var sessionPackets = packets
                .Where(p =>
                {
                    var ethType = PacketHeaderParser.ParseEthernet(p.Data, out var eOff);
                    if (ethType == 0) return false;
                    var proto = PacketHeaderParser.ParseIPv4(p.Data, eOff,
                        out var srcIP, out var dstIP, out _, out _, out var l4Offset);
                    if (proto != PacketHeaderParser.TcpProtocol || srcIP == null) return false;
                    PacketHeaderParser.ParseTcp(p.Data, l4Offset,
                        out var sp, out var dp, out _, out _, out _, out _, out _);

                    bool forward = srcIP.Equals(completedTcp.SrcIP) && dstIP.Equals(completedTcp.DstIP) &&
                                   sp == completedTcp.SrcPort && dp == completedTcp.DstPort;
                    bool reverse = srcIP.Equals(completedTcp.DstIP) && dstIP.Equals(completedTcp.SrcIP) &&
                                   sp == completedTcp.DstPort && dp == completedTcp.SrcPort;
                    return forward || reverse;
                }).ToList();

            foreach (var p in sessionPackets)
            {
                PacketHeaderParser.ParseEthernet(p.Data, out var eOff);
                ExtractIPs(p.Data, eOff, out var srcIP, out _);
                p.IsFromClientToServer = srcIP != null && srcIP.Equals(completedTcp.SrcIP);
            }

            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Tcp,
                TcpPackets = sessionPackets,
                TcpSrcIP = completedTcp.SrcIP,
                TcpDstIP = completedTcp.DstIP,
                TcpSrcPort = completedTcp.SrcPort,
                TcpDstPort = completedTcp.DstPort,
            };
        }

        if (firstUdpPacketIndex >= 0)
        {
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Udp,
                TcpPackets = packets.Where(p => true).ToList(),
                UdpSrcIP = firstUdpSrc,
                UdpDstIP = firstUdpDst,
                UdpSrcPort = firstUdpClientPort,
                UdpDstPort = firstUdpServerPort,
            };
        }

        if (firstIcmpPacketIndex >= 0)
        {
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Icmp,
                TcpPackets = packets,
                IcmpSrcIP = firstIcmpSrc,
                IcmpDstIP = firstIcmpDst,
            };
        }

        return new IdentifyResult { Type = IdentifyResult.ResultType.None };
    }

    private static TcpConnTracker FindOrCreateTcpTracker(List<TcpConnTracker> trackers,
        IPAddress srcIP, IPAddress dstIP, int srcPort, int dstPort, byte flags, ref int index)
    {
        foreach (var t in trackers)
        {
            bool forward = srcIP.Equals(t.SrcIP) && dstIP.Equals(t.DstIP) &&
                           srcPort == t.SrcPort && dstPort == t.DstPort;
            bool reverse = srcIP.Equals(t.DstIP) && dstIP.Equals(t.SrcIP) &&
                           srcPort == t.DstPort && dstPort == t.SrcPort;
            if (forward || reverse)
                return t;
        }

        if ((flags & PacketHeaderParser.TcpSyn) != 0 && (flags & PacketHeaderParser.TcpAck) == 0)
        {
            var t = new TcpConnTracker { SrcIP = srcIP, DstIP = dstIP, SrcPort = srcPort, DstPort = dstPort };
            trackers.Add(t);
            return t;
        }

        return null;
    }

    private static byte ParseL3(byte[] data, ref int ethPayloadOffset)
    {
        var etherType = PacketHeaderParser.ReadU16Big(data, ethPayloadOffset - 2);
        if (etherType == 0x0800)
        {
            var protocol = PacketHeaderParser.ParseIPv4(data, ethPayloadOffset,
                out _, out _, out _, out _, out var l4Offset);
            ethPayloadOffset = l4Offset;
            return protocol;
        }
        return 0;
    }

    private static void ExtractIPs(byte[] data, int ipOffset, out IPAddress src, out IPAddress dst)
    {
        src = null; dst = null;
        if (data.Length < ipOffset + PacketHeaderParser.Ipv4MinimumHeaderSize)
            return;
        PacketHeaderParser.ParseIPv4(data, ipOffset, out src, out dst, out _, out _, out _);
    }
}

internal sealed class IdentifyResult
{
    public enum ResultType { None, Tcp, Udp, Icmp }

    public ResultType Type { get; set; }
    public List<PacketRecord> TcpPackets { get; set; }
    public IPAddress TcpSrcIP { get; set; }
    public IPAddress TcpDstIP { get; set; }
    public int TcpSrcPort { get; set; }
    public int TcpDstPort { get; set; }
    public IPAddress UdpSrcIP { get; set; }
    public IPAddress UdpDstIP { get; set; }
    public int UdpSrcPort { get; set; }
    public int UdpDstPort { get; set; }
    public IPAddress IcmpSrcIP { get; set; }
    public IPAddress IcmpDstIP { get; set; }

    public bool HasSession => Type != ResultType.None;
}
