namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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

    private class UdpTracker
    {
        public IPAddress SrcIP, DstIP;
        public int SrcPort, DstPort;
        public int FirstPacketIndex = -1;
    }

    private class IcmpTracker
    {
        public IPAddress SrcIP, DstIP;
        public int FirstPacketIndex = -1;
    }

    public static IdentifyResult Identify(PcapReader reader)
    {
        var packets = new List<PacketRecord>();
        var tcpTrackers = new List<TcpConnTracker>();
        UdpTracker firstUdp = null;
        IcmpTracker firstIcmp = null;
        UdpTracker firstVxlanUdp = null;

        int index = 0;
        foreach (var rawPacket in reader.ReadPackets())
        {
            var info = PcapPacketParser.Parse(rawPacket.Data);
            if (info == null || info.SrcIP == null || info.DstIP == null)
            {
                index++;
                continue;
            }

            if (info.IsVxlan && info.VxlanSrcIP != null && info.VxlanDstIP != null)
            {
                var innerProto = info.VxlanTransportProtocol;
                if (innerProto == TransportProtocol.TCP)
                {
                    ProcessVxlanTcpPacket(info, packets, tcpTrackers, ref index);
                }
                else
                {
                    ProcessVxlanPacket(info, packets, ref index);
                    if (innerProto == TransportProtocol.UDP && firstVxlanUdp == null)
                    {
                        firstVxlanUdp = new UdpTracker
                        {
                            SrcIP = info.VxlanSrcIP,
                            DstIP = info.VxlanDstIP,
                            SrcPort = info.VxlanSrcPort,
                            DstPort = info.VxlanDstPort,
                            FirstPacketIndex = index,
                        };
                    }
                }
                index++;
                continue;
            }

            if (info.TransportProtocol == TransportProtocol.TCP)
            {
                ProcessTcpPacket(info, rawPacket, packets, tcpTrackers, ref index);
            }
            else if (info.TransportProtocol == TransportProtocol.UDP && info.HasPayload)
            {
                ProcessUdpPacket(info, rawPacket, packets, ref firstUdp, ref index);
            }
            else if (info.TransportProtocol == TransportProtocol.ICMP)
            {
                ProcessIcmpPacket(info, rawPacket, packets, ref firstIcmp, ref index);
            }

            index++;
        }

        var completedTcp = tcpTrackers
            .Where(t => t.SeenSyn && t.SeenSynAck && t.SeenAck && t.HasPayload)
            .OrderBy(t => t.FirstPayloadPacketIndex)
            .FirstOrDefault();

        if (completedTcp != null)
        {
            var sessionPackets = packets
                .Where(p =>
                {
                    PcapPacketParser.ExtractIps(p.Data, out var srcIP, out var dstIP, out _);
                    if (srcIP == null) return false;

                    var pktInfo = PcapPacketParser.Parse(p.Data);
                    if (pktInfo == null) return false;

                    if (pktInfo.TransportProtocol != TransportProtocol.TCP)
                        return false;

                    bool forward = srcIP.Equals(completedTcp.SrcIP) && dstIP.Equals(completedTcp.DstIP) &&
                                   pktInfo.SrcPort == completedTcp.SrcPort && pktInfo.DstPort == completedTcp.DstPort;
                    bool reverse = srcIP.Equals(completedTcp.DstIP) && dstIP.Equals(completedTcp.SrcIP) &&
                                   pktInfo.SrcPort == completedTcp.DstPort && pktInfo.DstPort == completedTcp.SrcPort;
                    return forward || reverse;
                }).ToList();

            int ipVer = 0;
            foreach (var p in sessionPackets)
            {
                PcapPacketParser.ExtractIps(p.Data, out var srcIP, out _, out _);
                var pi = PcapPacketParser.Parse(p.Data);
                p.IsFromClientToServer = srcIP != null && srcIP.Equals(completedTcp.SrcIP);
                if (pi != null) ipVer = pi.IpVersion;
            }

            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Tcp,
                TcpPackets = sessionPackets,
                TcpSrcIP = completedTcp.SrcIP,
                TcpDstIP = completedTcp.DstIP,
                TcpSrcPort = completedTcp.SrcPort,
                TcpDstPort = completedTcp.DstPort,
                IpVersion = ipVer,
                AppProtocol = DetectAppProtocol(sessionPackets, TransportProtocol.TCP, completedTcp.SrcPort, completedTcp.DstPort),
            };
        }

        var vxlanTcpTracker = tcpTrackers.FirstOrDefault(t => t.HasPayload);
        if (vxlanTcpTracker != null)
        {
            var sessionPackets = packets.Where(p =>
            {
                var pi = PcapPacketParser.Parse(p.Data);
                if (pi != null && pi.TransportProtocol == TransportProtocol.TCP)
                {
                    bool forward = pi.SrcIP.Equals(vxlanTcpTracker.SrcIP) && pi.DstIP.Equals(vxlanTcpTracker.DstIP) &&
                                   pi.SrcPort == vxlanTcpTracker.SrcPort && pi.DstPort == vxlanTcpTracker.DstPort;
                    bool reverse = pi.SrcIP.Equals(vxlanTcpTracker.DstIP) && pi.DstIP.Equals(vxlanTcpTracker.SrcIP) &&
                                   pi.SrcPort == vxlanTcpTracker.DstPort && pi.DstPort == vxlanTcpTracker.SrcPort;
                    return forward || reverse;
                }
                return false;
            }).ToList();

            foreach (var p in sessionPackets)
            {
                var pi = PcapPacketParser.Parse(p.Data);
                if (pi != null)
                    p.IsFromClientToServer = pi.SrcIP.Equals(vxlanTcpTracker.SrcIP);
            }

            var firstPktInfo = sessionPackets.Count > 0 ? PcapPacketParser.Parse(sessionPackets[0].Data) : null;
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Tcp,
                TcpPackets = sessionPackets,
                TcpSrcIP = vxlanTcpTracker.SrcIP,
                TcpDstIP = vxlanTcpTracker.DstIP,
                TcpSrcPort = vxlanTcpTracker.SrcPort,
                TcpDstPort = vxlanTcpTracker.DstPort,
                IpVersion = firstPktInfo?.IpVersion ?? 0,
                IsVxlan = true,
                AppProtocol = DetectAppProtocol(sessionPackets, TransportProtocol.TCP, vxlanTcpTracker.SrcPort, vxlanTcpTracker.DstPort),
            };
        }

        if (firstUdp != null)
        {
            var firstPktInfo = packets.Count > 0 ? PcapPacketParser.Parse(packets[0].Data) : null;
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Udp,
                TcpPackets = packets.Where(p => true).ToList(),
                UdpSrcIP = firstUdp.SrcIP,
                UdpDstIP = firstUdp.DstIP,
                UdpSrcPort = firstUdp.SrcPort,
                UdpDstPort = firstUdp.DstPort,
                IpVersion = firstPktInfo?.IpVersion ?? 0,
                AppProtocol = DetectAppProtocol(packets, TransportProtocol.UDP, firstUdp.SrcPort, firstUdp.DstPort),
            };
        }

        if (firstVxlanUdp != null)
        {
            var firstPktInfo = packets.Count > 0 ? PcapPacketParser.Parse(packets[0].Data) : null;
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Udp,
                TcpPackets = packets.Where(p => true).ToList(),
                UdpSrcIP = firstVxlanUdp.SrcIP,
                UdpDstIP = firstVxlanUdp.DstIP,
                UdpSrcPort = firstVxlanUdp.SrcPort,
                UdpDstPort = firstVxlanUdp.DstPort,
                IpVersion = firstPktInfo?.IpVersion ?? 0,
                IsVxlan = true,
                AppProtocol = DetectAppProtocol(packets, TransportProtocol.UDP, firstVxlanUdp.SrcPort, firstVxlanUdp.DstPort),
            };
        }

        if (firstIcmp != null)
        {
            var firstPktInfo = packets.Count > 0 ? PcapPacketParser.Parse(packets[0].Data) : null;
            return new IdentifyResult
            {
                Type = IdentifyResult.ResultType.Icmp,
                TcpPackets = packets,
                IcmpSrcIP = firstIcmp.SrcIP,
                IcmpDstIP = firstIcmp.DstIP,
                IpVersion = firstPktInfo?.IpVersion ?? 0,
                IsIcmpV6 = firstPktInfo?.IsIcmpV6 ?? false,
            };
        }

        return new IdentifyResult { Type = IdentifyResult.ResultType.None };
    }

    private static void ProcessTcpPacket(PcapPacketParser.PacketInfo info, PacketRecord rawPacket,
        List<PacketRecord> packets, List<TcpConnTracker> trackers, ref int index)
    {
        if (info.TcpHeaderLength == 0) return;

        var tracker = FindOrCreateTcpTracker(trackers, info.SrcIP, info.DstIP,
            info.SrcPort, info.DstPort, info.TcpFlags, ref index);

        if (tracker != null)
        {
            rawPacket.IsFromClientToServer = info.SrcIP.Equals(tracker.SrcIP);

            if ((info.TcpFlags & PacketHeaderParser.TcpSyn) != 0 &&
                (info.TcpFlags & PacketHeaderParser.TcpAck) == 0)
            {
                tracker.SeenSyn = true;
                if (tracker.FirstSynPacketIndex < 0)
                    tracker.FirstSynPacketIndex = index;
            }
            else if ((info.TcpFlags & PacketHeaderParser.TcpSyn) != 0 &&
                     (info.TcpFlags & PacketHeaderParser.TcpAck) != 0)
            {
                tracker.SeenSynAck = true;
            }
            else if ((info.TcpFlags & PacketHeaderParser.TcpAck) != 0 &&
                     tracker.SeenSyn && tracker.SeenSynAck)
            {
                tracker.SeenAck = true;
            }

            if ((info.TcpFlags & PacketHeaderParser.TcpPsh) != 0 || info.HasPayload)
            {
                tracker.HasPayload = true;
                if (tracker.FirstPayloadPacketIndex < 0)
                    tracker.FirstPayloadPacketIndex = index;
            }

            packets.Add(rawPacket);
        }
    }

    private static void ProcessUdpPacket(PcapPacketParser.PacketInfo info, PacketRecord rawPacket,
        List<PacketRecord> packets, ref UdpTracker tracker, ref int index)
    {
        if (tracker == null)
        {
            tracker = new UdpTracker
            {
                SrcIP = info.SrcIP,
                DstIP = info.DstIP,
                SrcPort = info.SrcPort,
                DstPort = info.DstPort,
                FirstPacketIndex = index,
            };
            rawPacket.IsFromClientToServer = true;
            packets.Add(rawPacket);
        }
        else
        {
            if ((info.SrcIP.Equals(tracker.SrcIP) && info.DstIP.Equals(tracker.DstIP) &&
                 info.SrcPort == tracker.SrcPort && info.DstPort == tracker.DstPort) ||
                (info.SrcIP.Equals(tracker.DstIP) && info.DstIP.Equals(tracker.SrcIP) &&
                 info.SrcPort == tracker.DstPort && info.DstPort == tracker.SrcPort))
            {
                rawPacket.IsFromClientToServer = info.SrcIP.Equals(tracker.SrcIP);
                packets.Add(rawPacket);
            }
        }
    }

    private static void ProcessIcmpPacket(PcapPacketParser.PacketInfo info, PacketRecord rawPacket,
        List<PacketRecord> packets, ref IcmpTracker tracker, ref int index)
    {
        if (tracker == null)
        {
            tracker = new IcmpTracker
            {
                SrcIP = info.SrcIP,
                DstIP = info.DstIP,
                FirstPacketIndex = index,
            };
            rawPacket.IsFromClientToServer = true;
            packets.Add(rawPacket);
        }
        else
        {
            if ((info.SrcIP.Equals(tracker.SrcIP) && info.DstIP.Equals(tracker.DstIP)) ||
                (info.SrcIP.Equals(tracker.DstIP) && info.DstIP.Equals(tracker.SrcIP)))
            {
                rawPacket.IsFromClientToServer = info.SrcIP.Equals(tracker.SrcIP);
                packets.Add(rawPacket);
            }
        }
    }

    private static void ProcessVxlanTcpPacket(PcapPacketParser.PacketInfo info,
        List<PacketRecord> packets, List<TcpConnTracker> trackers, ref int index)
    {
        if (info.VxlanFrameData == null || info.VxlanFrameData.Length == 0) return;

        var tracker = FindOrCreateTcpTracker(trackers, info.VxlanSrcIP, info.VxlanDstIP,
            info.VxlanSrcPort, info.VxlanDstPort, 0, ref index);

        if (tracker == null)
        {
            tracker = new TcpConnTracker
            {
                SrcIP = info.VxlanSrcIP,
                DstIP = info.VxlanDstIP,
                SrcPort = info.VxlanSrcPort,
                DstPort = info.VxlanDstPort,
                SeenSyn = true,
                SeenSynAck = true,
                SeenAck = true,
            };
            trackers.Add(tracker);
        }

        tracker.HasPayload = tracker.HasPayload || (info.VxlanPayload != null && info.VxlanPayload.Length > 0);
        if (tracker.HasPayload && tracker.FirstPayloadPacketIndex < 0)
            tracker.FirstPayloadPacketIndex = index;

        packets.Add(new PacketRecord
        {
            Timestamp = DateTime.MinValue,
            Data = info.VxlanFrameData,
            OriginalLength = info.VxlanFrameData.Length,
            IsFromClientToServer = info.VxlanSrcIP.Equals(tracker.SrcIP),
        });
    }

    private static void ProcessVxlanPacket(PcapPacketParser.PacketInfo info,
        List<PacketRecord> packets, ref int index)
    {
        if (info.VxlanFrameData == null || info.VxlanFrameData.Length == 0) return;

        packets.Add(new PacketRecord
        {
            Timestamp = DateTime.MinValue,
            Data = info.VxlanFrameData,
            OriginalLength = info.VxlanFrameData.Length,
            IsFromClientToServer = true,
        });
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

    internal static string DetectAppProtocol(List<PacketRecord> packets, TransportProtocol proto, int srcPort, int dstPort)
    {
        if (packets == null || packets.Count == 0) return null;

        foreach (var pkt in packets)
        {
            var info = PcapPacketParser.Parse(pkt.Data);
            if (info == null) continue;

            byte[] payload = null;
            if (proto == TransportProtocol.TCP)
                payload = info.TcpPayload;
            else if (proto == TransportProtocol.UDP)
                payload = info.UdpPayload;

            if (payload == null || payload.Length < 3) continue;

            if (proto == TransportProtocol.UDP && (srcPort == 53 || dstPort == 53 || info.SrcPort == 53 || info.DstPort == 53))
                return "DNS";

            if (proto == TransportProtocol.TCP)
            {
                if (payload.Length >= 3 && payload[0] == 0x16 && payload[1] == 0x03)
                    return "TLS";

                var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 16));
                if (text.StartsWith("GET ") || text.StartsWith("POST ") || text.StartsWith("PUT ") ||
                    text.StartsWith("DELETE ") || text.StartsWith("HEAD ") || text.StartsWith("OPTIONS ") ||
                    text.StartsWith("HTTP/"))
                    return "HTTP";
            }

            if (proto == TransportProtocol.UDP)
            {
                if (payload.Length >= 12)
                {
                    int qdCount = (payload[4] << 8) | payload[5];
                    int anCount = (payload[6] << 8) | payload[7];
                    if (qdCount > 0 || anCount > 0)
                    {
                        int flag = (payload[2] << 8) | payload[3];
                        if ((flag & 0x8000) == 0)
                            return "DNS";
                    }
                }
            }
        }

        return null;
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

    public int IpVersion { get; set; }
    public bool IsVxlan { get; set; }
    public int VxlanVni { get; set; }
    public bool IsIcmpV6 { get; set; }
    public string AppProtocol { get; set; }

    public bool HasSession => Type != ResultType.None;
}
