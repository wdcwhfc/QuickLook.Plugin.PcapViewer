namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Net;
using PacketDotNet;
using QuickLook.Plugin.PcapViewer.Models;

internal static class PcapPacketParser
{
    public static PacketInfo Parse(byte[] rawData)
    {
        var packet = Packet.ParsePacket(LinkLayers.Ethernet, rawData);
        if (packet == null)
            return null;

        var ipv4 = packet.Extract<IPv4Packet>();
        var ipv6 = packet.Extract<IPv6Packet>();
        var udp = packet.Extract<UdpPacket>();
        var icmpv4 = packet.Extract<IcmpV4Packet>();
        var icmpv6 = packet.Extract<IcmpV6Packet>();

        if (ipv4 == null && ipv6 == null)
            return null;

        var info = new PacketInfo();

        if (ipv4 != null)
        {
            info.SrcIP = ipv4.SourceAddress;
            info.DstIP = ipv4.DestinationAddress;
            info.IpVersion = 4;
            info.Protocol = (byte)ipv4.Protocol;
            info.IpHeaderLength = ipv4.HeaderLength;
            info.IpTotalLength = ipv4.TotalLength;
        }
        else if (ipv6 != null)
        {
            info.SrcIP = ipv6.SourceAddress;
            info.DstIP = ipv6.DestinationAddress;
            info.IpVersion = 6;
            info.Protocol = (byte)ipv6.NextHeader;
            info.IpHeaderLength = 40;
            info.IpTotalLength = ipv6.PayloadLength + 40;
        }

        if (udp != null)
        {
            info.SrcPort = udp.SourcePort;
            info.DstPort = udp.DestinationPort;
            info.UdpLength = udp.Length;
            info.HasPayload = udp.HasPayloadData;
            info.UdpPayload = udp.HasPayloadData ? udp.PayloadData : null;
            info.TransportProtocol = TransportProtocol.UDP;

            var vxlan = packet.Extract<VxlanPacket>();
            if (vxlan != null)
            {
                info.IsVxlan = true;
                info.VxlanVni = (int)vxlan.Vni;

                var innerPacket = vxlan.PayloadPacket;
                if (innerPacket is EthernetPacket innerEth && innerEth.PayloadPacket != null)
                {
                    info.VxlanFrameData = innerEth.Bytes;

                    var innerIp4 = innerEth.PayloadPacket.Extract<IPv4Packet>();
                    var innerIp6 = innerEth.PayloadPacket.Extract<IPv6Packet>();
                    var innerIp = (IPPacket)innerIp4 ?? (IPPacket)innerIp6;

                    if (innerIp != null)
                    {
                        info.VxlanSrcIP = innerIp.SourceAddress;
                        info.VxlanDstIP = innerIp.DestinationAddress;

                        var innerTcp = innerEth.PayloadPacket.Extract<TcpPacket>();
                        var innerUdp = innerEth.PayloadPacket.Extract<UdpPacket>();
                        if (innerTcp != null)
                        {
                            info.VxlanSrcPort = innerTcp.SourcePort;
                            info.VxlanDstPort = innerTcp.DestinationPort;
                            info.VxlanPayload = innerTcp.HasPayloadData ? innerTcp.PayloadData : null;
                            info.VxlanTransportProtocol = TransportProtocol.TCP;
                        }
                        else if (innerUdp != null)
                        {
                            info.VxlanSrcPort = innerUdp.SourcePort;
                            info.VxlanDstPort = innerUdp.DestinationPort;
                            info.VxlanPayload = innerUdp.HasPayloadData ? innerUdp.PayloadData : null;
                            info.VxlanTransportProtocol = TransportProtocol.UDP;
                        }
                    }
                }
            }
        }
        else
        {
            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null)
            {
                info.SrcPort = tcp.SourcePort;
                info.DstPort = tcp.DestinationPort;
                info.TcpSeqNum = (uint)tcp.SequenceNumber;
                info.TcpAckNum = (uint)tcp.AcknowledgmentNumber;
                info.TcpFlags = (byte)((tcp.Synchronize ? 0x02 : 0) |
                                        (tcp.Acknowledgment ? 0x10 : 0) |
                                        (tcp.Push ? 0x08 : 0) |
                                        (tcp.Finished ? 0x01 : 0) |
                                        (tcp.Reset ? 0x04 : 0));
                info.TcpHeaderLength = tcp.DataOffset;
                info.HasPayload = tcp.HasPayloadData;
                info.TcpPayload = tcp.HasPayloadData ? tcp.PayloadData : null;
                info.TransportProtocol = TransportProtocol.TCP;
            }
            else if (icmpv4 != null)
            {
                info.IcmpType = (byte)((ushort)icmpv4.TypeCode >> 8);
                info.IcmpCode = (byte)((ushort)icmpv4.TypeCode & 0xFF);
                info.HasPayload = icmpv4.HasPayloadData;
                info.IcmpPayload = icmpv4.HasPayloadData ? icmpv4.PayloadData : null;
                info.TransportProtocol = TransportProtocol.ICMP;
            }
            else if (icmpv6 != null)
            {
                info.IcmpType = (byte)icmpv6.Type;
                info.IcmpCode = icmpv6.Code;
                info.HasPayload = icmpv6.HasPayloadData;
                info.IcmpPayload = icmpv6.HasPayloadData ? icmpv6.PayloadData : null;
                info.TransportProtocol = TransportProtocol.ICMP;
                info.IsIcmpV6 = true;
            }
        }

        return info;
    }

    public static void ExtractIps(byte[] rawData, out IPAddress src, out IPAddress dst, out int l4Offset)
    {
        src = null;
        dst = null;
        l4Offset = 0;

        var packet = Packet.ParsePacket(LinkLayers.Ethernet, rawData);
        if (packet == null) return;

        var ipv4 = packet.Extract<IPv4Packet>();
        var ipv6 = packet.Extract<IPv6Packet>();

        if (ipv4 != null)
        {
            src = ipv4.SourceAddress;
            dst = ipv4.DestinationAddress;
            l4Offset = ipv4.HeaderLength;
        }
        else if (ipv6 != null)
        {
            src = ipv6.SourceAddress;
            dst = ipv6.DestinationAddress;
            l4Offset = 40;
        }
    }

    internal sealed class PacketInfo
    {
        public int IpVersion;
        public IPAddress SrcIP;
        public IPAddress DstIP;
        public byte Protocol;
        public int IpHeaderLength;
        public int IpTotalLength;

        public TransportProtocol TransportProtocol;
        public int SrcPort;
        public int DstPort;

        public uint TcpSeqNum;
        public uint TcpAckNum;
        public byte TcpFlags;
        public int TcpHeaderLength;
        public bool HasPayload;
        public byte[] TcpPayload;

        public int UdpLength;
        public byte[] UdpPayload;

        public byte IcmpType;
        public byte IcmpCode;
        public byte[] IcmpPayload;
        public bool IsIcmpV6;

        public bool IsVxlan;
        public int VxlanVni;
        public IPAddress VxlanSrcIP;
        public IPAddress VxlanDstIP;
        public int VxlanSrcPort;
        public int VxlanDstPort;
        public byte[] VxlanPayload;
        public byte[] VxlanFrameData;
        public TransportProtocol VxlanTransportProtocol;
    }
}
