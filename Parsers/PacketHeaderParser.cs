namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Net;
using System.Net.Sockets;

internal static class PacketHeaderParser
{
    public const int EthernetHeaderSize = 14;
    public const int Ipv4MinimumHeaderSize = 20;
    public const int TcpMinimumHeaderSize = 20;
    public const int UdpHeaderSize = 8;
    public const int IcmpMinimumHeaderSize = 4;

    public const byte TcpProtocol = 6;
    public const byte UdpProtocol = 17;
    public const byte IcmpProtocol = 1;

    public const byte TcpFin = 0x01;
    public const byte TcpSyn = 0x02;
    public const byte TcpRst = 0x04;
    public const byte TcpPsh = 0x08;
    public const byte TcpAck = 0x10;

    public static ushort ReadU16Big(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);

    public static uint ReadU32Big(byte[] data, int offset) =>
        (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);

    public static ushort ParseEthernet(byte[] data, out int payloadOffset)
    {
        payloadOffset = 0;
        if (data.Length < EthernetHeaderSize)
            return 0;
        payloadOffset = EthernetHeaderSize;
        return ReadU16Big(data, 12);
    }

    public static byte ParseIPv4(byte[] data, int offset,
        out IPAddress src, out IPAddress dst, out int headerLen, out int totalLen, out int l4Offset)
    {
        src = null; dst = null; headerLen = 0; totalLen = 0; l4Offset = 0;
        if (data.Length < offset + Ipv4MinimumHeaderSize)
            return 0;

        var verIhl = data[offset];
        headerLen = (verIhl & 0x0F) * 4;
        totalLen = ReadU16Big(data, offset + 2);
        var protocol = data[offset + 9];

        var srcBytes = new byte[4];
        Buffer.BlockCopy(data, offset + 12, srcBytes, 0, 4);
        var dstBytes = new byte[4];
        Buffer.BlockCopy(data, offset + 16, dstBytes, 0, 4);
        src = new IPAddress(srcBytes);
        dst = new IPAddress(dstBytes);
        l4Offset = offset + headerLen;
        return protocol;
    }

    public static void ParseTcp(byte[] data, int offset,
        out int srcPort, out int dstPort, out uint seqNum, out uint ackNum, out byte flags,
        out int dataOffset, out int dataLen)
    {
        srcPort = 0; dstPort = 0; seqNum = 0; ackNum = 0; flags = 0; dataOffset = 0; dataLen = 0;
        if (data.Length < offset + TcpMinimumHeaderSize)
            return;

        srcPort = ReadU16Big(data, offset);
        dstPort = ReadU16Big(data, offset + 2);
        seqNum = ReadU32Big(data, offset + 4);
        ackNum = ReadU32Big(data, offset + 8);
        dataOffset = ((data[offset + 12] >> 4) & 0x0F) * 4;
        flags = data[offset + 13];

        var headerSize = dataOffset;
        var totalLen = data.Length - offset;
        dataLen = Math.Max(0, totalLen - headerSize);
    }

    public static void ParseUdp(byte[] data, int offset,
        out int srcPort, out int dstPort, out int length)
    {
        srcPort = 0; dstPort = 0; length = 0;
        if (data.Length < offset + UdpHeaderSize)
            return;

        srcPort = ReadU16Big(data, offset);
        dstPort = ReadU16Big(data, offset + 2);
        length = ReadU16Big(data, offset + 4);
    }

    public static void ParseIcmp(byte[] data, int offset,
        out byte type, out byte code, out int headerSize)
    {
        type = 0; code = 0; headerSize = 0;
        if (data.Length < offset + IcmpMinimumHeaderSize)
            return;

        type = data[offset];
        code = data[offset + 1];
        headerSize = IcmpMinimumHeaderSize;
    }
}