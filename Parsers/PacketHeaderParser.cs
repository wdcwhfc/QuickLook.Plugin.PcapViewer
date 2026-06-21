namespace QuickLook.Plugin.PcapViewer.Parsers;

internal static class PacketHeaderParser
{
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
}
