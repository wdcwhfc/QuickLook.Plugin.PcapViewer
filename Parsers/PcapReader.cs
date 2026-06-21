namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Collections.Generic;
using System.IO;
using QuickLook.Plugin.PcapViewer.Models;

internal sealed class PcapReader : IDisposable
{
    private readonly BinaryReader _reader;
    private int _linkLayerType;
    private long _nextPacketOffset;

    private const uint MagicMicro = 0xa1b2c3d4;
    private const uint MagicNano = 0xa1b23c4d;
    private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public PcapReader(string path)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        _reader = new BinaryReader(stream);
        _nextPacketOffset = 0;
        ParseGlobalHeader();
    }

    private void ParseGlobalHeader()
    {
        var magic = _reader.ReadUInt32();
        if (magic != MagicMicro && magic != MagicNano)
            throw new InvalidDataException("Not a valid pcap file (invalid magic number).");

        _reader.ReadUInt16();   // version_major（版本主号）
        _reader.ReadUInt16();   // version_minor（版本次号）
        _reader.ReadInt32();    // thiszone（时区偏移）
        _reader.ReadUInt32();   // sigfigs（时间戳精度）
        _reader.ReadUInt32();   // snaplen（抓包长度）
        _linkLayerType = _reader.ReadInt32();  // 1 = Ethernet; 101 = Raw IP; 113 = Linux cooked-mode capture

        _nextPacketOffset = _reader.BaseStream.Position;
    }

    public IEnumerable<PacketRecord> ReadPackets()
    {
        var stream = _reader.BaseStream;
        while (_nextPacketOffset + 16 <= stream.Length)
        {
            stream.Seek(_nextPacketOffset, SeekOrigin.Begin);

            var tsSec = _reader.ReadUInt32();
            var tsUsec = _reader.ReadUInt32();
            var inclLen = _reader.ReadInt32();
            var origLen = _reader.ReadInt32();

            if (inclLen <= 0 || inclLen > 65535 || _nextPacketOffset + 16 + inclLen > stream.Length)
                break;

            var data = _reader.ReadBytes(inclLen);
            _nextPacketOffset = stream.Position;

            yield return new PacketRecord
            {
                Timestamp = UnixEpoch.AddSeconds(tsSec).AddTicks(tsUsec * 10),
                Data = data,
                OriginalLength = origLen,
            };
        }
    }

    public int LinkLayerType => _linkLayerType;

    public void Dispose() => _reader?.Close();
}