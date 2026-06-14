using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using QuickLook.Plugin.PcapViewer.Parsers;
using QuickLook.Plugin.PcapViewer.UI.Converters;

namespace QuickLook.Plugin.PcapViewer.UI;

public partial class PcapViewerControl : UserControl, IDisposable
{
    private readonly List<PayloadChunk> _payloadChunks = new List<PayloadChunk>();
    private long _totalBytes;
    private bool _isTruncated;

    private struct PayloadChunk
    {
        public byte[] Data;
        public bool IsFromClientToServer;
    }

    private static readonly Brush RequestForeground = new SolidColorBrush(Color.FromRgb(0x7F, 0x00, 0x00));     // #7f0000
    private static readonly Brush RequestBackground = new SolidColorBrush(Color.FromRgb(0xFB, 0xED, 0xED));     // #fbeded
    private static readonly Brush ResponseForeground = new SolidColorBrush(Color.FromRgb(0x00, 0x00, 0x7F));    // #00007f
    private static readonly Brush ResponseBackground = new SolidColorBrush(Color.FromRgb(0xED, 0xED, 0xFB));    // #ededfb

    public PcapViewerControl()
    {
        InitializeComponent();
        EncodingTabs.SelectedIndex = 0;
    }

    public void LoadFile(string path)
    {
        try
        {
            ErrorOverlay.Visibility = Visibility.Collapsed;
            _payloadChunks.Clear();
            _totalBytes = 0;
            _isTruncated = false;

            using var reader = new PcapReader(path);
            var result = SessionIdentifier.Identify(reader);

            if (!result.HasSession)
            {
                ShowError("No valid session found in this pcap file.\n" +
                          "Requires a pcap with at least one TCP, UDP, or ICMP session.");
                return;
            }

            switch (result.Type)
            {
                case IdentifyResult.ResultType.Tcp:
                    CollectTcpPayloads(result);
                    break;
                case IdentifyResult.ResultType.Udp:
                    CollectUdpPayloads(result);
                    break;
                case IdentifyResult.ResultType.Icmp:
                    CollectIcmpPayloads(result);
                    break;
            }

            // Build info bar
            var src = GetSourceString(result);
            var dst = GetDestString(result);
            var proto = GetProtocolString(result);
            ProtocolIcon.Text = proto;

            var info = $"{proto}  |  {src}  \u2192  {dst}";
            if (_isTruncated)
                info += "  [TRUNCATED > 1MB]";
            InfoText.Text = info;

            RenderContent();
        }
        catch (Exception ex)
        {
            ShowError($"Error loading pcap file:\n{ex.Message}");
        }
    }

    private void CollectTcpPayloads(IdentifyResult result)
    {
        ProtocolIcon.Foreground = Brushes.DarkOrange;

        foreach (var pkt in result.TcpPackets)
        {
            var etherType = PacketHeaderParser.ParseEthernet(pkt.Data, out var ethOff);
            if (etherType == 0) continue;

            var protocol = PacketHeaderParser.ParseIPv4(pkt.Data, ethOff,
                out _, out _, out var ipHeaderLen, out var ipTotalLen, out var l4Offset);
            if (protocol != PacketHeaderParser.TcpProtocol) continue;

            PacketHeaderParser.ParseTcp(pkt.Data, l4Offset,
                out _, out _, out _, out _, out var flags, out var tcpHeaderLen, out _);

            // Use IP Total Length to avoid Ethernet padding bytes
            int actualPayloadLen = Math.Max(0, ipTotalLen - ipHeaderLen - tcpHeaderLen);
            if (actualPayloadLen <= 0) continue;
            if ((flags & PacketHeaderParser.TcpSyn) != 0) continue;

            var payload = new byte[actualPayloadLen];
            Buffer.BlockCopy(pkt.Data, l4Offset + tcpHeaderLen, payload, 0, actualPayloadLen);
            AddPayload(payload, pkt.IsFromClientToServer);
        }
    }

    private void CollectUdpPayloads(IdentifyResult result)
    {
        ProtocolIcon.Foreground = Brushes.Green;

        foreach (var pkt in result.TcpPackets)
        {
            var etherType = PacketHeaderParser.ParseEthernet(pkt.Data, out var ethOff);
            if (etherType == 0) continue;

            var protocol = PacketHeaderParser.ParseIPv4(pkt.Data, ethOff,
                out _, out _, out _, out _, out var l4Offset);
            if (protocol != PacketHeaderParser.UdpProtocol) continue;

            PacketHeaderParser.ParseUdp(pkt.Data, l4Offset,
                out _, out _, out var length);

            int payloadLen = length - PacketHeaderParser.UdpHeaderSize;
            if (payloadLen <= 0) continue;

            int payloadOffset = l4Offset + PacketHeaderParser.UdpHeaderSize;
            var payload = new byte[payloadLen];
            Buffer.BlockCopy(pkt.Data, payloadOffset, payload, 0,
                Math.Min(payloadLen, pkt.Data.Length - payloadOffset));
            AddPayload(payload, pkt.IsFromClientToServer);
        }
    }

    private void CollectIcmpPayloads(IdentifyResult result)
    {
        ProtocolIcon.Foreground = Brushes.Purple;

        foreach (var pkt in result.TcpPackets)
        {
            var etherType = PacketHeaderParser.ParseEthernet(pkt.Data, out var ethOff);
            if (etherType == 0) continue;

            PacketHeaderParser.ParseIPv4(pkt.Data, ethOff,
                out _, out _, out _, out _, out var l4Offset);

            PacketHeaderParser.ParseIcmp(pkt.Data, l4Offset,
                out _, out _, out var icmpHeaderSize);

            int payloadLen = pkt.Data.Length - l4Offset - icmpHeaderSize;
            if (payloadLen <= 0) continue;

            int payloadOffset = l4Offset + icmpHeaderSize;
            var payload = new byte[payloadLen];
            Buffer.BlockCopy(pkt.Data, payloadOffset, payload, 0,
                Math.Min(payloadLen, pkt.Data.Length - payloadOffset));
            AddPayload(payload, pkt.IsFromClientToServer);
        }
    }

    private void AddPayload(byte[] payload, bool isFromClientToServer)
    {
        const int maxTotal = 1_000_000;
        if (_totalBytes >= maxTotal)
        {
            _isTruncated = true;
            return;
        }

        int remaining = maxTotal - (int)_totalBytes;
        int copyLen = Math.Min(remaining, payload.Length);
        if (copyLen <= 0) return;

        var chunkData = new byte[copyLen];
        Buffer.BlockCopy(payload, 0, chunkData, 0, copyLen);

        // Merge with last chunk if same direction
        if (_payloadChunks.Count > 0 &&
            _payloadChunks[_payloadChunks.Count - 1].IsFromClientToServer == isFromClientToServer)
        {
            var last = _payloadChunks[_payloadChunks.Count - 1];
            var combined = new byte[last.Data.Length + copyLen];
            Buffer.BlockCopy(last.Data, 0, combined, 0, last.Data.Length);
            Buffer.BlockCopy(chunkData, 0, combined, last.Data.Length, copyLen);
            _payloadChunks[_payloadChunks.Count - 1] = new PayloadChunk
            {
                Data = combined,
                IsFromClientToServer = isFromClientToServer,
            };
        }
        else
        {
            _payloadChunks.Add(new PayloadChunk
            {
                Data = chunkData,
                IsFromClientToServer = isFromClientToServer,
            });
        }

        _totalBytes += copyLen;
    }

    private static string GetSourceString(IdentifyResult result)
    {
        switch (result.Type)
        {
            case IdentifyResult.ResultType.Tcp:
                return $"{result.TcpSrcIP}:{result.TcpSrcPort}";
            case IdentifyResult.ResultType.Udp:
                return $"{result.UdpSrcIP}:{result.UdpSrcPort}";
            case IdentifyResult.ResultType.Icmp:
                return result.IcmpSrcIP?.ToString() ?? "?";
            default:
                return "?";
        }
    }

    private static string GetDestString(IdentifyResult result)
    {
        switch (result.Type)
        {
            case IdentifyResult.ResultType.Tcp:
                return $"{result.TcpDstIP}:{result.TcpDstPort}";
            case IdentifyResult.ResultType.Udp:
                return $"{result.UdpDstIP}:{result.UdpDstPort}";
            case IdentifyResult.ResultType.Icmp:
                return result.IcmpDstIP?.ToString() ?? "?";
            default:
                return "?";
        }
    }

    private static string GetProtocolString(IdentifyResult result)
    {
        return result.Type switch
        {
            IdentifyResult.ResultType.Tcp => "TCP",
            IdentifyResult.ResultType.Udp => "UDP",
            IdentifyResult.ResultType.Icmp => "ICMP",
            _ => "?",
        };
    }

    private void EncodingTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RenderContent();
    }

    private void RenderContent()
    {
        var encoding = GetSelectedEncoding();
        bool selectiveBg = (encoding == HexEncoding.ASCII ||
                            encoding == HexEncoding.UTF8 ||
                            encoding == HexEncoding.GBK);

        var doc = new FlowDocument
        {
            PagePadding = new Thickness(0),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 18,
        };

        if (_payloadChunks.Count == 0)
        {
            doc.Blocks.Add(new Paragraph(new Run("(No data)")));
            ContentViewer.Document = doc;
            return;
        }

        foreach (var chunk in _payloadChunks)
        {
            var text = HexConverters.ToString(chunk.Data, encoding);
            var foreground = chunk.IsFromClientToServer ? RequestForeground : ResponseForeground;
            var background = chunk.IsFromClientToServer ? RequestBackground : ResponseBackground;

            if (selectiveBg)
            {
                var para = new Paragraph { Foreground = foreground, Margin = new Thickness(0), Padding = new Thickness(8, 6, 8, 6) };
                foreach (var seg in SplitByVisibility(text))
                {
                    var run = new Run(seg.Text);
                    if (seg.IsVisible)
                        run.Background = background;
                    para.Inlines.Add(run);
                }
                doc.Blocks.Add(para);
            }
            else
            {
                doc.Blocks.Add(new Paragraph(new Run(text))
                {
                    Foreground = foreground,
                    Background = background,
                    Margin = new Thickness(0),
                    Padding = new Thickness(8, 6, 8, 6),
                });
            }
        }

        ContentViewer.Document = doc;
    }

    private struct TextSegment { public string Text; public bool IsVisible; }

    private static List<TextSegment> SplitByVisibility(string text)
    {
        var result = new List<TextSegment>();
        if (string.IsNullOrEmpty(text))
            return result;

        var buf = new System.Text.StringBuilder(256);
        bool? groupIsVisible = null;

        foreach (var ch in text)
        {
            bool visible = ch != '\r' && ch != '\n';
            if (groupIsVisible == null)
            {
                groupIsVisible = visible;
                buf.Append(ch);
            }
            else if (visible == groupIsVisible.Value)
            {
                buf.Append(ch);
            }
            else
            {
                result.Add(new TextSegment { Text = buf.ToString(), IsVisible = groupIsVisible.Value });
                buf.Clear();
                buf.Append(ch);
                groupIsVisible = visible;
            }
        }

        if (buf.Length > 0)
            result.Add(new TextSegment { Text = buf.ToString(), IsVisible = groupIsVisible.Value });

        return result;
    }

    private HexEncoding GetSelectedEncoding()
    {
        return EncodingTabs.SelectedIndex switch
        {
            0 => HexEncoding.UTF8,
            1 => HexEncoding.ASCII,
            2 => HexEncoding.HexRaw,
            3 => HexEncoding.HexDump,
            4 => HexEncoding.GBK,
            _ => HexEncoding.UTF8,
        };
    }

    private void ShowError(string message)
    {
        ErrorOverlay.Visibility = Visibility.Visible;
        ErrorMessage.Text = message;
        ContentViewer.Document = new FlowDocument();
    }

    public void Dispose()
    {
        _payloadChunks.Clear();
    }
}