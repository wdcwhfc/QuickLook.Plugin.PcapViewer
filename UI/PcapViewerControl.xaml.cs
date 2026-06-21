using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using QuickLook.Plugin.PcapViewer.Models;
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

    private static readonly Brush RequestForeground = new SolidColorBrush(Color.FromRgb(0x7F, 0x00, 0x00));
    private static readonly Brush RequestBackground = new SolidColorBrush(Color.FromRgb(0xFB, 0xED, 0xED));
    private static readonly Brush ResponseForeground = new SolidColorBrush(Color.FromRgb(0x00, 0x00, 0x7F));
    private static readonly Brush ResponseBackground = new SolidColorBrush(Color.FromRgb(0xED, 0xED, 0xFB));

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

            var src = GetSourceString(result);
            var dst = GetDestString(result);
            var proto = GetProtocolString(result);
            var appProto = GetAppProtocolString(result);
            ProtocolIcon.Text = proto;

            var info = $"{proto}  {appProto}  |  {src}  \u2192  {dst}";
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
            var info = PcapPacketParser.Parse(pkt.Data);
            if (info == null) continue;
            if (info.TransportProtocol != TransportProtocol.TCP) continue;
            if (info.TcpHeaderLength == 0) continue;

            int actualPayloadLen = info.TcpPayload?.Length ?? 0;
            if (actualPayloadLen <= 0) continue;
            if ((info.TcpFlags & PacketHeaderParser.TcpSyn) != 0) continue;

            AddPayload(info.TcpPayload, pkt.IsFromClientToServer, actualPayloadLen);
        }
    }

    private void CollectUdpPayloads(IdentifyResult result)
    {
        ProtocolIcon.Foreground = Brushes.Green;

        foreach (var pkt in result.TcpPackets)
        {
            var info = PcapPacketParser.Parse(pkt.Data);
            if (info == null) continue;
            if (info.TransportProtocol != TransportProtocol.UDP) continue;

            int payloadLen = info.UdpPayload?.Length ?? 0;
            if (payloadLen <= 0) continue;

            AddPayload(info.UdpPayload, pkt.IsFromClientToServer, payloadLen);
        }
    }

    private void CollectIcmpPayloads(IdentifyResult result)
    {
        ProtocolIcon.Foreground = Brushes.Purple;

        foreach (var pkt in result.TcpPackets)
        {
            var info = PcapPacketParser.Parse(pkt.Data);
            if (info == null) continue;
            if (info.TransportProtocol != TransportProtocol.ICMP) continue;

            int payloadLen = info.IcmpPayload?.Length ?? 0;
            if (payloadLen <= 0) continue;

            AddPayload(info.IcmpPayload, pkt.IsFromClientToServer, payloadLen);
        }
    }

    private void AddPayload(byte[] payload, bool isFromClientToServer, int length)
    {
        const int maxTotal = 1_000_000;
        if (_totalBytes >= maxTotal)
        {
            _isTruncated = true;
            return;
        }

        int remaining = maxTotal - (int)_totalBytes;
        int copyLen = Math.Min(remaining, Math.Min(length, payload.Length));
        if (copyLen <= 0) return;

        var chunkData = new byte[copyLen];
        Buffer.BlockCopy(payload, 0, chunkData, 0, copyLen);

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
                return FormatAddress(result.TcpSrcIP, result.TcpSrcPort);
            case IdentifyResult.ResultType.Udp:
                return FormatAddress(result.UdpSrcIP, result.UdpSrcPort);
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
                return FormatAddress(result.TcpDstIP, result.TcpDstPort);
            case IdentifyResult.ResultType.Udp:
                return FormatAddress(result.UdpDstIP, result.UdpDstPort);
            case IdentifyResult.ResultType.Icmp:
                return result.IcmpDstIP?.ToString() ?? "?";
            default:
                return "?";
        }
    }

    private static string FormatAddress(System.Net.IPAddress ip, int port)
    {
        if (ip == null) return "?";
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return $"[{ip}]:{port}";
        return $"{ip}:{port}";
    }

    private static string GetProtocolString(IdentifyResult result)
    {
        var ipTag = result.IpVersion == 6 ? "6" : "";
        var vxlanTag = result.IsVxlan ? "VXLAN\u2192" : "";
        return result.Type switch
        {
            IdentifyResult.ResultType.Tcp => $"{vxlanTag}TCP{ipTag}",
            IdentifyResult.ResultType.Udp => $"{vxlanTag}UDP{ipTag}",
            IdentifyResult.ResultType.Icmp => result.IsIcmpV6 ? "ICMPv6" : "ICMP",
            _ => "?",
        };
    }

    private static string GetAppProtocolString(IdentifyResult result)
    {
        var app = result.AppProtocol;
        if (string.IsNullOrEmpty(app)) return "";
        return $"[{app}]";
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
