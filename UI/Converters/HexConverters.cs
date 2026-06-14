namespace QuickLook.Plugin.PcapViewer.UI.Converters;

using System;
using System.Text;

internal enum HexEncoding
{
    ASCII,
    UTF8,
    HexRaw,
    HexDump,
    GBK,
}

internal static class HexConverters
{
    public static string ToString(byte[] data, HexEncoding encoding)
    {
        if (data == null || data.Length == 0)
            return "(No data)";

        return encoding switch
        {
            HexEncoding.ASCII => ToAscii(data),
            HexEncoding.UTF8 => ToUtf8(data),
            HexEncoding.HexRaw => ToHexRaw(data),
            HexEncoding.HexDump => ToHexDump(data),
            HexEncoding.GBK => ToGbk(data),
            _ => ToAscii(data),
        };
    }

    private static string ToAscii(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (var b in data)
            sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
        return sb.ToString();
    }

    private static string ToUtf8(byte[] data)
    {
        try
        {
            return Encoding.UTF8.GetString(data);
        }
        catch
        {
            return "(UTF-8 decode error)";
        }
    }

    private static string ToHexRaw(byte[] data)
    {
        return BitConverter.ToString(data).Replace("-", "");
    }

    private static string ToHexDump(byte[] data)
    {
        const int bytesPerLine = 16;
        var sb = new StringBuilder();

        for (int offset = 0; offset < data.Length; offset += bytesPerLine)
        {
            // Offset
            sb.Append(offset.ToString("X8"));
            sb.Append("  ");

            // Hex values
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (offset + i < data.Length)
                {
                    sb.Append(data[offset + i].ToString("X2"));
                }
                else
                {
                    sb.Append("  ");
                }

                if (i == 7)
                    sb.Append("  "); // wider gap between groups of 8
                else
                    sb.Append(' ');
            }

            sb.Append("  ");

            // ASCII representation
            for (int i = 0; i < bytesPerLine && offset + i < data.Length; i++)
            {
                var b = data[offset + i];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            if (offset + bytesPerLine < data.Length)
                sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string ToGbk(byte[] data)
    {
        try
        {
            var gbk = Encoding.GetEncoding("GBK");
            return gbk.GetString(data);
        }
        catch
        {
            return "(GBK decode error)";
        }
    }
}