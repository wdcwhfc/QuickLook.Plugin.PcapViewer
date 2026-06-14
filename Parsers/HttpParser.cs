namespace QuickLook.Plugin.PcapViewer.Parsers;

using System;
using System.Collections.Generic;
using System.Text;
using QuickLook.Plugin.PcapViewer.Models;

internal static class HttpParser
{
    public static void Parse(byte[] clientData, byte[] serverData,
        out HttpMessage request, out HttpMessage response)
    {
        request = ParseMessage(clientData, isRequest: true);
        response = ParseMessage(serverData, isRequest: false);
    }

    private static HttpMessage ParseMessage(byte[] data, bool isRequest)
    {
        if (data == null || data.Length == 0)
            return CreateEmptyMessage(isRequest);

        int headerEnd = FindHeaderEnd(data);
        if (headerEnd < 0)
        {
            return new HttpMessage
            {
                IsRequest = isRequest,
                Headers = new Dictionary<string, string>(),
                Body = data,
            };
        }

        var headerBytes = new byte[headerEnd];
        Buffer.BlockCopy(data, 0, headerBytes, 0, headerEnd);
        var headerText = Encoding.ASCII.GetString(headerBytes);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);

        string method = null, uri = null, version = null;
        int statusCode = 0;
        string reasonPhrase = null;

        if (lines.Length > 0)
        {
            var requestLine = lines[0];
            if (isRequest)
            {
                var parts = requestLine.Split(' ');
                if (parts.Length >= 3)
                {
                    method = parts[0];
                    uri = parts[1];
                    version = parts[2];
                }
            }
            else
            {
                var parts = requestLine.Split(' ');
                if (parts.Length >= 2)
                {
                    version = parts[0];
                    int.TryParse(parts[1], out statusCode);
                    reasonPhrase = parts.Length > 2 ? string.Join(" ", parts, 2, parts.Length - 2) : "";
                }
            }

            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrEmpty(line)) continue;
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var key = line.Substring(0, colonIdx).Trim();
                    var value = line.Substring(colonIdx + 1).Trim();
                    headers[key] = value;
                }
            }
        }

        int bodyStart = headerEnd + 4;
        byte[] body;
        bool isTruncated = false;

        if (bodyStart >= data.Length)
        {
            body = Array.Empty<byte>();
        }
        else
        {
            int bodyLength = data.Length - bodyStart;

            if (headers.TryGetValue("Content-Length", out var clStr) && int.TryParse(clStr, out int cl))
            {
                bodyLength = Math.Min(bodyLength, cl);
            }
            else if (headers.TryGetValue("Transfer-Encoding", out var te) &&
                     te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var chunkedBytes = new byte[data.Length - bodyStart];
                Buffer.BlockCopy(data, bodyStart, chunkedBytes, 0, chunkedBytes.Length);
                body = DecodeChunked(chunkedBytes, out isTruncated);
                return new HttpMessage
                {
                    IsRequest = isRequest,
                    Method = method,
                    Uri = uri,
                    Version = version,
                    StatusCode = statusCode,
                    ReasonPhrase = reasonPhrase,
                    Headers = headers,
                    Body = body,
                    IsTruncated = isTruncated,
                };
            }

            body = new byte[bodyLength];
            Buffer.BlockCopy(data, bodyStart, body, 0, bodyLength);
        }

        return new HttpMessage
        {
            IsRequest = isRequest,
            Method = method,
            Uri = uri,
            Version = version,
            StatusCode = statusCode,
            ReasonPhrase = reasonPhrase,
            Headers = headers,
            Body = body,
            IsTruncated = isTruncated,
        };
    }

    private static int FindHeaderEnd(byte[] data)
    {
        for (int i = 0; i < data.Length - 3; i++)
        {
            if (data[i] == 0x0D && data[i + 1] == 0x0A &&
                data[i + 2] == 0x0D && data[i + 3] == 0x0A)
                return i;
        }
        return -1;
    }

    private static byte[] DecodeChunked(byte[] data, out bool isTruncated)
    {
        isTruncated = false;
        var result = new List<byte>();
        int offset = 0;

        while (offset < data.Length)
        {
            int lineEnd = -1;
            for (int i = offset; i < data.Length - 1; i++)
            {
                if (data[i] == 0x0D && data[i + 1] == 0x0A)
                {
                    lineEnd = i;
                    break;
                }
            }
            if (lineEnd < 0) break;

            var sizeLine = Encoding.ASCII.GetString(data, offset, lineEnd - offset);
            var chunkSize = Convert.ToInt32(sizeLine.Trim().Split(';')[0], 16);
            offset = lineEnd + 2;

            if (chunkSize == 0) break;

            if (offset + chunkSize + 2 > data.Length)
            {
                int remaining = data.Length - offset;
                if (remaining > 0)
                {
                    var part = new byte[remaining];
                    Buffer.BlockCopy(data, offset, part, 0, remaining);
                    result.AddRange(part);
                    isTruncated = true;
                }
                break;
            }

            var chunk = new byte[chunkSize];
            Buffer.BlockCopy(data, offset, chunk, 0, chunkSize);
            result.AddRange(chunk);
            offset += chunkSize + 2;
        }

        return result.ToArray();
    }

    private static HttpMessage CreateEmptyMessage(bool isRequest)
    {
        return new HttpMessage
        {
            IsRequest = isRequest,
            Method = isRequest ? "N/A" : null,
            Uri = isRequest ? "" : null,
            Version = "N/A",
            Headers = new Dictionary<string, string>(),
            Body = Array.Empty<byte>(),
        };
    }
}