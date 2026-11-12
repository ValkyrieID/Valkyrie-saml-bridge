using System.IO.Compression;
using System.Text;

namespace ValkyrieSamlBridge.Core.Saml;

// Decodes SAMLRequest values. HTTP-Redirect uses base64 of raw DEFLATE; HTTP-POST uses base64 of XML
// (SAML Bindings §3.4.4 and §3.5.4). The inflated size is capped, so a small input can't expand into
// a large one.
public static class SamlMessageEncoding
{
    private const int MaxInflatedBytes = SafeXml.MaxBytes;

    public static string DecodePost(string value) => Encoding.UTF8.GetString(DecodeBase64(value));

    public static string InflateRedirect(string value)
    {
        var compressed = DecodeBase64(value);

        using var input = new MemoryStream(compressed);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        int read;
        while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (output.Length + read > MaxInflatedBytes)
            {
                throw new SamlException("The SAMLRequest is too large once inflated.");
            }
            output.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static byte[] DecodeBase64(string value)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw new SamlException("The SAMLRequest is not valid base64.");
        }
    }
}
