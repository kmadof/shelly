<Query Kind="Program" />

// Author: Sebastian Solnica
void Main()
{
    // Write code to test your extensions here. Press F5 to compile and run.

    byte[] b = { 1, 2, 3, 4 };
    b.DumpHex();
}

public static class MyExtensions
{
    // Write custom extension methods here. They will be available to all queries.
    private readonly static HexEncoder encoder = new HexEncoder();

    /// <summary>
    /// Returns hex representation of the byte array.
    /// </summary>
    /// <param name="data">bytes to encode</param>
    /// <returns></returns>
    public static string ToHexString(this byte[] data)
    {
        return ToHexString(data, 0, data.Length);
    }

    /// <summary>
    /// Returns hex representation of the byte array.
    /// </summary>
    /// <param name="data">bytes to encode</param>
    /// <param name="off">offset</param>
    /// <param name="length">number of bytes to encode</param>
    /// <returns></returns>
    public static string ToHexString(this byte[] data, int off, int length)
    {
        return Encoding.ASCII.GetString(Encode(data, off, length));
    }

    private static byte[] Encode(byte[] data, int off, int length)
    {
        using (var stream = new MemoryStream())
        {
            encoder.Encode(data, off, length, stream);
            return stream.ToArray();
        }
    }

    /// <summary>
    /// Decodes hex representation to a byte array.
    /// </summary>
    /// <param name="hex">hex string to decode</param>
    /// <returns></returns>
    public static byte[] FromHexString(this string hex)
    {
        if (hex != null && hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hex = hex.Substring(2);
        }
        else if (hex != null && hex.EndsWith("h", StringComparison.OrdinalIgnoreCase))
        {
            hex = hex.Substring(0, hex.Length - 1);
        }
        if (string.IsNullOrEmpty(hex))
        {
            throw new ArgumentException();
        }
        using (var stream = new MemoryStream())
        {
            encoder.DecodeString(hex, stream);
            return stream.ToArray();
        }
    }

    public static void DumpHex(this short n) {
        var bytes = BitConverter.GetBytes(n);
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(bytes);
        }
        bytes.DumpHex();
    }
    
    public static void DumpHex(this int n) {
        var bytes = BitConverter.GetBytes(n);
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(bytes);
        }
        bytes.DumpHex();
    }

    public static void DumpHex(this float d) {
        var bytes = BitConverter.GetBytes(d);
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(bytes);
        }
        bytes.DumpHex();
    }
    
    public static void DumpHex(this double d) {
        var bytes = BitConverter.GetBytes(d);
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(bytes);
        }
        bytes.DumpHex();
    }

    public static void DumpHex(this decimal d)
    {
        byte[] bytes = new byte[16];
        int[] decimalParts = Decimal.GetBits(d);
        int offset = 0;
        for (int i = 3; i >= 0; i--) {
            var b = BitConverter.GetBytes(decimalParts[i]);
            Array.Reverse(b);
            Array.Copy(b, 0, bytes, offset, 4);
            offset += 4;
        }
        bytes.DumpHex();
    }
    
    /// <summary>
    /// Returns a string containing a nice representation  of the byte array 
    /// (similarly to the binary editors). 
    /// <param name="bytes">array of bytes to pretty print</param>
    /// <returns></returns>
    public static void DumpHex(this byte[] bytes)
    {
        bytes.DumpHex(0, bytes.Length);
    }

    /// <summary>
    /// Returns a string containing a nice representation  of the byte array 
    /// (similarly to the binary editors). 
    /// 
    /// Example output:
    ///
    ///        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    /// 0000: c8 83 93 8f b0 cb cb d3 d1 e5 7c ff 52 dc ea 92  E....ËËÓNa.yRÜe.
    /// 0010: 5b af 30 ca d8 7a 35 e9 2e 46 fa 85 b7 38 3f 4e  [.0EOz5é.Fú.8?N
    /// 0020: 8d 60 af 4a 00 00 00 00 57 4d a4 29 35 9e c2 6f  ...J....WM.)5.Âo
    /// 0030: 30 7b 92 40 33 6d 55 43 46 fe d6 8d ef 67 99 9c  0{.@3mUCF?Ö.ig..
    /// </summary>
    /// <param name="bytes">array of bytes to pretty print</param>
    /// <param name="offset">offset in the array</param>
    /// <param name="length">number of bytes to print</param>
    /// <returns></returns>
    public static void DumpHex(this byte[] bytes, int offset, int length)
    {
        if (bytes.Length == 0)
        {
            return;
        }

        var buffer = new StringBuilder();
        int maxLength = offset + length;
        if (offset < 0 || offset >= bytes.Length || maxLength > bytes.Length)
        {
            throw new ArgumentException();
        }

        int end = Math.Min(offset + 16, maxLength);
        int start = offset;

        buffer.Append("       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F").AppendLine();
        while (end <= maxLength)
        {
            // print offset 
            buffer.Append($"{(start - offset):x4}:");

            // print hex bytes
            for (int i = start; i < end; i++)
            {
                buffer.Append($" {bytes[i]:x2}");
            }
            for (int i = 0; i < 16 - (end - start); i++)
            {
                buffer.Append("   ");
            }

            buffer.Append("  ");
            // print ascii characters
            for (int i = start; i < end; i++)
            {
                char c = (char)bytes[i];
                if (char.IsLetterOrDigit(c) || char.IsPunctuation(c))
                {
                    buffer.Append($"&#{(int)c};");
                }
                else
                {
                    buffer.Append(".");
                }
            }

            if (end == maxLength)
            {
                break;
            }

            start = end;
            end = Math.Min(end + 16, maxLength);
            buffer.AppendLine();
        }

        Util.RawHtml("<pre style=\"font-family: Consolas\">" + buffer.ToString() + "</pre>").Dump();
    }
}

// You can also define non-static classes, enums, etc.

/*
  * Class imported from BouncyCastle library. 
  * 
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
  * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
  * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
  * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
  * OR OTHER DEALINGS IN THE SOFTWARE. 
  */
public class HexEncoder
{
    protected readonly byte[] encodingTable =
    {
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
        };

    /*
	 * set up the decoding table.
	 */
    protected readonly byte[] decodingTable = new byte[128];

    private static void FillArray(byte[] buf, byte b)
    {
        int i = buf.Length;
        while (i > 0)
        {
            buf[--i] = b;
        }
    }

    protected void InitialiseDecodingTable()
    {
        FillArray(decodingTable, (byte)0xff);

        for (int i = 0; i < encodingTable.Length; i++)
        {
            decodingTable[encodingTable[i]] = (byte)i;
        }

        decodingTable['A'] = decodingTable['a'];
        decodingTable['B'] = decodingTable['b'];
        decodingTable['C'] = decodingTable['c'];
        decodingTable['D'] = decodingTable['d'];
        decodingTable['E'] = decodingTable['e'];
        decodingTable['F'] = decodingTable['f'];
    }

    public HexEncoder()
    {
        InitialiseDecodingTable();
    }

    /**
	* encode the input data producing a Hex output stream.
	*
	* @return the number of bytes produced.
	*/
    public int Encode(byte[] data, int off, int length, Stream outStream)
    {
        for (int i = off; i < (off + length); i++)
        {
            int v = data[i];

            outStream.WriteByte(encodingTable[v >> 4]);
            outStream.WriteByte(encodingTable[v & 0xf]);
        }

        return length * 2;
    }

    private static bool Ignore(char c)
    {
        return c == '\n' || c == '\r' || c == '\t' || c == ' ';
    }

    /**
	* decode the Hex encoded byte data writing it to the given output stream,
	* whitespace characters will be ignored.
	*
	* @return the number of bytes produced.
	*/
    public int Decode(byte[] data, int off, int length, Stream outStream)
    {
        byte b1, b2;
        int outLen = 0;
        int end = off + length;

        while (end > off)
        {
            if (!Ignore((char)data[end - 1]))
            {
                break;
            }

            end--;
        }

        int i = off;
        while (i < end)
        {
            while (i < end && Ignore((char)data[i]))
            {
                i++;
            }

            b1 = decodingTable[data[i++]];

            while (i < end && Ignore((char)data[i]))
            {
                i++;
            }

            b2 = decodingTable[data[i++]];

            if ((b1 | b2) >= 0x80)
                throw new IOException("invalid characters encountered in Hex data");

            outStream.WriteByte((byte)((b1 << 4) | b2));

            outLen++;
        }

        return outLen;
    }

    /**
	* decode the Hex encoded string data writing it to the given output stream,
	* whitespace characters will be ignored.
	*
	* @return the number of bytes produced.
	*/
    public int DecodeString(string data, Stream outStream)
    {
        byte b1, b2;
        int length = 0;

        int end = data.Length;

        while (end > 0)
        {
            if (!Ignore(data[end - 1]))
            {
                break;
            }

            end--;
        }

        int i = 0;
        while (i < end)
        {
            while (i < end && Ignore(data[i]))
            {
                i++;
            }

            b1 = decodingTable[data[i++]];

            while (i < end && Ignore(data[i]))
            {
                i++;
            }

            b2 = decodingTable[data[i++]];

            if ((b1 | b2) >= 0x80)
                throw new IOException("invalid characters encountered in Hex data");

            outStream.WriteByte((byte)((b1 << 4) | b2));

            length++;
        }

        return length;
    }
}