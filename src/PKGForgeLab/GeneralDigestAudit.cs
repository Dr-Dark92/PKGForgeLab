using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

public static class GeneralDigestAudit
{
    private static uint BE32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32BigEndian(b.Slice(o, 4));

    public static string Compare(string referencePath, string candidatePath)
    {
        var a = Inspect(referencePath);
        var b = Inspect(candidatePath);
        var sb = new StringBuilder();
        sb.AppendLine("[GENERAL_DIGESTS offline comparison]");
        sb.AppendLine("Slot values and flag bits are observations, not verified semantic mappings.");
        sb.AppendLine($"REFERENCE flags={a.Flags} CANDIDATE flags={b.Flags}");
        for (var i = 0; i < 7; i++)
        {
            var offset = 0x20 + 32 * i;
            sb.AppendLine($"slot[{i}] offset=0x{offset:X3} ref={a.Slots[i]} candidate={b.Slots[i]} match={a.Slots[i] == b.Slots[i]}");
        }
        return sb.ToString();
    }

    private sealed record Audit(string Flags, string[] Slots);

    private static Audit Inspect(string path)
    {
        using var fs = File.OpenRead(path);
        var header = new byte[0x1000];
        fs.ReadExactly(header);
        var count = BE32(header, 0x10);
        var tableOffset = BE32(header, 0x18);
        if (count > 4096 || (ulong)tableOffset + (ulong)count * 32 > (ulong)fs.Length)
            throw new InvalidDataException("Invalid PKG entry table.");
        fs.Position = tableOffset;
        var table = new byte[checked((int)count * 32)];
        fs.ReadExactly(table);
        for (var i = 0; i < count; i++)
        {
            var entry = table.AsSpan(i * 32, 32);
            if (BE32(entry, 0) != 0x0400) continue;
            var off = BE32(entry, 16);
            var len = BE32(entry, 20);
            if (len < 0x100 || (ulong)off + len > (ulong)fs.Length)
                throw new InvalidDataException("GENERAL_DIGESTS entry is truncated.");
            var data = new byte[0x100];
            fs.Position = off;
            fs.ReadExactly(data);
            var slots = Enumerable.Range(0, 7)
                .Select(j => Convert.ToHexString(data.AsSpan(0x20 + j * 32, 32)))
                .ToArray();
            return new Audit($"0x{BE32(data, 0x1C):X8}", slots);
        }
        throw new InvalidDataException("GENERAL_DIGESTS (0x0400) entry missing.");
    }
}
