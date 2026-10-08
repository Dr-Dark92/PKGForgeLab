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
        sb.AppendLine($"REFERENCE: {a.Diagnostic}");
        sb.AppendLine($"CANDIDATE: {b.Diagnostic}");
        if (a.Slots is null || b.Slots is null)
        {
            sb.AppendLine("Slot comparison unavailable: at least one entry did not decrypt to D256.");
            return sb.ToString();
        }
        sb.AppendLine($"REFERENCE flags={a.Flags} CANDIDATE flags={b.Flags}");
        for (var i = 0; i < 7; i)
        {
            var offset = 0x20 + 32 * i;
            sb.AppendLine($"slot[{i}] offset=0x{offset:X3} ref={a.Slots[i]} candidate={b.Slots[i]} match={a.Slots[i] == b.Slots[i]}");
        }
        return sb.ToString();
    }

    private sealed record Audit(string Flags, string[]? Slots, string Diagnostic);

    private static Audit Inspect(string path)
    {
        var report = PkgInspector.Inspect(path);
        var contentId = report.ParamSfo.FirstOrDefault(x => x.Key == "CONTENT_ID")?.Value
            ?? throw new InvalidDataException("CONTENT_ID is missing.");
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
            var ciphertext = new byte[checked((int)len)];
            fs.Position = off;
            fs.ReadExactly(ciphertext);
            var pkgEntry = report.Entries.Single(x => x.Id == 0x0400);
            var cipherHash = Convert.ToHexString(SHA256.HashData(ciphertext));
            var cipherPrefix = Convert.ToHexString(ciphertext.AsSpan(0, 16));
            try
            {
                var data = PkgInspector.DecryptFakePkgEntry(ciphertext, pkgEntry, contentId);
                var plainPrefix = Convert.ToHexString(data.AsSpan(0, Math.Min(16, data.Length)));
                var diagnostic = $"entry=0x0400 offset=0x{off:X} size=0x{len:X} flags2=0x{pkgEntry.Flags2:X8} cipherSha256={cipherHash} cipherPrefix={cipherPrefix} derivedKeyAttemptPrefix={plainPrefix}";
                if (data.Length < 0x100 || BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(0, 2)) != 0xD256)
                    return new Audit("UNAVAILABLE", null, diagnostic + " status=DECRYPTION_UNVERIFIED (expected D256)");
                var slots = Enumerable.Range(0, 7)
                    .Select(j => Convert.ToHexString(data.AsSpan(0x20 + j * 32, 32)))
                    .ToArray();
                return new Audit($"0x{BE32(data, 0x1C):X8}", slots, diagnostic + " status=DECRYPTED");
            }
            catch (Exception ex)
            {
                return new Audit("UNAVAILABLE", null, $"entry=0x0400 offset=0x{off:X} size=0x{len:X} cipherSha256={cipherHash} cipherPrefix={cipherPrefix} status=DECRYPTION_ERROR {ex.GetType().Name}: {ex.Message}");
            }
        }
        throw new InvalidDataException("GENERAL_DIGESTS (0x0400) entry missing.");
    }
}
