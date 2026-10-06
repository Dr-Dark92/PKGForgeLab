using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length is < 1 or > 2)
{
    Console.WriteLine("PKGForgeLab");
    Console.WriteLine("Usage:");
    Console.WriteLine("  PKGForgeLab <pkg>");
    Console.WriteLine("  PKGForgeLab <good.pkg> <bad.pkg>");
    return 2;
}

try
{
    var reports = args.Select(PkgInspector.Inspect).ToArray();

    foreach (var report in reports)
    {
        var outPath = Path.ChangeExtension(report.Path, ".pkglab.json");
        File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonOptions));
        Console.WriteLine($"Wrote: {outPath}");
    }

    if (reports.Length == 2)
    {
        var diff = PkgComparer.Compare(reports[0], reports[1]);
        var dir = Path.GetDirectoryName(Path.GetFullPath(reports[1].Path))!;
        var name = Path.GetFileNameWithoutExtension(reports[1].Path);
        var diffPath = Path.Combine(dir, name + ".pkglab.diff.txt");
        File.WriteAllText(diffPath, diff);
        Console.WriteLine($"Wrote: {diffPath}");
        Console.WriteLine();
        Console.WriteLine(diff);
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}

static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

public sealed record PkgReport(
    string Path,
    long FileSize,
    string Sha256,
    uint Magic,
    uint EntryCount,
    uint EntryTableOffset,
    uint EntryTableSize,
    ulong BodyOffset,
    ulong BodySize,
    ulong ContentOffset,
    ulong ContentSize,
    ulong PackageSize,
    ulong MetadataSpan,
    ulong ContentBlocks64K,
    IReadOnlyList<PkgEntryReport> Entries,
    PlayGoReport? PlayGo,
    OuterPfsReport? OuterPfs);

public sealed record PkgEntryReport(
    uint Id,
    uint NameOffset,
    uint Flags1,
    uint Flags2,
    uint DataOffset,
    uint DataSize,
    string? Name);

public sealed record PlayGoReport(
    uint DataOffset,
    uint DataSize,
    uint Magic,
    ushort ImageCount,
    ushort ChunkCount,
    ushort MicroChunkCount,
    ushort ScenarioCount,
    ulong PackageSizeField,
    ulong InnerPfsSizeField,
    uint ChunkShaOffset,
    uint ChunkShaSize);

public sealed record OuterPfsReport(
    ulong FileOffset,
    ulong AvailableBytes,
    long Version,
    long Magic,
    byte ModeByte,
    ushort Flags,
    uint BlockSize,
    long BlockCount,
    long InodeCount,
    long DataBlockCount,
    long InodeBlockCount,
    ulong DeclaredImageBytes);

public static class PkgInspector
{
    private const uint PlayGoChunkDat = 0x00001001;
    private const uint PlayGoChunkSha = 0x00001002;

    public static PkgReport Inspect(string path)
    {
        path = Path.GetFullPath(path);
        using var fs = File.OpenRead(path);
        if (fs.Length < 0x1100)
            throw new InvalidDataException("File is too small to be a PS4 PKG.");

        var header = ReadExact(fs, 0, 0x1100);
        var magic = BE32(header, 0x00);
        var entryCount = BE32(header, 0x10);
        var entryTableOffset = BE32(header, 0x18);
        var entryTableSize = BE32(header, 0x1C);
        var bodyOffset = BE64(header, 0x20);
        var bodySize = BE64(header, 0x28);
        var contentOffset = BE64(header, 0x30);
        var contentSize = BE64(header, 0x38);
        var packageSize = BE64(header, 0x430);

        if (entryCount > 4096)
            throw new InvalidDataException($"Implausible PKG entry count: {entryCount}.");

        var tableBytes = checked((long)entryCount * 32);
        if ((ulong)entryTableOffset + (ulong)tableBytes > (ulong)fs.Length)
            throw new InvalidDataException("PKG entry table extends beyond the file.");

        var rawEntries = ReadExact(fs, entryTableOffset, checked((int)tableBytes));
        var temp = new List<(uint Id,uint NameOffset,uint Flags1,uint Flags2,uint DataOffset,uint DataSize)>();
        for (var i = 0; i < entryCount; i++)
        {
            var s = rawEntries.AsSpan(i * 32, 32);
            temp.Add((
                BinaryPrimitives.ReadUInt32BigEndian(s[0..4]),
                BinaryPrimitives.ReadUInt32BigEndian(s[4..8]),
                BinaryPrimitives.ReadUInt32BigEndian(s[8..12]),
                BinaryPrimitives.ReadUInt32BigEndian(s[12..16]),
                BinaryPrimitives.ReadUInt32BigEndian(s[16..20]),
                BinaryPrimitives.ReadUInt32BigEndian(s[20..24])));
        }

        var namesEntry = temp.FirstOrDefault(x => x.Id == 0x00000200);
        byte[] names = [];
        if (namesEntry.DataSize > 0 && (ulong)namesEntry.DataOffset + namesEntry.DataSize <= (ulong)fs.Length)
            names = ReadExact(fs, namesEntry.DataOffset, checked((int)namesEntry.DataSize));

        var entries = temp.Select(x => new PkgEntryReport(
            x.Id, x.NameOffset, x.Flags1, x.Flags2, x.DataOffset, x.DataSize,
            ReadName(names, x.NameOffset))).ToArray();

        PlayGoReport? playGo = null;
        var pg = entries.FirstOrDefault(x => x.Id == PlayGoChunkDat);
        var sha = entries.FirstOrDefault(x => x.Id == PlayGoChunkSha);
        if (pg is not null && pg.DataSize >= 0x160 && (ulong)pg.DataOffset + pg.DataSize <= (ulong)fs.Length)
        {
            var b = ReadExact(fs, pg.DataOffset, checked((int)pg.DataSize));
            playGo = new PlayGoReport(
                pg.DataOffset,
                pg.DataSize,
                LE32(b, 0x00),
                LE16(b, 0x08),
                LE16(b, 0x0A),
                LE16(b, 0x0C),
                LE16(b, 0x0E),
                LE64(b, 0x148),
                LE64(b, 0x158),
                sha?.DataOffset ?? 0,
                sha?.DataSize ?? 0);
        }

        OuterPfsReport? outer = null;
        if (contentOffset > 0 && contentOffset + 0x380 <= (ulong)fs.Length)
        {
            var b = ReadExact(fs, checked((long)contentOffset), 0x380);
            var blockSize = LE32(b, 0x20);
            var blockCount = LE64S(b, 0x28);
            ulong declared = 0;
            if (blockSize > 0 && blockCount > 0)
                declared = checked((ulong)blockSize * (ulong)blockCount);
            outer = new OuterPfsReport(
                contentOffset,
                (ulong)fs.Length - contentOffset,
                LE64S(b, 0x00),
                LE64S(b, 0x08),
                b[0x1A],
                LE16(b, 0x1C),
                blockSize,
                blockCount,
                LE64S(b, 0x30),
                LE64S(b, 0x38),
                LE64S(b, 0x40),
                declared);
        }

        fs.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(fs));

        return new PkgReport(
            path,
            fs.Length,
            sha256,
            magic,
            entryCount,
            entryTableOffset,
            entryTableSize,
            bodyOffset,
            bodySize,
            contentOffset,
            contentSize,
            packageSize,
            contentOffset >= bodyOffset ? contentOffset - bodyOffset : 0,
            contentSize / 0x10000,
            entries,
            playGo,
            outer);
    }

    private static string? ReadName(byte[] names, uint offset)
    {
        if (offset == 0 || offset >= names.Length) return null;
        var end = Array.IndexOf(names, (byte)0, checked((int)offset));
        if (end < 0) end = names.Length;
        return System.Text.Encoding.UTF8.GetString(names, checked((int)offset), end - checked((int)offset));
    }

    private static byte[] ReadExact(FileStream fs, long offset, int size)
    {
        var b = new byte[size];
        fs.Position = offset;
        fs.ReadExactly(b);
        return b;
    }

    private static uint BE32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o,4));
    private static ulong BE64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(o,8));
    private static ushort LE16(byte[] b,int o)=>BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o,2));
    private static uint LE32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o,4));
    private static ulong LE64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o,8));
    private static long LE64S(byte[] b,int o)=>BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(o,8));
}

public static class PkgComparer
{
    public static string Compare(PkgReport good, PkgReport bad)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("PKGForgeLab comparison");
        sb.AppendLine($"GOOD: {Path.GetFileName(good.Path)}");
        sb.AppendLine($"BAD : {Path.GetFileName(bad.Path)}");
        sb.AppendLine();

        Add(sb, "File size", good.FileSize, bad.FileSize);
        AddHex(sb, "Magic", good.Magic, bad.Magic);
        Add(sb, "Entry count", good.EntryCount, bad.EntryCount);
        AddHex(sb, "Entry table offset", good.EntryTableOffset, bad.EntryTableOffset);
        AddHex(sb, "Entry table size", good.EntryTableSize, bad.EntryTableSize);
        AddHex(sb, "Body offset", good.BodyOffset, bad.BodyOffset);
        AddHex(sb, "Body size", good.BodySize, bad.BodySize);
        AddHex(sb, "PFS/content offset", good.ContentOffset, bad.ContentOffset);
        AddHex(sb, "PFS/content size", good.ContentSize, bad.ContentSize);
        Add(sb, "64K content blocks", good.ContentBlocks64K, bad.ContentBlocks64K);

        sb.AppendLine();
        sb.AppendLine("[PlayGo]");
        if (good.PlayGo is null || bad.PlayGo is null)
            sb.AppendLine($"Present: good={good.PlayGo is not null}, bad={bad.PlayGo is not null}");
        else
        {
            AddHex(sb,"chunk.dat size",good.PlayGo.DataSize,bad.PlayGo.DataSize);
            Add(sb,"image count",good.PlayGo.ImageCount,bad.PlayGo.ImageCount);
            Add(sb,"chunk count",good.PlayGo.ChunkCount,bad.PlayGo.ChunkCount);
            Add(sb,"scenario count",good.PlayGo.ScenarioCount,bad.PlayGo.ScenarioCount);
            Add(sb,"package size field",good.PlayGo.PackageSizeField,bad.PlayGo.PackageSizeField);
            Add(sb,"inner PFS size field",good.PlayGo.InnerPfsSizeField,bad.PlayGo.InnerPfsSizeField);
            Add(sb,"chunk.sha size",good.PlayGo.ChunkShaSize,bad.PlayGo.ChunkShaSize);
        }

        sb.AppendLine();
        sb.AppendLine("[Outer PFS]");
        if (good.OuterPfs is null || bad.OuterPfs is null)
            sb.AppendLine($"Present: good={good.OuterPfs is not null}, bad={bad.OuterPfs is not null}");
        else
        {
            Add(sb,"block size",good.OuterPfs.BlockSize,bad.OuterPfs.BlockSize);
            Add(sb,"block count",good.OuterPfs.BlockCount,bad.OuterPfs.BlockCount);
            Add(sb,"inode count",good.OuterPfs.InodeCount,bad.OuterPfs.InodeCount);
            Add(sb,"inode blocks",good.OuterPfs.InodeBlockCount,bad.OuterPfs.InodeBlockCount);
            Add(sb,"declared image bytes",good.OuterPfs.DeclaredImageBytes,bad.OuterPfs.DeclaredImageBytes);
            Add(sb,"available image bytes",good.OuterPfs.AvailableBytes,bad.OuterPfs.AvailableBytes);
        }

        sb.AppendLine();
        sb.AppendLine("[Entry IDs]");
        var goodIds = good.Entries.Select(x=>x.Id).ToHashSet();
        var badIds = bad.Entries.Select(x=>x.Id).ToHashSet();
        foreach (var id in goodIds.Union(badIds).Order())
        {
            var g = good.Entries.FirstOrDefault(x=>x.Id==id);
            var b = bad.Entries.FirstOrDefault(x=>x.Id==id);
            if (g is null || b is null || g.DataSize != b.DataSize || g.Flags1 != b.Flags1 || g.Flags2 != b.Flags2)
                sb.AppendLine($"0x{id:X8}: good={FormatEntry(g)} | bad={FormatEntry(b)}");
        }

        return sb.ToString();
    }

    private static string FormatEntry(PkgEntryReport? e) =>
        e is null ? "missing" : $"off=0x{e.DataOffset:X}, size=0x{e.DataSize:X}, f1=0x{e.Flags1:X8}, f2=0x{e.Flags2:X8}, name={e.Name ?? "-"}";

    private static void Add(System.Text.StringBuilder sb,string name,object a,object b)=>
        sb.AppendLine($"{name,-24} GOOD={a,-16} BAD={b,-16} {(Equals(a,b)?"MATCH":"DIFF")}");

    private static void AddHex(System.Text.StringBuilder sb,string name,uint a,uint b)=>
        sb.AppendLine($"{name,-24} GOOD=0x{a:X} BAD=0x{b:X} {(a==b?"MATCH":"DIFF")}");

    private static void AddHex(System.Text.StringBuilder sb,string name,ulong a,ulong b)=>
        sb.AppendLine($"{name,-24} GOOD=0x{a:X} BAD=0x{b:X} {(a==b?"MATCH":"DIFF")}");
}
