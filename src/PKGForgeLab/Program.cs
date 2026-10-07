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
        File.WriteAllText(outPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
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


public sealed record PkgReport(
    string Path,
    long FileSize,
    string Sha256,
    uint Magic,
    uint EntryCount,
    uint EntryTableOffset,
    uint MainEntryDataSize,
    ulong BodyOffset,
    ulong BodySize,
    ulong ContentOffset,
    ulong ContentSize,
    ulong PackageSize,
    ulong MetadataSpan,
    ulong ContentBlocks64K,
    IReadOnlyList<PkgEntryReport> Entries,
    IReadOnlyList<SfoEntryReport> ParamSfo,
    PlayGoReport? PlayGo,
    OuterPfsReport? OuterPfs,
    InnerPfsReport? InnerPfs);

public sealed record PkgEntryReport(
    uint Id,
    uint NameOffset,
    uint Flags1,
    uint Flags2,
    uint DataOffset,
    uint DataSize,
    string? Name);

public sealed record SfoEntryReport(
    string Key,
    ushort Format,
    uint Length,
    uint MaxLength,
    string Value);

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
    long NBlock,
    long InodeCount,
    long DataBlockCount,
    long InodeBlockCount,
    ulong DataImageBytes);

public sealed record InnerPfsReport(
    string Status,
    long? LogicalSize,
    IReadOnlyList<InnerFileReport> Files,
    IReadOnlyList<TocFileReport> TocFiles);

public sealed record InnerFileReport(
    string Path,
    long Size,
    string Sha256);

public sealed record TocFileReport(
    string Path,
    long Size,
    string Sha256,
    string Hex,
    IReadOnlyList<TocRecordReport> Records);

public sealed record TocRecordReport(
    int Index,
    string Kind,
    string Hex,
    string AdrControl,
    string Point,
    string PMinSecFrame,
    string AMinSecFrame);

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
        var mainEntryDataSize = BE32(header, 0x1C);
        var bodyOffset = BE64(header, 0x20);
        var bodySize = BE64(header, 0x28);
        var contentOffset = BE64(header, 0x410);
        var contentSize = BE64(header, 0x418);
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

        var paramSfo = Array.Empty<SfoEntryReport>();
        var sfoEntry = entries.FirstOrDefault(x => x.Id == 0x00001000);
        if (sfoEntry is not null && sfoEntry.DataSize >= 0x14 &&
            (ulong)sfoEntry.DataOffset + sfoEntry.DataSize <= (ulong)fs.Length)
            paramSfo = ParseSfo(ReadExact(fs, sfoEntry.DataOffset, checked((int)sfoEntry.DataSize)));

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
            var nBlock = LE64S(b, 0x28);
            var dataBlockCount = LE64S(b, 0x38);
            ulong dataImageBytes = 0;
            if (blockSize > 0 && dataBlockCount > 0)
                dataImageBytes = checked((ulong)blockSize * (ulong)dataBlockCount);
            outer = new OuterPfsReport(
                contentOffset,
                (ulong)fs.Length - contentOffset,
                LE64S(b, 0x00),
                LE64S(b, 0x08),
                b[0x1A],
                LE16(b, 0x1C),
                blockSize,
                nBlock,
                LE64S(b, 0x30),
                dataBlockCount,
                LE64S(b, 0x40),
                dataImageBytes);
        }

        InnerPfsReport? inner = null;
        try
        {
            var contentId = paramSfo.FirstOrDefault(x => x.Key == "CONTENT_ID")?.Value;
            if (outer is not null && !string.IsNullOrWhiteSpace(contentId))
                inner = InspectInnerPfs(fs, outer, contentId);
        }
        catch (Exception ex)
        {
            inner = new InnerPfsReport("ERROR: " + ex.Message, null, [], []);
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
            mainEntryDataSize,
            bodyOffset,
            bodySize,
            contentOffset,
            contentSize,
            packageSize,
            contentOffset >= bodyOffset ? contentOffset - bodyOffset : 0,
            contentSize / 0x10000,
            entries,
            paramSfo,
            playGo,
            outer,
            inner);
    }

    private static InnerPfsReport InspectInnerPfs(FileStream pkg, OuterPfsReport outer, string contentId)
    {
        const string passcode = "00000000000000000000000000000000";
        const int blockSize = 0x10000;
        const int sectorSize = 0x1000;

        if (outer.BlockSize != blockSize)
            return new InnerPfsReport($"UNSUPPORTED outer block size 0x{outer.BlockSize:X}", null, [], []);

        var image = ReadExact(pkg, checked((long)outer.FileOffset), checked((int)outer.AvailableBytes));
        var seed = image.AsSpan(0x370, 16).ToArray();
        var ekpfs = ComputeKey(contentId, passcode, 1);
        var k = PfsCryptoKey(ekpfs, seed, 1);
        var tweakKey = k[..16];
        var dataKey = k[16..32];

        DecryptOuter(image, dataKey, tweakKey, blockSize, sectorSize, sectorBase: 0);

        if (LE64S(image, 0x08) != 20130315)
            return new InnerPfsReport("OUTER_DECRYPT_FAILED: header magic mismatch", null, [], []);

        const int signedInodeSize = 0x2C8;
        var fileInode = blockSize + 3 * signedInodeSize;
        if (fileInode + signedInodeSize > image.Length)
            return new InnerPfsReport("OUTER_DECRYPT_FAILED: pfs_image inode is out of range", null, [], []);

        var flags = LE32(image, fileInode + 4);
        var storedSize = LE64S(image, fileInode + 8);
        var logicalSize = LE64S(image, fileInode + 16);
        var firstBlock = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(fileInode + 132, 4));

        // Reference packages produced by other toolchains can use a different XTS
        // sector-number base. If the Ps1Forge convention yields an impossible inode,
        // probe common bases and accept only a structurally valid pfs_image.dat inode.
        if (!ValidOuterExtent(flags, storedSize, logicalSize, firstBlock, image.Length, blockSize))
        {
            var encrypted = ReadExact(pkg, checked((long)outer.FileOffset), checked((int)outer.AvailableBytes));
            var candidates = new List<string>();
            foreach (var baseSector in new ulong[] { 0, (ulong)outer.FileOffset / (ulong)sectorSize })
            foreach (var keyIndex in new uint[] { 1, 2, 0 })
            {
                var trial = (byte[])encrypted.Clone();
                var trialEkpfs = ComputeKey(contentId, passcode, keyIndex == 0 ? 1u : keyIndex);
                var trialK = PfsCryptoKey(trialEkpfs, seed, 1);
                DecryptOuter(trial, trialK[16..32], trialK[..16], blockSize, sectorSize, baseSector);
                var tf = LE32(trial, fileInode + 4);
                var ts = LE64S(trial, fileInode + 8);
                var tl = LE64S(trial, fileInode + 16);
                var tb = BinaryPrimitives.ReadInt32LittleEndian(trial.AsSpan(fileInode + 132, 4));
                candidates.Add($"base={baseSector},key={keyIndex}:flags=0x{tf:X},stored={ts},logical={tl},first={tb}");
                if (ValidOuterExtent(tf, ts, tl, tb, trial.Length, blockSize))
                {
                    image = trial; flags = tf; storedSize = ts; logicalSize = tl; firstBlock = tb;
                    break;
                }
            }
            if (!ValidOuterExtent(flags, storedSize, logicalSize, firstBlock, image.Length, blockSize))
                return new InnerPfsReport("OUTER_DECRYPT_FAILED: no valid pfs_image inode; " + string.Join(" | ", candidates), logicalSize, [], []);
        }
        if ((flags & 1) == 0)
            return new InnerPfsReport("OUTER_DECRYPT_FAILED: pfs_image.dat is not marked compressed/PFSC", logicalSize, [], []);
        if (storedSize <= 0 || firstBlock <= 0 || (long)firstBlock * blockSize + storedSize > image.Length)
            return new InnerPfsReport("OUTER_DECRYPT_FAILED: invalid pfs_image.dat extent", logicalSize, [], []);

        var pfsc = image.AsSpan(firstBlock * blockSize, checked((int)storedSize)).ToArray();
        var inner = UnwrapPfsc(pfsc, logicalSize);
        var files = ParseInnerPfsFiles(inner);
        var toc = files.Where(x => x.Path.EndsWith(".toc", StringComparison.OrdinalIgnoreCase))
            .Select(x =>
            {
                var data = ReadInnerFile(inner, x);
                return new TocFileReport(
                    x.Path,
                    x.Size,
                    Convert.ToHexString(SHA256.HashData(data)),
                    Convert.ToHexString(data),
                    DecodeToc(data));
            }).ToArray();

        return new InnerPfsReport("OK", logicalSize, files.Select(x => new InnerFileReport(
            x.Path, x.Size, Convert.ToHexString(SHA256.HashData(ReadInnerFile(inner, x))))).ToArray(), toc);
    }

    private sealed record InnerNode(string Path, long Size, int StartBlock);

    private static bool ValidOuterExtent(uint flags, long storedSize, long logicalSize, int firstBlock, int imageLength, int blockSize) =>
        (flags & 1) != 0 && storedSize > 0 && logicalSize > 0 && logicalSize < int.MaxValue &&
        firstBlock > 0 && (long)firstBlock * blockSize + storedSize <= imageLength;

    private static void DecryptOuter(byte[] image, byte[] dataKey, byte[] tweakKey, int blockSize, int sectorSize, ulong sectorBase)
    {
        for (var sectorNo = blockSize / sectorSize; sectorNo * sectorSize < image.Length; sectorNo++)
        {
            var blockNo = sectorNo / (blockSize / sectorSize);
            if (blockNo == 4) continue;
            AesXtsDecryptSectorInPlace(image.AsSpan(sectorNo * sectorSize, sectorSize), dataKey, tweakKey, sectorBase + (ulong)sectorNo);
        }
    }

    private static byte[] UnwrapPfsc(byte[] pfsc, long logicalSize)
    {
        if (pfsc.Length < 0x10000 || BinaryPrimitives.ReadUInt32BigEndian(pfsc.AsSpan(0,4)) != 0x50465343)
            throw new InvalidDataException("pfs_image.dat is not PFSC.");
        var blockSize = BinaryPrimitives.ReadInt32LittleEndian(pfsc.AsSpan(12,4));
        var tableOffset = BinaryPrimitives.ReadInt64LittleEndian(pfsc.AsSpan(24,8));
        var dataOffset = BinaryPrimitives.ReadInt64LittleEndian(pfsc.AsSpan(32,8));
        var logical = BinaryPrimitives.ReadInt64LittleEndian(pfsc.AsSpan(40,8));
        if (blockSize != 0x10000 || tableOffset < 0 || dataOffset <= tableOffset || dataOffset > pfsc.Length)
            throw new InvalidDataException("Unsupported PFSC geometry.");
        var blockCount = (logical + blockSize - 1) / blockSize;
        var result = new byte[checked((int)Math.Min(logicalSize > 0 ? logicalSize : logical, int.MaxValue))];

        for (var i = 0L; i < blockCount; i++)
        {
            var p0o = checked((int)(tableOffset + i * 8));
            var p1o = checked((int)(tableOffset + (i + 1) * 8));
            if (p1o + 8 > pfsc.Length) throw new InvalidDataException("PFSC seek table truncated.");
            var p0 = BinaryPrimitives.ReadInt64LittleEndian(pfsc.AsSpan(p0o,8));
            var p1 = BinaryPrimitives.ReadInt64LittleEndian(pfsc.AsSpan(p1o,8));
            if (p0 < dataOffset || p1 < p0 || p1 > pfsc.Length) throw new InvalidDataException("PFSC seek entry invalid.");
            var stored = pfsc.AsSpan(checked((int)p0), checked((int)(p1-p0))).ToArray();
            byte[] block;
            if (stored.Length == blockSize) block = stored;
            else
            {
                using var ms = new MemoryStream(stored);
                using var z = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionMode.Decompress);
                block = new byte[blockSize];
                var read = 0;
                while (read < block.Length)
                {
                    var n = z.Read(block, read, block.Length - read);
                    if (n == 0) break;
                    read += n;
                }
            }
            var dst = checked((int)(i * blockSize));
            if (dst >= result.Length) break;
            Buffer.BlockCopy(block, 0, result, dst, Math.Min(block.Length, result.Length - dst));
        }
        return result;
    }

    private static InnerNode[] ParseInnerPfsFiles(byte[] pfs)
    {
        const int blockSize = 0x10000;
        if (pfs.Length < blockSize || LE64S(pfs, 8) != 20130315)
            throw new InvalidDataException("Inner PFS header magic mismatch.");
        var inodeCount = checked((int)LE64S(pfs, 0x30));
        if (inodeCount < 3 || inodeCount > 65536) throw new InvalidDataException("Inner PFS inode count is implausible.");

        var result = new List<InnerNode>();
        WalkInnerDir(pfs, 2, "", inodeCount, result, new HashSet<uint>());
        return result.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();

        static void WalkInnerDir(byte[] pfs, uint inode, string prefix, int inodeCount, List<InnerNode> result, HashSet<uint> visited)
        {
            if (!visited.Add(inode)) return;
            var d = ReadInnerInode(pfs, inode, inodeCount);
            var start = d.StartBlock * blockSize;
            var end = Math.Min((long)pfs.Length, start + d.Size);
            var pos = start;
            while (pos + 16 <= end)
            {
                var ino = BinaryPrimitives.ReadUInt32LittleEndian(pfs.AsSpan(checked((int)pos),4));
                var type = BinaryPrimitives.ReadInt32LittleEndian(pfs.AsSpan(checked((int)pos+4),4));
                var nameLen = BinaryPrimitives.ReadInt32LittleEndian(pfs.AsSpan(checked((int)pos+8),4));
                var entSize = BinaryPrimitives.ReadInt32LittleEndian(pfs.AsSpan(checked((int)pos+12),4));
                if (entSize <= 0 || pos + entSize > end || nameLen < 0 || nameLen > entSize - 16) break;
                var name = System.Text.Encoding.UTF8.GetString(pfs, checked((int)pos + 16), nameLen);
                pos += entSize;
                if (name is "." or ".." || ino >= inodeCount) continue;
                var child = ReadInnerInode(pfs, ino, inodeCount);
                var path = string.IsNullOrEmpty(prefix) ? "/" + name : prefix + "/" + name;
                if ((child.Mode & 0x4000) != 0) WalkInnerDir(pfs, ino, path, inodeCount, result, visited);
                else if ((child.Mode & 0x8000) != 0) result.Add(new InnerNode(path, child.Size, child.StartBlock));
            }
        }
    }

    private readonly record struct InnerInode(ushort Mode, long Size, int StartBlock);
    private static InnerInode ReadInnerInode(byte[] pfs, uint inode, int inodeCount)
    {
        const int blockSize = 0x10000;
        const int inodeSize = 0xA8;
        if (inode >= inodeCount) throw new InvalidDataException("Inner inode out of range.");
        var off = blockSize + checked((int)inode) * inodeSize;
        if (off + inodeSize > pfs.Length) throw new InvalidDataException("Inner inode table truncated.");
        return new InnerInode(
            BinaryPrimitives.ReadUInt16LittleEndian(pfs.AsSpan(off,2)),
            BinaryPrimitives.ReadInt64LittleEndian(pfs.AsSpan(off+8,8)),
            BinaryPrimitives.ReadInt32LittleEndian(pfs.AsSpan(off+100,4)));
    }

    private static byte[] ReadInnerFile(byte[] pfs, InnerNode n)
    {
        const int blockSize = 0x10000;
        var off = checked((long)n.StartBlock * blockSize);
        if (off < 0 || n.Size < 0 || off + n.Size > pfs.Length) throw new InvalidDataException($"Inner file extent invalid: {n.Path}");
        return pfs.AsSpan(checked((int)off), checked((int)n.Size)).ToArray();
    }

    private static TocRecordReport[] DecodeToc(byte[] data)
    {
        var records = new List<TocRecordReport>();
        for (var o = 0; o + 10 <= data.Length; o += 10)
        {
            var s = data.AsSpan(o,10);
            var point = s[2];
            var kind = point switch { 0xA0 => "A0", 0xA1 => "A1", 0xA2 => "A2", _ => $"TRACK {BcdToInt(point):00}" };
            records.Add(new TocRecordReport(
                o / 10,
                kind,
                Convert.ToHexString(s),
                $"0x{s[0]:X2}",
                $"0x{point:X2}",
                $"{BcdToInt(s[3]):00}:{BcdToInt(s[4]):00}:{BcdToInt(s[5]):00}",
                $"{BcdToInt(s[7]):00}:{BcdToInt(s[8]):00}:{BcdToInt(s[9]):00}"));
        }
        return records.ToArray();
    }

    private static int BcdToInt(byte b) => ((b >> 4) & 0xF) * 10 + (b & 0xF);

    private static byte[] ComputeKey(string contentId, string passcode, uint index)
    {
        Span<byte> idx = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(idx, index);
        var data = new byte[96];
        SHA256.HashData(idx).CopyTo(data,0);
        var padded = new byte[48];
        System.Text.Encoding.ASCII.GetBytes(contentId).CopyTo(padded,0);
        SHA256.HashData(padded).CopyTo(data,32);
        System.Text.Encoding.ASCII.GetBytes(passcode).CopyTo(data,64);
        return SHA256.HashData(data);
    }

    private static byte[] PfsCryptoKey(byte[] ekpfs, byte[] seed, uint index)
    {
        var d = new byte[4 + seed.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(d, index);
        seed.CopyTo(d,4);
        using var h = new HMACSHA256(ekpfs);
        return h.ComputeHash(d);
    }

    private static void AesXtsDecryptSectorInPlace(Span<byte> sector, byte[] dataKey, byte[] tweakKey, ulong sectorNumber)
    {
        using var dataAes = Aes.Create();
        dataAes.Key = dataKey; dataAes.Mode = CipherMode.ECB; dataAes.Padding = PaddingMode.None;
        using var tweakAes = Aes.Create();
        tweakAes.Key = tweakKey; tweakAes.Mode = CipherMode.ECB; tweakAes.Padding = PaddingMode.None;
        using var dataDec = dataAes.CreateDecryptor();
        using var tweakEnc = tweakAes.CreateEncryptor();

        var tweakInput = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(tweakInput, sectorNumber);
        var tweak = new byte[16];
        tweakEnc.TransformBlock(tweakInput,0,16,tweak,0);
        var block = new byte[16];
        var plain = new byte[16];
        for (var off = 0; off < sector.Length; off += 16)
        {
            for (var i=0;i<16;i++) block[i]=(byte)(sector[off+i]^tweak[i]);
            dataDec.TransformBlock(block,0,16,plain,0);
            for (var i=0;i<16;i++) sector[off+i]=(byte)(plain[i]^tweak[i]);
            byte feedback = 0;
            for (var i=0;i<16;i++)
            {
                var value=tweak[i];
                tweak[i]=(byte)((value<<1)|feedback);
                feedback=(byte)(value>>7);
            }
            if (feedback!=0) tweak[0]^=0x87;
        }
    }

    private static SfoEntryReport[] ParseSfo(byte[] b)
    {
        if (b.Length < 0x14 || LE32(b, 0) != 0x46535000)
            return [];
        var keyTable = checked((int)LE32(b, 0x08));
        var dataTable = checked((int)LE32(b, 0x0C));
        var count = checked((int)LE32(b, 0x10));
        if (count < 0 || count > 1024) return [];
        var result = new List<SfoEntryReport>(count);
        for (var i = 0; i < count; i++)
        {
            var o = 0x14 + i * 0x10;
            if (o + 0x10 > b.Length) break;
            var keyOff = LE16(b, o);
            var format = LE16(b, o + 2);
            var len = LE32(b, o + 4);
            var max = LE32(b, o + 8);
            var dataOff = LE32(b, o + 12);
            var ks = keyTable + keyOff;
            if (ks < 0 || ks >= b.Length) continue;
            var ke = Array.IndexOf(b, (byte)0, ks);
            if (ke < 0) continue;
            var key = System.Text.Encoding.UTF8.GetString(b, ks, ke - ks);
            var ds = (long)dataTable + dataOff;
            if (ds < 0 || ds + len > b.Length) continue;
            string value;
            if (format == 0x0404 && len == 4)
                value = $"0x{LE32(b, checked((int)ds)):X8}";
            else
            {
                var n = checked((int)len);
                if (n > 0 && b[checked((int)ds) + n - 1] == 0) n--;
                value = System.Text.Encoding.UTF8.GetString(b, checked((int)ds), n);
            }
            result.Add(new SfoEntryReport(key, format, len, max, value));
        }
        return result.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray();
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
        AddHex(sb, "Main entry data size", good.MainEntryDataSize, bad.MainEntryDataSize);
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
            Add(sb,"nblock",good.OuterPfs.NBlock,bad.OuterPfs.NBlock);
            Add(sb,"inode count",good.OuterPfs.InodeCount,bad.OuterPfs.InodeCount);
            Add(sb,"data block count",good.OuterPfs.DataBlockCount,bad.OuterPfs.DataBlockCount);
            Add(sb,"inode blocks",good.OuterPfs.InodeBlockCount,bad.OuterPfs.InodeBlockCount);
            Add(sb,"data image bytes",good.OuterPfs.DataImageBytes,bad.OuterPfs.DataImageBytes);
            Add(sb,"available image bytes",good.OuterPfs.AvailableBytes,bad.OuterPfs.AvailableBytes);
        }

        sb.AppendLine();
        sb.AppendLine("[Inner PFS]");
        sb.AppendLine($"status: good={good.InnerPfs?.Status ?? "missing"} | bad={bad.InnerPfs?.Status ?? "missing"}");
        if (good.InnerPfs is not null && bad.InnerPfs is not null)
        {
            sb.AppendLine($"{"logical size",-24} GOOD={good.InnerPfs.LogicalSize?.ToString() ?? "null",-16} BAD={bad.InnerPfs.LogicalSize?.ToString() ?? "null",-16} {(good.InnerPfs.LogicalSize==bad.InnerPfs.LogicalSize?"MATCH":"DIFF")}");
            var paths = good.InnerPfs.Files.Select(x=>x.Path).Union(bad.InnerPfs.Files.Select(x=>x.Path)).Order(StringComparer.Ordinal);
            foreach (var path in paths)
            {
                var g = good.InnerPfs.Files.FirstOrDefault(x=>x.Path==path);
                var b = bad.InnerPfs.Files.FirstOrDefault(x=>x.Path==path);
                if (g is null || b is null || g.Size != b.Size || g.Sha256 != b.Sha256)
                    sb.AppendLine($"{path}: good={FormatInner(g)} | bad={FormatInner(b)}");
            }

            sb.AppendLine();
            sb.AppendLine("[TOC]");
            var tocPaths = good.InnerPfs.TocFiles.Select(x=>x.Path).Union(bad.InnerPfs.TocFiles.Select(x=>x.Path)).Order(StringComparer.Ordinal);
            foreach (var path in tocPaths)
            {
                var g = good.InnerPfs.TocFiles.FirstOrDefault(x=>x.Path==path);
                var b = bad.InnerPfs.TocFiles.FirstOrDefault(x=>x.Path==path);
                sb.AppendLine($"{path}: good={FormatToc(g)} | bad={FormatToc(b)}");
                if (g is not null) foreach (var r in g.Records) sb.AppendLine($"  GOOD [{r.Index:00}] {r.Kind,-8} {r.Hex} ADR/CTRL={r.AdrControl} P={r.PMinSecFrame} A={r.AMinSecFrame}");
                if (b is not null) foreach (var r in b.Records) sb.AppendLine($"  BAD  [{r.Index:00}] {r.Kind,-8} {r.Hex} ADR/CTRL={r.AdrControl} P={r.PMinSecFrame} A={r.AMinSecFrame}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("[param.sfo]");
        var sfoKeys = good.ParamSfo.Select(x => x.Key).Union(bad.ParamSfo.Select(x => x.Key)).Order(StringComparer.Ordinal);
        foreach (var key in sfoKeys)
        {
            var g = good.ParamSfo.FirstOrDefault(x => x.Key == key);
            var b = bad.ParamSfo.FirstOrDefault(x => x.Key == key);
            if (g is null || b is null || g.Format != b.Format || g.Length != b.Length || g.MaxLength != b.MaxLength || g.Value != b.Value)
                sb.AppendLine($"{key}: good={FormatSfo(g)} | bad={FormatSfo(b)}");
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

    private static string FormatSfo(SfoEntryReport? e) =>
        e is null ? "missing" : $"fmt=0x{e.Format:X4}, len={e.Length}, max={e.MaxLength}, value={e.Value}";

    private static string FormatEntry(PkgEntryReport? e) =>
        e is null ? "missing" : $"off=0x{e.DataOffset:X}, size=0x{e.DataSize:X}, f1=0x{e.Flags1:X8}, f2=0x{e.Flags2:X8}, name={e.Name ?? "-"}";

    private static string FormatInner(InnerFileReport? e) =>
        e is null ? "missing" : $"size={e.Size}, sha256={e.Sha256}";

    private static string FormatToc(TocFileReport? e) =>
        e is null ? "missing" : $"size={e.Size}, sha256={e.Sha256}, hex={e.Hex}";

    private static void Add(System.Text.StringBuilder sb,string name,object a,object b)=>
        sb.AppendLine($"{name,-24} GOOD={a,-16} BAD={b,-16} {(Equals(a,b)?"MATCH":"DIFF")}");

    private static void AddHex(System.Text.StringBuilder sb,string name,uint a,uint b)=>
        sb.AppendLine($"{name,-24} GOOD=0x{a:X} BAD=0x{b:X} {(a==b?"MATCH":"DIFF")}");

    private static void AddHex(System.Text.StringBuilder sb,string name,ulong a,ulong b)=>
        sb.AppendLine($"{name,-24} GOOD=0x{a:X} BAD=0x{b:X} {(a==b?"MATCH":"DIFF")}");
}
