using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

public static class EntryIntegrityAudit
{
    private sealed record E(uint Id,uint NameOffset,uint Flags1,uint Flags2,uint Offset,uint Size,byte[] Meta)
    {
        public uint StoredSize => (Flags1 & 0x80000000u) != 0 ? (Size + 15u) & ~15u : Size;
    }

    public static string Compare(string goodPath,string badPath)
    {
        var g=Inspect(goodPath); var b=Inspect(badPath);
        var sb=new StringBuilder();
        sb.AppendLine("[NPDRM entry integrity]");
        sb.AppendLine("Digest status is checked two ways: logical DataSize and encrypted 16-byte StoredSize.");
        sb.AppendLine("A reference-only PASS identifies the convention used by the known-working package.");
        foreach(var id in g.Keys.Union(b.Keys).Order())
        {
            g.TryGetValue(id,out var ge); b.TryGetValue(id,out var be);
            if(ge is null||be is null){sb.AppendLine($"0x{id:X8}: GOOD={(ge is null?"missing":"present")} BAD={(be is null?"missing":"present")}");continue;}
            var metaSame=ge.MetaHex==be.MetaHex;
            var rawSame=ge.RawSha==be.RawSha;
            sb.AppendLine($"0x{id:X8} meta={(metaSame?"MATCH":"DIFF")} raw={(rawSame?"MATCH":"DIFF")} | GOOD digest(logical/stored)={ge.LogicalDigestOk}/{ge.StoredDigestOk} | BAD={be.LogicalDigestOk}/{be.StoredDigestOk}");
            if(!metaSame) sb.AppendLine($"  META GOOD={ge.MetaHex}\n  META BAD ={be.MetaHex}");
            sb.AppendLine($"  GOOD off=0x{ge.Offset:X} size=0x{ge.Size:X} stored=0x{ge.StoredSize:X} f1=0x{ge.Flags1:X8} f2=0x{ge.Flags2:X8} rawsha={ge.RawSha}");
            sb.AppendLine($"  BAD  off=0x{be.Offset:X} size=0x{be.Size:X} stored=0x{be.StoredSize:X} f1=0x{be.Flags1:X8} f2=0x{be.Flags2:X8} rawsha={be.RawSha}");
            if(ge.ExpectedDigest!=be.ExpectedDigest || ge.ActualLogicalDigest!=be.ActualLogicalDigest)
                sb.AppendLine($"  DIGEST GOOD expected={ge.ExpectedDigest} actual={ge.ActualLogicalDigest}\n  DIGEST BAD  expected={be.ExpectedDigest} actual={be.ActualLogicalDigest}");
        }
        return sb.ToString();
    }

    private sealed record A(uint Id,uint Offset,uint Size,uint StoredSize,uint Flags1,uint Flags2,string MetaHex,string RawSha,string ExpectedDigest,string ActualLogicalDigest,bool LogicalDigestOk,bool StoredDigestOk);

    private static Dictionary<uint,A> Inspect(string path)
    {
        using var fs=File.OpenRead(path);
        var h=Read(fs,0,0x1000);
        var count=BE32(h,0x10); var tableOff=BE32(h,0x18);
        var table=Read(fs,tableOff,checked((int)count*32));
        var es=new List<E>();
        for(int i=0;i<count;i++)
        {
            var m=table.AsSpan(i*32,32).ToArray();
            es.Add(new E(BE32(m,0),BE32(m,4),BE32(m,8),BE32(m,12),BE32(m,16),BE32(m,20),m));
        }
        var sorted=es.OrderBy(x=>x.Id).ToArray();
        var de=sorted.FirstOrDefault(x=>x.Id==1);
        byte[] digestTable=de is null?[]:Read(fs,de.Offset,checked((int)de.Size));
        var result=new Dictionary<uint,A>();
        for(int i=0;i<sorted.Length;i++)
        {
            var e=sorted[i];
            if((ulong)e.Offset+e.StoredSize>(ulong)fs.Length) continue;
            var logical=Read(fs,e.Offset,checked((int)e.Size));
            var stored=Read(fs,e.Offset,checked((int)e.StoredSize));
            var ld=SHA256.HashData(logical); var sd=SHA256.HashData(stored);
            var expected=digestTable.Length>=(i+1)*32?digestTable.AsSpan(i*32,32).ToArray():[];
            result[e.Id]=new A(e.Id,e.Offset,e.Size,e.StoredSize,e.Flags1,e.Flags2,Convert.ToHexString(e.Meta),Convert.ToHexString(SHA256.HashData(stored)),Convert.ToHexString(expected),Convert.ToHexString(ld),expected.Length==32&&expected.SequenceEqual(ld),expected.Length==32&&expected.SequenceEqual(sd));
        }
        return result;
    }
    private static byte[] Read(FileStream fs,long off,int len){var b=new byte[len];fs.Position=off;fs.ReadExactly(b);return b;}
    private static uint BE32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o,4));
}
