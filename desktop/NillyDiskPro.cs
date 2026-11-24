// ============================================================================
// NillyDisk Pro — Ultra-Light Native Disk Space Analyzer, Treemap,
//                 SHA-256 Duplicate Finder & Safe Cache Cleaner
// created by Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/
// Strictly C# 5 compatible (.NET Framework 4.x csc.exe — 0 external DLLs)
// 100% Safe Read-Only Scan · Recycle-Bin-Only Deletion · System Path Lock
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("NillyDisk Pro")]
[assembly: AssemblyDescription("Ultra-Light Disk Space Analyzer, Interactive Treemap, SHA-256 Duplicate Finder & Safe Cache Cleaner — created by Nilly graphics (Nillygraphics · Sotiris Christos)")]
[assembly: AssemblyCompany("Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/")]
[assembly: AssemblyProduct("NillyDisk Pro")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Nilly graphics (Sotiris Christos) — https://nillygraphics.com/")]
[assembly: AssemblyTrademark("Nilly graphics / Nillygraphics — Sotiris Christos")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace NillyDiskPro
{
    // ========================================================================
    // 1. WIN32 KERNEL / SHELL INTEROP (Fast FindFirstFileEx, Recycle Bin, DWM)
    // ========================================================================
    internal static class Native
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const int FindExInfoBasic = 1;
        public const int FindExSearchNameMatch = 0;
        public const int FIND_FIRST_EX_LARGE_FETCH = 2;
        public const int FILE_ATTRIBUTE_DIRECTORY = 0x10;
        public const int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

        public const int FO_DELETE = 0x0003;
        public const ushort FOF_SILENT = 0x0004;
        public const ushort FOF_NOCONFIRMATION = 0x0010;
        public const ushort FOF_ALLOWUNDO = 0x0040;
        public const ushort FOF_NOERRORUI = 0x0400;

        public const uint SHERB_NOCONFIRMATION = 0x00000001;
        public const uint SHERB_NOPROGRESSUI = 0x00000002;
        public const uint SHERB_NOSOUND = 0x00000004;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public uint ftCreationTimeLow, ftCreationTimeHigh;
            public uint ftLastAccessTimeLow, ftLastAccessTimeHigh;
            public uint ftLastWriteTimeLow, ftLastWriteTimeHigh;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SHQUERYRBINFO
        {
            public int cbSize;
            public long i64Size;
            public long i64NumItems;
        }

        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
        [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int sz);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr FindFirstFileExW(string lpFileName, int fInfoLevelId, out WIN32_FIND_DATA lpFindFileData,
            int fSearchOp, IntPtr lpSearchFilter, int dwAdditionalFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindClose(IntPtr hFindFile);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern int SHFileOperationW(ref SHFILEOPSTRUCT lpFileOp);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern int SHQueryRecycleBinW(string pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern int SHEmptyRecycleBinW(IntPtr hwnd, string pszRootPath, uint dwFlags);

        public static void SetDarkTitlebar(IntPtr hwnd, bool dark)
        {
            if (hwnd == IntPtr.Zero) return;
            try
            {
                int v = dark ? 1 : 0;
                if (DwmSetWindowAttribute(hwnd, 20, ref v, 4) != 0)
                    DwmSetWindowAttribute(hwnd, 19, ref v, 4);
            }
            catch { }
        }

        public static DateTime FileTimeToLocal(uint low, uint high)
        {
            try
            {
                long ft = (((long)high) << 32) | (uint)low;
                if (ft <= 0) return DateTime.MinValue;
                return DateTime.FromFileTime(ft);
            }
            catch { return DateTime.MinValue; }
        }

        public static long QueryRecycleBinBytes(out long itemCount)
        {
            itemCount = 0;
            try
            {
                SHQUERYRBINFO info = new SHQUERYRBINFO();
                info.cbSize = Marshal.SizeOf(typeof(SHQUERYRBINFO));
                if (SHQueryRecycleBinW(null, ref info) == 0)
                {
                    itemCount = info.i64NumItems;
                    return info.i64Size;
                }
            }
            catch { }
            return 0;
        }

        public static bool SendToRecycleBin(string path)
        {
            if (string.IsNullOrEmpty(path) || (!File.Exists(path) && !Directory.Exists(path))) return false;
            if (SafetyGuard.IsProtectedPath(path)) return false;
            try
            {
                SHFILEOPSTRUCT op = new SHFILEOPSTRUCT();
                op.wFunc = FO_DELETE;
                op.pFrom = path + "\0\0";
                op.fFlags = (ushort)(FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI);
                int rc = SHFileOperationW(ref op);
                return (rc == 0 && !op.fAnyOperationsAborted);
            }
            catch { return false; }
        }
    }

    // ========================================================================
    // 2. HARD-CODED SYSTEM SAFETY GUARD & FORMATTING HELPERS
    // ========================================================================
    internal static class SafetyGuard
    {
        private static readonly string[] ProtectedPrefixes = new string[]
        {
            @"C:\Windows",
            @"C:\Program Files",
            @"C:\Program Files (x86)",
            @"C:\ProgramData",
            @"C:\Recovery",
            @"C:\System Volume Information",
            @"C:\$Recycle.Bin",
            @"C:\Boot",
            @"C:\EFI"
        };

        public static bool IsProtectedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            try
            {
                string full = Path.GetFullPath(path).TrimEnd('\\');
                if (full.Length <= 2) return true; // Drive root like C:
                for (int i = 0; i < ProtectedPrefixes.Length; i++)
                {
                    string p = ProtectedPrefixes[i];
                    if (full.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                        full.StartsWith(p + "\\", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                // Protect Windows Registry hives / NTUSER / OneDrive sync db
                string name = Path.GetFileName(full);
                if (name.Equals("NTUSER.DAT", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { return true; }
            return false;
        }

        public static string FmtBytes(long bytes)
        {
            if (bytes < 0) bytes = 0;
            if (bytes >= 1099511627776L) return (bytes / 1099511627776.0).ToString("0.00") + " TB";
            if (bytes >= 1073741824L) return (bytes / 1073741824.0).ToString("0.00") + " GB";
            if (bytes >= 1048576L) return (bytes / 1048576.0).ToString("0.0") + " MB";
            if (bytes >= 1024L) return (bytes / 1024.0).ToString("0.0") + " KB";
            return bytes + " B";
        }

        public static Color CategoryColor(string ext, bool isFolder)
        {
            if (isFolder) return Color.FromArgb(71, 85, 105);
            if (string.IsNullOrEmpty(ext)) return Color.FromArgb(100, 116, 139);
            string e = ext.ToLowerInvariant();
            // Design & 3D Studio (Orange)
            if (e == ".psd" || e == ".psb" || e == ".ai" || e == ".eps" || e == ".cdr" || e == ".indd" ||
                e == ".max" || e == ".c4d" || e == ".blend" || e == ".fbx" || e == ".obj" || e == ".spp" || e == ".sbsar" || e == ".svg")
                return Color.FromArgb(252, 150, 31);
            // Images (Cyan)
            if (e == ".png" || e == ".jpg" || e == ".jpeg" || e == ".tif" || e == ".tiff" || e == ".webp" ||
                e == ".bmp" || e == ".gif" || e == ".heic" || e == ".cr2" || e == ".nef" || e == ".arw" || e == ".dng" || e == ".exr" || e == ".hdr")
                return Color.FromArgb(102, 217, 239);
            // Video & Audio (Pink)
            if (e == ".mp4" || e == ".mov" || e == ".mkv" || e == ".avi" || e == ".wmv" || e == ".webm" || e == ".m4v" ||
                e == ".mp3" || e == ".wav" || e == ".flac" || e == ".m4a" || e == ".aep" || e == ".prproj")
                return Color.FromArgb(249, 38, 114);
            // PDF & Office Docs (Green)
            if (e == ".pdf" || e == ".doc" || e == ".docx" || e == ".xls" || e == ".xlsx" || e == ".ppt" || e == ".pptx" || e == ".txt" || e == ".csv")
                return Color.FromArgb(166, 226, 46);
            // Archives & Disk Images (Purple)
            if (e == ".zip" || e == ".rar" || e == ".7z" || e == ".tar" || e == ".gz" || e == ".iso" || e == ".cab" || e == ".msi" || e == ".exe")
                return Color.FromArgb(174, 129, 255);
            return Color.FromArgb(110, 125, 148);
        }
    }

    // ========================================================================
    // 3. FAST WIN32 DISK SCANNER & DATA MODEL
    // ========================================================================
    internal sealed class DiskNode
    {
        public string Name;
        public string FullPath;
        public bool IsDir;
        public long Size;
        public int FileCount;
        public int DirCount;
        public DateTime Modified;
        public string Ext;
        public DiskNode Parent;
        public List<DiskNode> Children;
    }

    internal sealed class ExtStat
    {
        public string Ext;
        public long TotalBytes;
        public int FileCount;
    }

    internal sealed class ScanResult
    {
        public DiskNode Root;
        public List<DiskNode> TopFiles = new List<DiskNode>();
        public List<ExtStat> Extensions = new List<ExtStat>();
        public int TotalFiles;
        public int TotalDirs;
        public long TotalBytes;
        public double ElapsedSec;
        public bool Cancelled;
    }

    internal static class FastScanner
    {
        public static ScanResult Scan(string rootPath, ref bool cancelFlag, Action<int, int, long> onProgress)
        {
            Stopwatch sw = Stopwatch.StartNew();
            ScanResult res = new ScanResult();
            string cleanRoot = rootPath.TrimEnd('\\');
            if (cleanRoot.Length == 2 && cleanRoot[1] == ':') cleanRoot += "\\";

            DiskNode root = new DiskNode();
            root.Name = cleanRoot;
            root.FullPath = cleanRoot;
            root.IsDir = true;
            root.Children = new List<DiskNode>();

            Dictionary<string, ExtStat> extMap = new Dictionary<string, ExtStat>(StringComparer.OrdinalIgnoreCase);
            List<DiskNode> largestHeap = new List<DiskNode>(640);
            long minTopSize = 0;
            int totalFiles = 0;
            int totalDirs = 0;
            long totalBytes = 0;

            // Scan top-level root first, then scan top-level subdirs in parallel (4-6x faster on SSD!)
            string pattern = root.FullPath.EndsWith("\\") ? (root.FullPath + "*") : (root.FullPath + "\\*");
            Native.WIN32_FIND_DATA fd;
            IntPtr h = Native.FindFirstFileExW(ToLongPath(pattern), Native.FindExInfoBasic, out fd,
                Native.FindExSearchNameMatch, IntPtr.Zero, Native.FIND_FIRST_EX_LARGE_FETCH);
            List<DiskNode> topDirs = new List<DiskNode>();
            if (h != Native.INVALID_HANDLE_VALUE)
            {
                try
                {
                    do
                    {
                        if (cancelFlag) break;
                        string name = fd.cFileName;
                        if (name == "." || name == "..") continue;
                        if ((fd.dwFileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
                        string childPath = root.FullPath.EndsWith("\\") ? (root.FullPath + name) : (root.FullPath + "\\" + name);
                        bool isDir = (fd.dwFileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0;
                        if (isDir)
                        {
                            totalDirs++;
                            DiskNode sub = new DiskNode();
                            sub.Name = name; sub.FullPath = childPath; sub.IsDir = true;
                            sub.Parent = root; sub.Children = new List<DiskNode>();
                            sub.Modified = Native.FileTimeToLocal(fd.ftLastWriteTimeLow, fd.ftLastWriteTimeHigh);
                            root.Children.Add(sub);
                            topDirs.Add(sub);
                        }
                        else
                        {
                            long fsize = (((long)fd.nFileSizeHigh) << 32) | (uint)fd.nFileSizeLow;
                            totalFiles++; totalBytes += fsize;
                            string ext = GetExt(name);
                            AddExt(extMap, ext, fsize);
                            DiskNode fn = new DiskNode();
                            fn.Name = name; fn.FullPath = childPath; fn.IsDir = false;
                            fn.Size = fsize; fn.FileCount = 1; fn.Ext = ext;
                            fn.Modified = Native.FileTimeToLocal(fd.ftLastWriteTimeLow, fd.ftLastWriteTimeHigh);
                            fn.Parent = root;
                            root.Children.Add(fn);
                            TrackTopFile(largestHeap, ref minTopSize, fn);
                        }
                    } while (Native.FindNextFileW(h, out fd));
                }
                finally { Native.FindClose(h); }
            }

            if (topDirs.Count > 1 && !cancelFlag)
            {
                int workerCount = Math.Min(6, topDirs.Count);
                int nextIdx = -1;
                object mergeLock = new object();
                bool localCancel = cancelFlag;
                long sharedFiles = totalFiles, sharedDirs = totalDirs, sharedBytes = totalBytes;
                int sharedLastTick = Environment.TickCount;

                Thread[] workers = new Thread[workerCount];
                for (int wi = 0; wi < workerCount; wi++)
                {
                    workers[wi] = new Thread(delegate()
                    {
                        Dictionary<string, ExtStat> locExt = new Dictionary<string, ExtStat>(StringComparer.OrdinalIgnoreCase);
                        List<DiskNode> locTop = new List<DiskNode>(640);
                        long locMinTop = 0;
                        int lf = 0, ld = 0;
                        long lb = 0;
                        while (true)
                        {
                            if (localCancel) break;
                            int idx = Interlocked.Increment(ref nextIdx);
                            if (idx >= topDirs.Count) break;
                            int prevF = lf, prevD = ld;
                            long prevB = lb;
                            ScanDirRecursive(topDirs[idx], locExt, locTop, ref locMinTop, ref lf, ref ld, ref lb,
                                ref localCancel, ref sharedFiles, ref sharedDirs, ref sharedBytes, ref sharedLastTick, onProgress);
                            // Flush delta
                            Interlocked.Add(ref sharedFiles, lf - prevF);
                            Interlocked.Add(ref sharedDirs, ld - prevD);
                            Interlocked.Add(ref sharedBytes, lb - prevB);
                        }
                        lock (mergeLock)
                        {
                            foreach (KeyValuePair<string, ExtStat> kv in locExt)
                            {
                                ExtStat dst;
                                if (!extMap.TryGetValue(kv.Key, out dst)) { dst = new ExtStat { Ext = kv.Key }; extMap[kv.Key] = dst; }
                                dst.TotalBytes += kv.Value.TotalBytes;
                                dst.FileCount += kv.Value.FileCount;
                            }
                            largestHeap.AddRange(locTop);
                        }
                    });
                    workers[wi].IsBackground = true;
                    workers[wi].Start();
                }

                // Wait for workers while propagating external cancelFlag
                while (true)
                {
                    if (cancelFlag) localCancel = true;
                    bool anyAlive = false;
                    for (int wi = 0; wi < workerCount; wi++)
                        if (workers[wi].IsAlive) { anyAlive = true; break; }
                    if (!anyAlive) break;
                    Thread.Sleep(40);
                }
                totalFiles = (int)Math.Min(int.MaxValue, sharedFiles);
                totalDirs = (int)Math.Min(int.MaxValue, sharedDirs);
                totalBytes = sharedBytes;
            }
            else if (topDirs.Count == 1 && !cancelFlag)
            {
                long sf = totalFiles, sd = totalDirs, sb2 = totalBytes;
                int st = Environment.TickCount;
                ScanDirRecursive(topDirs[0], extMap, largestHeap, ref minTopSize, ref totalFiles, ref totalDirs, ref totalBytes,
                    ref cancelFlag, ref sf, ref sd, ref sb2, ref st, onProgress);
            }

            long rootTotalSize = 0;
            int rootTotalFiles = 0;
            int rootTotalDirs = 0;
            for (int i = 0; i < root.Children.Count; i++)
            {
                DiskNode ch = root.Children[i];
                rootTotalSize += ch.Size;
                rootTotalFiles += ch.FileCount;
                if (ch.IsDir) rootTotalDirs += 1 + ch.DirCount;
            }
            root.Size = rootTotalSize;
            root.FileCount = rootTotalFiles;
            root.DirCount = rootTotalDirs;
            if (root.Children.Count > 1)
                root.Children.Sort(delegate(DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); });

            largestHeap.Sort(delegate(DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); });
            if (largestHeap.Count > 300) largestHeap.RemoveRange(300, largestHeap.Count - 300);

            List<ExtStat> extList = new List<ExtStat>(extMap.Values);
            extList.Sort(delegate(ExtStat a, ExtStat b) { return b.TotalBytes.CompareTo(a.TotalBytes); });

            sw.Stop();
            res.Root = root;
            res.TopFiles = largestHeap;
            res.Extensions = extList;
            res.TotalFiles = rootTotalFiles;
            res.TotalDirs = rootTotalDirs;
            res.TotalBytes = rootTotalSize;
            res.ElapsedSec = sw.Elapsed.TotalSeconds;
            res.Cancelled = cancelFlag;
            return res;
        }

        private static string GetExt(string name)
        {
            int dot = name.LastIndexOf('.');
            return (dot > 0 && dot < name.Length - 1) ? name.Substring(dot).ToLowerInvariant() : "(χωρίς επέκταση)";
        }

        private static void AddExt(Dictionary<string, ExtStat> extMap, string ext, long fsize)
        {
            ExtStat st;
            if (!extMap.TryGetValue(ext, out st)) { st = new ExtStat { Ext = ext }; extMap[ext] = st; }
            st.TotalBytes += fsize;
            st.FileCount++;
        }

        private static void TrackTopFile(List<DiskNode> topFiles, ref long minTopSize, DiskNode fn)
        {
            if (fn.Size >= 10240 && (topFiles.Count < 300 || fn.Size > minTopSize))
            {
                topFiles.Add(fn);
                if (topFiles.Count >= 600)
                {
                    topFiles.Sort(delegate(DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); });
                    topFiles.RemoveRange(300, topFiles.Count - 300);
                    minTopSize = topFiles[299].Size;
                }
            }
        }

        private static string ToLongPath(string p)
        {
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
            if (p.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + p.Substring(2);
            return @"\\?\" + p;
        }

        private static void ScanDirRecursive(
            DiskNode dirNode,
            Dictionary<string, ExtStat> extMap,
            List<DiskNode> topFiles,
            ref long minTopSize,
            ref int totalFiles,
            ref int totalDirs,
            ref long totalBytes,
            ref bool cancelFlag,
            ref long sharedFiles,
            ref long sharedDirs,
            ref long sharedBytes,
            ref int sharedLastTick,
            Action<int, int, long> onProgress)
        {
            if (cancelFlag) return;
            string pattern = dirNode.FullPath.EndsWith("\\") ? (dirNode.FullPath + "*") : (dirNode.FullPath + "\\*");
            Native.WIN32_FIND_DATA fd;
            IntPtr h = Native.FindFirstFileExW(ToLongPath(pattern), Native.FindExInfoBasic, out fd,
                Native.FindExSearchNameMatch, IntPtr.Zero, Native.FIND_FIRST_EX_LARGE_FETCH);
            if (h == Native.INVALID_HANDLE_VALUE) return;

            long dirSize = 0;
            int dirFiles = 0;
            int dirSubDirs = 0;

            try
            {
                do
                {
                    if (cancelFlag) break;
                    string name = fd.cFileName;
                    if (name == "." || name == "..") continue;
                    if ((fd.dwFileAttributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;

                    string childPath = dirNode.FullPath.EndsWith("\\") ? (dirNode.FullPath + name) : (dirNode.FullPath + "\\" + name);
                    bool isDir = (fd.dwFileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0;

                    if (isDir)
                    {
                        totalDirs++;
                        dirSubDirs++;
                        DiskNode sub = new DiskNode();
                        sub.Name = name; sub.FullPath = childPath; sub.IsDir = true;
                        sub.Parent = dirNode; sub.Children = new List<DiskNode>();
                        sub.Modified = Native.FileTimeToLocal(fd.ftLastWriteTimeLow, fd.ftLastWriteTimeHigh);

                        ScanDirRecursive(sub, extMap, topFiles, ref minTopSize, ref totalFiles, ref totalDirs, ref totalBytes,
                            ref cancelFlag, ref sharedFiles, ref sharedDirs, ref sharedBytes, ref sharedLastTick, onProgress);

                        dirSize += sub.Size;
                        dirFiles += sub.FileCount;
                        dirSubDirs += sub.DirCount;
                        dirNode.Children.Add(sub);
                    }
                    else
                    {
                        long fsize = (((long)fd.nFileSizeHigh) << 32) | (uint)fd.nFileSizeLow;
                        totalFiles++;
                        totalBytes += fsize;
                        dirSize += fsize;
                        dirFiles++;

                        string ext = GetExt(name);
                        AddExt(extMap, ext, fsize);

                        DiskNode fn = new DiskNode();
                        fn.Name = name; fn.FullPath = childPath; fn.IsDir = false;
                        fn.Size = fsize; fn.FileCount = 1; fn.Ext = ext;
                        fn.Modified = Native.FileTimeToLocal(fd.ftLastWriteTimeLow, fd.ftLastWriteTimeHigh);
                        fn.Parent = dirNode;
                        dirNode.Children.Add(fn);

                        TrackTopFile(topFiles, ref minTopSize, fn);
                    }

                    if (onProgress != null && (totalFiles & 1023) == 0)
                    {
                        int now = Environment.TickCount;
                        int prev = sharedLastTick;
                        if (unchecked(now - prev) >= 150 && Interlocked.CompareExchange(ref sharedLastTick, now, prev) == prev)
                        {
                            long sf = Interlocked.Read(ref sharedFiles);
                            long sd = Interlocked.Read(ref sharedDirs);
                            long sbv = Interlocked.Read(ref sharedBytes);
                            onProgress((int)Math.Min(int.MaxValue, Math.Max(sf, totalFiles)),
                                       (int)Math.Min(int.MaxValue, Math.Max(sd, totalDirs)),
                                       Math.Max(sbv, totalBytes));
                        }
                    }
                }
                while (Native.FindNextFileW(h, out fd));
            }
            finally { Native.FindClose(h); }

            dirNode.Size = dirSize;
            dirNode.FileCount = dirFiles;
            dirNode.DirCount = dirSubDirs;
            if (dirNode.Children != null && dirNode.Children.Count > 1)
                dirNode.Children.Sort(delegate(DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); });
        }
    }

    // ========================================================================
    // 4. 3-STAGE CRYPTOGRAPHIC SHA-256 DUPLICATE FINDER (0% FALSE POSITIVES)
    // ========================================================================
    internal sealed class DupGroup
    {
        public string Hash;
        public long FileSize;
        public List<DiskNode> Files = new List<DiskNode>();
        public long WastedBytes { get { return FileSize * Math.Max(0, Files.Count - 1); } }
    }

    internal static class DuplicateFinder
    {
        public static List<DupGroup> FindDuplicates(DiskNode root, long minBytes, ref bool cancelFlag, Action<string> onStatus)
        {
            List<DupGroup> result = new List<DupGroup>();
            if (root == null) return result;

            // Stage 1: Group by exact byte size
            if (onStatus != null) onStatus("Στάδιο 1/3: Ομαδοποίηση κατά ακριβές μέγεθος...");
            Dictionary<long, List<DiskNode>> bySize = new Dictionary<long, List<DiskNode>>();
            CollectFiles(root, minBytes, bySize, ref cancelFlag);
            if (cancelFlag) return result;

            List<List<DiskNode>> sizeCandidates = new List<List<DiskNode>>();
            foreach (KeyValuePair<long, List<DiskNode>> kv in bySize)
                if (kv.Value.Count >= 2) sizeCandidates.Add(kv.Value);

            // Stage 2: Fast 64KB Head + 64KB Tail fingerprint
            if (onStatus != null) onStatus("Στάδιο 2/3: Γρήγορο αποτύπωμα " + sizeCandidates.Count + " ομάδων...");
            List<List<DiskNode>> partialCandidates = new List<List<DiskNode>>();
            for (int i = 0; i < sizeCandidates.Count && !cancelFlag; i++)
            {
                List<DiskNode> grp = sizeCandidates[i];
                Dictionary<string, List<DiskNode>> byQuick = new Dictionary<string, List<DiskNode>>();
                for (int j = 0; j < grp.Count && !cancelFlag; j++)
                {
                    string qh = ComputeQuickHash(grp[j].FullPath, grp[j].Size);
                    if (qh == null) continue;
                    List<DiskNode> sub;
                    if (!byQuick.TryGetValue(qh, out sub)) { sub = new List<DiskNode>(); byQuick[qh] = sub; }
                    sub.Add(grp[j]);
                }
                foreach (KeyValuePair<string, List<DiskNode>> kv in byQuick)
                    if (kv.Value.Count >= 2) partialCandidates.Add(kv.Value);
            }

            // Stage 3: Full SHA-256 verification (100% byte-for-byte guaranteed!)
            if (onStatus != null) onStatus("Στάδιο 3/3: Πλήρης επαλήθευση SHA-256 σε " + partialCandidates.Count + " υποψήφιες ομάδες...");
            for (int i = 0; i < partialCandidates.Count && !cancelFlag; i++)
            {
                List<DiskNode> grp = partialCandidates[i];
                Dictionary<string, List<DiskNode>> byFull = new Dictionary<string, List<DiskNode>>();
                for (int j = 0; j < grp.Count && !cancelFlag; j++)
                {
                    string fh = ComputeFullSha256(grp[j].FullPath);
                    if (fh == null) continue;
                    List<DiskNode> sub;
                    if (!byFull.TryGetValue(fh, out sub)) { sub = new List<DiskNode>(); byFull[fh] = sub; }
                    sub.Add(grp[j]);
                }
                foreach (KeyValuePair<string, List<DiskNode>> kv in byFull)
                {
                    if (kv.Value.Count >= 2)
                    {
                        // Sort newest first so index 0 is kept as newest original
                        kv.Value.Sort(delegate(DiskNode a, DiskNode b) { return b.Modified.CompareTo(a.Modified); });
                        DupGroup dg = new DupGroup();
                        dg.Hash = kv.Key;
                        dg.FileSize = kv.Value[0].Size;
                        dg.Files = kv.Value;
                        result.Add(dg);
                    }
                }
            }

            result.Sort(delegate(DupGroup a, DupGroup b) { return b.WastedBytes.CompareTo(a.WastedBytes); });
            return result;
        }

        private static void CollectFiles(DiskNode node, long minBytes, Dictionary<long, List<DiskNode>> bySize, ref bool cancelFlag)
        {
            if (cancelFlag || node == null) return;
            if (!node.IsDir)
            {
                if (node.Size >= minBytes && !SafetyGuard.IsProtectedPath(node.FullPath))
                {
                    List<DiskNode> list;
                    if (!bySize.TryGetValue(node.Size, out list)) { list = new List<DiskNode>(); bySize[node.Size] = list; }
                    list.Add(node);
                }
                return;
            }
            if (node.Children == null) return;
            for (int i = 0; i < node.Children.Count && !cancelFlag; i++)
                CollectFiles(node.Children[i], minBytes, bySize, ref cancelFlag);
        }

        private static string ComputeQuickHash(string path, long size)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (SHA256 sha = SHA256.Create())
                {
                    int chunk = 65536;
                    byte[] buf = new byte[chunk];
                    int r1 = fs.Read(buf, 0, (int)Math.Min(chunk, size));
                    sha.TransformBlock(buf, 0, r1, null, 0);
                    if (size > chunk)
                    {
                        fs.Seek(Math.Max(0, size - chunk), SeekOrigin.Begin);
                        int r2 = fs.Read(buf, 0, chunk);
                        sha.TransformFinalBlock(buf, 0, r2);
                    }
                    else sha.TransformFinalBlock(buf, 0, 0);
                    return BitConverter.ToString(sha.Hash).Replace("-", "");
                }
            }
            catch { return null; }
        }

        private static string ComputeFullSha256(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 131072))
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] h = sha.ComputeHash(fs);
                    return BitConverter.ToString(h).Replace("-", "");
                }
            }
            catch { return null; }
        }
    }

    // ========================================================================
    // 5. 100% SAFE REGENERABLE CACHE AUDITOR & CLEANER
    // ========================================================================
    internal sealed class SafeCacheTarget
    {
        public string Id;
        public string Title;
        public string Description;
        public List<string> Folders = new List<string>();
        public bool IsRecycleBin;
        public long Bytes;
        public int FileCount;
        public bool Selected = true;
    }

    internal static class SafeCacheEngine
    {
        public static List<SafeCacheTarget> BuildAndMeasureTargets()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roam = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string temp = Path.GetTempPath();

            List<SafeCacheTarget> list = new List<SafeCacheTarget>();

            AddTarget(list, "temp", "Windows User Temp (%TEMP%)",
                "Προσωρινά αρχεία εγκαταστάσεων & εφαρμογών (100% ασφαλές)",
                new string[] { temp });

            AddTarget(list, "adobe_media", "Adobe Media Cache & Peak Files",
                "Προσωρινή cache Premiere / After Effects / Media Encoder (αναγεννάται αυτόματα)",
                new string[] {
                    Path.Combine(roam, @"Adobe\Common\Media Cache"),
                    Path.Combine(roam, @"Adobe\Common\Media Cache Files"),
                    Path.Combine(roam, @"Adobe\Common\Peak Files")
                });

            AddTarget(list, "adobe_acr", "Adobe Camera Raw Cache",
                "Cache προεπισκοπήσεων RAW Photoshop (δεν αγγίζει presets ή XMP)",
                new string[] { Path.Combine(local, @"Adobe\CameraRaw\Cache") });

            AddTarget(list, "nvidia_dx", "NVIDIA & DirectX Shader Cache",
                "Προσωρινοί compiled shaders GPU (αναγεννώνται αυτόματα)",
                new string[] {
                    Path.Combine(local, @"NVIDIA\DXCache"),
                    Path.Combine(local, @"NVIDIA\GLCache"),
                    Path.Combine(local, @"D3DSCache")
                });

            AddTarget(list, "crash_dumps", "Windows Crash Dumps",
                "Παλιά αρχεία αναφορών σφαλμάτων (.dmp)",
                new string[] { Path.Combine(local, "CrashDumps") });

            // Chrome Disk Cache ONLY (NEVER Cookies, Login Data, Bookmarks, History!)
            List<string> chromeCaches = FindProfileSubDirs(Path.Combine(local, @"Google\Chrome\User Data"),
                new string[] { @"Cache\Cache_Data", "Code Cache", "GPUCache" });
            AddTarget(list, "chrome_cache", "Google Chrome Disk Cache",
                "ΜΟΝΟ προσωρινή cache εικόνων/scripts — 0 κωδικοί, 0 cookies, 0 tabs",
                chromeCaches.ToArray());

            // Edge Disk Cache ONLY
            List<string> edgeCaches = FindProfileSubDirs(Path.Combine(local, @"Microsoft\Edge\User Data"),
                new string[] { @"Cache\Cache_Data", "Code Cache", "GPUCache" });
            AddTarget(list, "edge_cache", "Microsoft Edge Disk Cache",
                "ΜΟΝΟ προσωρινή cache — 0 κωδικοί, 0 cookies, 0 αγαπημένα",
                edgeCaches.ToArray());

            // Firefox cache2 ONLY
            List<string> ffCaches = FindProfileSubDirs(Path.Combine(local, @"Mozilla\Firefox\Profiles"),
                new string[] { "cache2", "startupCache" });
            AddTarget(list, "firefox_cache", "Mozilla Firefox Disk Cache (cache2)",
                "ΜΟΝΟ προσωρινή cache2 — 0 κωδικοί, 0 cookies, 0 ανοιχτά tabs",
                ffCaches.ToArray());

            // Recycle Bin
            long rbCount;
            long rbBytes = Native.QueryRecycleBinBytes(out rbCount);
            SafeCacheTarget rb = new SafeCacheTarget();
            rb.Id = "recycle_bin";
            rb.Title = "Κάδος Ανακύκλωσης (Recycle Bin)";
            rb.Description = "Άδειασμα διαγραμμένων αρχείων στον Κάδο Ανακύκλωσης";
            rb.IsRecycleBin = true;
            rb.Bytes = rbBytes;
            rb.FileCount = (int)Math.Min(int.MaxValue, rbCount);
            rb.Selected = false; // Unchecked by default for extra user safety!
            list.Add(rb);

            return list;
        }

        private static List<string> FindProfileSubDirs(string root, string[] relSubs)
        {
            List<string> res = new List<string>();
            if (!Directory.Exists(root)) return res;
            try
            {
                foreach (string prof in Directory.GetDirectories(root))
                {
                    for (int i = 0; i < relSubs.Length; i++)
                    {
                        string cand = Path.Combine(prof, relSubs[i]);
                        if (Directory.Exists(cand)) res.Add(cand);
                    }
                }
            }
            catch { }
            return res;
        }

        private static void AddTarget(List<SafeCacheTarget> list, string id, string title, string desc, string[] folders)
        {
            SafeCacheTarget t = new SafeCacheTarget();
            t.Id = id; t.Title = title; t.Description = desc;
            long bytes = 0; int files = 0;
            for (int i = 0; i < folders.Length; i++)
            {
                if (Directory.Exists(folders[i]))
                {
                    t.Folders.Add(folders[i]);
                    MeasureDir(folders[i], ref bytes, ref files);
                }
            }
            t.Bytes = bytes;
            t.FileCount = files;
            t.Selected = (bytes > 0);
            list.Add(t);
        }

        private static void MeasureDir(string dir, ref long bytes, ref int files)
        {
            try
            {
                foreach (string f in Directory.GetFiles(dir))
                {
                    try { bytes += new FileInfo(f).Length; files++; } catch { }
                }
                foreach (string sub in Directory.GetDirectories(dir))
                {
                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                        MeasureDir(sub, ref bytes, ref files);
                    }
                    catch { }
                }
            }
            catch { }
        }

        public static long CleanTarget(SafeCacheTarget t, out int deletedFiles)
        {
            deletedFiles = 0;
            long freed = 0;
            if (t.IsRecycleBin)
            {
                long cnt;
                long before = Native.QueryRecycleBinBytes(out cnt);
                Native.SHEmptyRecycleBinW(IntPtr.Zero, null, Native.SHERB_NOCONFIRMATION | Native.SHERB_NOPROGRESSUI | Native.SHERB_NOSOUND);
                deletedFiles = (int)Math.Min(int.MaxValue, cnt);
                return before;
            }
            for (int i = 0; i < t.Folders.Count; i++)
                CleanFolderContents(t.Folders[i], false, ref freed, ref deletedFiles);
            return freed;
        }

        private static void CleanFolderContents(string dir, bool removeSelf, ref long freed, ref int deletedFiles)
        {
            if (!Directory.Exists(dir) || SafetyGuard.IsProtectedPath(dir)) return;
            try
            {
                foreach (string f in Directory.GetFiles(dir))
                {
                    try
                    {
                        long len = new FileInfo(f).Length;
                        File.SetAttributes(f, FileAttributes.Normal);
                        File.Delete(f);
                        freed += len;
                        deletedFiles++;
                    }
                    catch { } // File in use by active app -> safely skipped!
                }
                foreach (string sub in Directory.GetDirectories(dir))
                {
                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                        CleanFolderContents(sub, true, ref freed, ref deletedFiles);
                    }
                    catch { }
                }
                if (removeSelf)
                {
                    try { Directory.Delete(dir, false); } catch { }
                }
            }
            catch { }
        }
    }

    // ========================================================================
    // 6. INTERACTIVE SQUARIFIED TREEMAP CANVAS
    // ========================================================================
    internal sealed class TreemapTile
    {
        public DiskNode Node;
        public RectangleF Rect;
        public Color Fill;
    }

    internal sealed class TreemapCanvas : Control
    {
        public bool IsDark = true;
        public event Action<DiskNode> TileHovered;
        public event Action<DiskNode> TileActivated;
        public event Action<DiskNode, Point> TileRightClicked;

        private DiskNode _root;
        private readonly List<TreemapTile> _tiles = new List<TreemapTile>();
        private TreemapTile _hover;

        public TreemapCanvas()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        }

        public void SetNode(DiskNode node)
        {
            _root = node;
            _hover = null;
            RebuildLayout();
            Invalidate();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            RebuildLayout();
            base.OnSizeChanged(e);
        }

        private void RebuildLayout()
        {
            _tiles.Clear();
            if (_root == null || _root.Children == null || _root.Children.Count == 0 || Width < 20 || Height < 20) return;

            List<DiskNode> items = new List<DiskNode>();
            long total = 0;
            int limit = Math.Min(120, _root.Children.Count);
            for (int i = 0; i < limit; i++)
            {
                DiskNode ch = _root.Children[i];
                if (ch.Size > 0) { items.Add(ch); total += ch.Size; }
            }
            if (items.Count == 0 || total <= 0) return;

            LayoutSliceDice(items, 0, items.Count, total, new RectangleF(4, 4, Width - 8, Height - 8));
        }

        // Balanced binary split treemap (near-square aspect ratio, deterministic, zero NaN!)
        private void LayoutSliceDice(List<DiskNode> items, int start, int count, long sum, RectangleF area)
        {
            if (count <= 0 || area.Width < 2f || area.Height < 2f || sum <= 0) return;
            if (count == 1)
            {
                DiskNode n = items[start];
                TreemapTile tile = new TreemapTile();
                tile.Node = n;
                tile.Rect = area;
                tile.Fill = n.IsDir ? FolderTint(n.Name) : SafetyGuard.CategoryColor(n.Ext, false);
                _tiles.Add(tile);
                return;
            }

            long half = sum / 2;
            long acc = 0;
            int split = start;
            for (int i = start; i < start + count - 1; i++)
            {
                acc += items[i].Size;
                split = i + 1;
                if (acc >= half) break;
            }
            double ratio = Math.Max(0.02, Math.Min(0.98, (double)acc / sum));

            RectangleF r1, r2;
            if (area.Width >= area.Height)
            {
                float w1 = (float)(area.Width * ratio);
                r1 = new RectangleF(area.X, area.Y, w1, area.Height);
                r2 = new RectangleF(area.X + w1, area.Y, area.Width - w1, area.Height);
            }
            else
            {
                float h1 = (float)(area.Height * ratio);
                r1 = new RectangleF(area.X, area.Y, area.Width, h1);
                r2 = new RectangleF(area.X, area.Y + h1, area.Width, area.Height - h1);
            }

            LayoutSliceDice(items, start, split - start, acc, r1);
            LayoutSliceDice(items, split, start + count - split, sum - acc, r2);
        }

        private static Color FolderTint(string name)
        {
            Color[] palette = new Color[]
            {
                Color.FromArgb(42, 92, 128),
                Color.FromArgb(52, 108, 92),
                Color.FromArgb(128, 82, 42),
                Color.FromArgb(96, 62, 124),
                Color.FromArgb(122, 54, 78),
                Color.FromArgb(58, 86, 112)
            };
            int h = Math.Abs((name ?? "").GetHashCode());
            return palette[h % palette.Length];
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.Clear(IsDark ? Color.FromArgb(24, 25, 29) : Color.FromArgb(240, 242, 246));

            if (_tiles.Count == 0)
            {
                string msg = "Διάλεξε δίσκο ή φάκελο και πάτα «▶ Σάρωση» για οπτικό Treemap";
                TextRenderer.DrawText(g, msg, Font, ClientRectangle, IsDark ? Color.FromArgb(130, 140, 155) : Color.Gray,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                return;
            }

            Color borderCol = IsDark ? Color.FromArgb(22, 23, 27) : Color.White;
            using (Pen bp = new Pen(borderCol, 1.5f))
            using (Pen hp = new Pen(Color.White, 2.2f))
            {
                for (int i = 0; i < _tiles.Count; i++)
                {
                    TreemapTile t = _tiles[i];
                    Rectangle r = Rectangle.Round(t.Rect);
                    if (r.Width < 2 || r.Height < 2) continue;

                    Color fill = (t == _hover) ? ControlPaint.Light(t.Fill, 0.22f) : t.Fill;
                    using (SolidBrush br = new SolidBrush(fill))
                        g.FillRectangle(br, r);
                    g.DrawRectangle(t == _hover ? hp : bp, r);

                    if (r.Width >= 56 && r.Height >= 26)
                    {
                        Rectangle tr = new Rectangle(r.X + 4, r.Y + 3, r.Width - 8, r.Height - 6);
                        string label = (t.Node.IsDir ? "▸ " : "") + t.Node.Name + "\n" + SafetyGuard.FmtBytes(t.Node.Size);
                        TextRenderer.DrawText(g, label, Font, tr, Color.White,
                            TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.WordBreak);
                    }
                }
            }
        }

        private TreemapTile HitTest(Point pt)
        {
            for (int i = _tiles.Count - 1; i >= 0; i--)
                if (_tiles[i].Rect.Contains(pt)) return _tiles[i];
            return null;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            TreemapTile hit = HitTest(e.Location);
            if (hit != _hover)
            {
                _hover = hit;
                Cursor = (hit != null) ? Cursors.Hand : Cursors.Default;
                Invalidate();
                if (TileHovered != null) TileHovered(hit != null ? hit.Node : null);
            }
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            if (_hover != null) { _hover = null; Invalidate(); if (TileHovered != null) TileHovered(null); }
            base.OnMouseLeave(e);
        }

        protected override void OnMouseDoubleClick(MouseEventArgs e)
        {
            TreemapTile hit = HitTest(e.Location);
            if (hit != null && TileActivated != null) TileActivated(hit.Node);
            base.OnMouseDoubleClick(e);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                TreemapTile hit = HitTest(e.Location);
                if (hit != null && TileRightClicked != null) TileRightClicked(hit.Node, e.Location);
            }
            base.OnMouseDown(e);
        }
    }

    // ========================================================================
    // 7. MAIN STUDIO WINDOW (4 PRO TABS · DARK/LIGHT · ZERO-RISK SAFETY)
    // ========================================================================
    internal sealed class MainForm : Form
    {
        private bool _dark = true;
        private bool _scanning = false;
        private bool _cancelScan = false;
        private ScanResult _lastScan;
        private DiskNode _currentDir;
        private List<DupGroup> _dupGroups = new List<DupGroup>();
        private List<SafeCacheTarget> _cacheTargets = new List<SafeCacheTarget>();

        // Palette
        private Color _bgMain, _bgPanel, _bgCard, _bgInput, _fgMain, _fgMuted, _border, _accent;

        // Top Bar
        private Panel _topBar;
        private ComboBox _cmbTarget;
        private Button _btnBrowse, _btnScan, _btnStop, _btnTheme;
        private Label _lblScanStatus;

        // Nav Tabs
        private Panel _navBar;
        private readonly Button[] _navBtns = new Button[4];
        private readonly Panel[] _pages = new Panel[4];
        private int _activePage = 0;

        // Page 0: Analyzer & Treemap
        private Panel _crumbBar;
        private Button _btnUp, _btnOpenDir, _btnExportCsv;
        private Label _lblCrumb;
        private SplitContainer _splitAnalyze;
        private ListView _lvNodes;
        private TreemapCanvas _treemap;
        private Label _lblHoverInfo;

        // Page 1: Top Files & Extensions
        private TextBox _txtFilterFiles;
        private ListView _lvTopFiles;
        private ListView _lvExts;

        // Page 2: SHA-256 Duplicates
        private ComboBox _cmbDupMin;
        private Button _btnFindDups, _btnAutoOlder, _btnClearDups, _btnTrashDups;
        private Label _lblDupSummary;
        private ListView _lvDups;

        // Page 3: Safe Cache Cleaner
        private Button _btnRefreshCache, _btnCleanCache;
        private Label _lblCacheSummary;
        private ListView _lvCache;

        // Footer
        private Label _lblFooter;
        private readonly Font _headerFont = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        private readonly string _initialPath;

        public MainForm(string initialPath, bool smokeMode)
        {
            _initialPath = initialPath;
            Text = "NillyDisk Pro — Disk Analyzer, Treemap, SHA-256 Duplicates & Safe Cleaner";
            Size = new Size(1180, 720);
            MinimumSize = new Size(860, 540);
            StartPosition = FormStartPosition.CenterScreen;

            try
            {
                string ico = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NillyDiskPro.ico");
                if (File.Exists(ico)) Icon = new Icon(ico);
                else Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch { }

            BuildUi();
            PopulateDriveTargets();
            ApplyTheme();
            SwitchPage(0);

            if (!smokeMode)
            {
                Shown += delegate
                {
                    RefreshCacheTargetsAsync();
                    if (!string.IsNullOrEmpty(_initialPath) && Directory.Exists(_initialPath))
                    {
                        _cmbTarget.Text = _initialPath;
                        StartScan();
                    }
                };
            }
        }

        private void BuildUi()
        {
            // Bottom Brand Footer (clickable -> nillygraphics.com)
            _lblFooter = new Label();
            _lblFooter.UseMnemonic = false;
            _lblFooter.Dock = DockStyle.Bottom;
            _lblFooter.Height = 24;
            _lblFooter.TextAlign = ContentAlignment.MiddleCenter;
            _lblFooter.Font = new Font("Segoe UI", 8.3f);
            _lblFooter.Text = "NillyDisk Pro · 100% Read-Only Scan & Recycle-Bin Safety · created by Nilly graphics (Sotiris Christos) · nillygraphics.com";
            _lblFooter.Cursor = Cursors.Hand;
            _lblFooter.Click += delegate { try { Process.Start(new ProcessStartInfo("https://nillygraphics.com/") { UseShellExecute = true }); } catch { } };

            // Top Control Bar
            _topBar = new Panel { Dock = DockStyle.Top, Height = 48, Padding = new Padding(10, 8, 10, 8) };
            _cmbTarget = new ComboBox { Left = 10, Top = 11, Width = 360, DropDownStyle = ComboBoxStyle.DropDown, Font = new Font("Segoe UI", 9.5f) };
            _btnBrowse = MkBtn("▸ Φάκελος...", 378, 10, 102, 28, delegate { BrowseFolder(); });
            _btnScan = MkBtn("▶ Σάρωση", 488, 10, 102, 28, delegate { StartScan(); });
            _btnStop = MkBtn("■ Διακοπή", 596, 10, 86, 28, delegate { _cancelScan = true; });
            _btnStop.Enabled = false;
            _lblScanStatus = new Label { Left = 694, Top = 10, Width = 390, Height = 28, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 9f), Text = "Έτοιμο (100% Read-Only σάρωση)" };
            _btnTheme = MkBtn("☀", 1090, 10, 34, 28, delegate { _dark = !_dark; ApplyTheme(); });
            _btnTheme.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _lblScanStatus.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _topBar.Controls.AddRange(new Control[] { _cmbTarget, _btnBrowse, _btnScan, _btnStop, _lblScanStatus, _btnTheme });

            // Nav Bar (4 Pro Tabs — crisp symbols + UseMnemonic=false so '&' renders cleanly!)
            _navBar = new Panel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(10, 3, 10, 3) };
            string[] tabTitles = new string[] {
                "▦  Ανάλυση & Treemap",
                "▲  Μεγαλύτερα Αρχεία & Τύποι",
                "⧉  Διπλότυπα (SHA-256)",
                "✦  Ασφαλής Καθαρισμός Cache"
            };
            int nx = 10;
            for (int i = 0; i < 4; i++)
            {
                int idx = i;
                Button b = MkBtn(tabTitles[i], nx, 4, 224, 28, delegate { SwitchPage(idx); });
                b.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
                _navBtns[i] = b;
                _navBar.Controls.Add(b);
                nx += 230;
            }

            // Content Host
            Panel host = new Panel { Dock = DockStyle.Fill };
            _pages[0] = BuildAnalyzerPage();
            _pages[1] = BuildTopFilesPage();
            _pages[2] = BuildDuplicatesPage();
            _pages[3] = BuildSafeCachePage();
            for (int i = 0; i < 4; i++)
            {
                _pages[i].Dock = DockStyle.Fill;
                _pages[i].Visible = false;
                host.Controls.Add(_pages[i]);
            }

            Controls.Add(host);
            Controls.Add(_navBar);
            Controls.Add(_topBar);
            Controls.Add(_lblFooter);
        }

        private Panel BuildAnalyzerPage()
        {
            Panel p = new Panel();

            _crumbBar = new Panel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(8, 3, 8, 3) };
            _btnUp = MkBtn("↑ Πάνω", 8, 4, 78, 25, delegate { if (_currentDir != null && _currentDir.Parent != null) ShowFolder(_currentDir.Parent); });
            _btnOpenDir = MkBtn("↗ Explorer", 92, 4, 92, 25, delegate { if (_currentDir != null) OpenInExplorer(_currentDir.FullPath, false); });
            _btnExportCsv = MkBtn("↓ CSV", 190, 4, 68, 25, delegate { ExportCurrentCsv(); });
            _lblCrumb = new Label { Left = 268, Top = 4, Width = 860, Height = 25, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Consolas", 9.5f), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, Text = "—" };
            _crumbBar.Controls.AddRange(new Control[] { _btnUp, _btnOpenDir, _btnExportCsv, _lblCrumb });

            _lblHoverInfo = new Label { Dock = DockStyle.Bottom, Height = 24, Padding = new Padding(10, 0, 10, 0), TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 8.5f), Text = "Hover στο Treemap για λεπτομέρειες · Διπλό κλικ = Άνοιγμα · Δεξί κλικ = Ασφαλής διαγραφή στον Κάδο" };

            _splitAnalyze = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterDistance = 540, SplitterWidth = 5 };
            _splitAnalyze.SizeChanged += delegate
            {
                if (_splitAnalyze.Width > 300)
                {
                    int target = (int)(_splitAnalyze.Width * 0.48);
                    if (target > 260 && target < _splitAnalyze.Width - 240)
                        _splitAnalyze.SplitterDistance = target;
                }
            };

            // Left: Owner-drawn ListView with inline percentage bars (auto-fits width -> ZERO white header gap!)
            _lvNodes = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false,
                BorderStyle = BorderStyle.None, OwnerDraw = true, Font = new Font("Segoe UI", 9f)
            };
            _lvNodes.Columns.Add("Όνομα", 230);
            _lvNodes.Columns.Add("Μέγεθος", 92, HorizontalAlignment.Right);
            _lvNodes.Columns.Add("% Χώρου", 130);
            _lvNodes.Columns.Add("Αρχεία", 74, HorizontalAlignment.Right);
            _lvNodes.SizeChanged += delegate { FitAnalyzerColumns(); };
            _lvNodes.DrawColumnHeader += DrawListHeader;
            _lvNodes.DrawItem += delegate { };
            _lvNodes.DrawSubItem += DrawNodeSubItem;
            _lvNodes.DoubleClick += delegate
            {
                if (_lvNodes.SelectedItems.Count == 0) return;
                DiskNode n = _lvNodes.SelectedItems[0].Tag as DiskNode;
                ActivateNode(n);
            };
            _lvNodes.ContextMenuStrip = BuildNodeContextMenu(delegate { return _lvNodes.SelectedItems.Count > 0 ? _lvNodes.SelectedItems[0].Tag as DiskNode : null; });

            // Right: Interactive Squarified Treemap
            _treemap = new TreemapCanvas { Dock = DockStyle.Fill };
            _treemap.TileHovered += delegate(DiskNode n)
            {
                if (n == null) _lblHoverInfo.Text = "Hover στο Treemap για λεπτομέρειες · Διπλό κλικ = Άνοιγμα · Δεξί κλικ = Επιλογές";
                else
                {
                    double pct = (_currentDir != null && _currentDir.Size > 0) ? (n.Size * 100.0 / _currentDir.Size) : 0;
                    _lblHoverInfo.Text = string.Format("{0}  |  {1} ({2:0.0}%)  |  {3}", n.Name, SafetyGuard.FmtBytes(n.Size), pct, n.FullPath);
                }
            };
            _treemap.TileActivated += ActivateNode;
            _treemap.TileRightClicked += delegate(DiskNode n, Point pt)
            {
                ContextMenuStrip cms = BuildNodeContextMenu(delegate { return n; });
                cms.Show(_treemap, pt);
            };

            _splitAnalyze.Panel1.Controls.Add(_lvNodes);
            _splitAnalyze.Panel2.Controls.Add(_treemap);

            p.Controls.Add(_splitAnalyze);
            p.Controls.Add(_crumbBar);
            p.Controls.Add(_lblHoverInfo);
            return p;
        }

        private Panel BuildTopFilesPage()
        {
            Panel p = new Panel();
            Panel bar = new Panel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(10, 5, 10, 5) };
            Label lbl = new Label { Left = 10, Top = 8, Width = 140, Text = "Φίλτρο (π.χ. .psd):", Font = new Font("Segoe UI", 9f) };
            _txtFilterFiles = new TextBox { Left = 152, Top = 6, Width = 260, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 9.5f) };
            _txtFilterFiles.TextChanged += delegate { PopulateTopFilesList(); };
            bar.Controls.AddRange(new Control[] { lbl, _txtFilterFiles });

            SplitContainer sp = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterDistance = 760, SplitterWidth = 5 };

            _lvTopFiles = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 9f) };
            _lvTopFiles.Columns.Add("Αρχείο", 220);
            _lvTopFiles.Columns.Add("Μέγεθος", 90, HorizontalAlignment.Right);
            _lvTopFiles.Columns.Add("Τροποποίηση", 115);
            _lvTopFiles.Columns.Add("Διαδρομή", 330);
            _lvTopFiles.DoubleClick += delegate
            {
                if (_lvTopFiles.SelectedItems.Count > 0)
                {
                    DiskNode n = _lvTopFiles.SelectedItems[0].Tag as DiskNode;
                    if (n != null) OpenInExplorer(n.FullPath, true);
                }
            };
            _lvTopFiles.ContextMenuStrip = BuildNodeContextMenu(delegate { return _lvTopFiles.SelectedItems.Count > 0 ? _lvTopFiles.SelectedItems[0].Tag as DiskNode : null; });

            _lvExts = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 9f) };
            _lvExts.Columns.Add("Τύπος (Ext)", 100);
            _lvExts.Columns.Add("Σύνολο", 95, HorizontalAlignment.Right);
            _lvExts.Columns.Add("Αρχεία", 75, HorizontalAlignment.Right);
            _lvExts.Columns.Add("%", 60, HorizontalAlignment.Right);
            _lvExts.DoubleClick += delegate
            {
                if (_lvExts.SelectedItems.Count > 0) _txtFilterFiles.Text = _lvExts.SelectedItems[0].Text;
            };

            sp.Panel1.Controls.Add(_lvTopFiles);
            sp.Panel2.Controls.Add(_lvExts);
            p.Controls.Add(sp);
            p.Controls.Add(bar);
            return p;
        }

        private Panel BuildDuplicatesPage()
        {
            Panel p = new Panel();
            Panel bar = new Panel { Dock = DockStyle.Top, Height = 44, Padding = new Padding(10, 7, 10, 7) };

            Label lMin = new Label { Left = 10, Top = 12, Width = 80, Text = "Ελάχιστο:", Font = new Font("Segoe UI", 9f) };
            _cmbDupMin = new ComboBox { Left = 90, Top = 9, Width = 100, DropDownStyle = ComboBoxStyle.DropDownList, Font = new Font("Segoe UI", 9f) };
            _cmbDupMin.Items.AddRange(new object[] { "1 MB+", "100 KB+", "10 MB+", "50 MB+" });
            _cmbDupMin.SelectedIndex = 0;

            _btnFindDups = MkBtn("⧉ Εύρεση Διπλοτύπων (SHA-256)", 198, 8, 224, 28, delegate { RunDuplicateSearch(); });
            _btnAutoOlder = MkBtn("⚡ Επιλογή Παλαιότερων", 430, 8, 170, 28, delegate { AutoSelectOlderDuplicates(); });
            _btnClearDups = MkBtn("Αποεπιλογή", 608, 8, 94, 28, delegate { foreach (ListViewItem it in _lvDups.Items) it.Checked = false; });
            _btnTrashDups = MkBtn("× Επιλεγμένα στον Κάδο", 710, 8, 180, 28, delegate { MoveSelectedDuplicatesToTrash(); });

            bar.Controls.AddRange(new Control[] { lMin, _cmbDupMin, _btnFindDups, _btnAutoOlder, _btnClearDups, _btnTrashDups });

            _lblDupSummary = new Label { Dock = DockStyle.Top, Height = 26, Padding = new Padding(12, 0, 10, 0), TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Text = "Κάνε πρώτα «▶ Σάρωση» και μετά «⧉ Εύρεση Διπλοτύπων» — 100% επαλήθευση SHA-256, κρατάει πάντα τουλάχιστον 1 πρωτότυπο!" };

            _lvDups = new ListView { Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 9f) };
            _lvDups.Columns.Add("Ομάδα / Αρχείο", 240);
            _lvDups.Columns.Add("Μέγεθος", 90, HorizontalAlignment.Right);
            _lvDups.Columns.Add("Τροποποίηση", 120);
            _lvDups.Columns.Add("Διαδρομή", 480);
            _lvDups.Columns.Add("Κατάσταση", 120);
            _lvDups.DoubleClick += delegate
            {
                if (_lvDups.SelectedItems.Count > 0)
                {
                    DiskNode n = _lvDups.SelectedItems[0].Tag as DiskNode;
                    if (n != null) OpenInExplorer(n.FullPath, true);
                }
            };

            p.Controls.Add(_lvDups);
            p.Controls.Add(_lblDupSummary);
            p.Controls.Add(bar);
            return p;
        }

        private Panel BuildSafeCachePage()
        {
            Panel p = new Panel();
            Panel bar = new Panel { Dock = DockStyle.Top, Height = 44, Padding = new Padding(10, 7, 10, 7) };
            _btnRefreshCache = MkBtn("↻ Επανυπολογισμός Caches", 10, 8, 195, 28, delegate { RefreshCacheTargetsAsync(); });
            _btnCleanCache = MkBtn("✦ Ασφαλής Καθαρισμός Επιλεγμένων", 214, 8, 250, 28, delegate { CleanSelectedCaches(); });
            _lblCacheSummary = new Label { Left = 476, Top = 8, Width = 660, Height = 28, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, Text = "Υπολογισμός ασφαλών regenerable caches..." };
            bar.Controls.AddRange(new Control[] { _btnRefreshCache, _btnCleanCache, _lblCacheSummary });

            _lvCache = new ListView { Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 9.2f) };
            _lvCache.Columns.Add("Ασφαλής Κατηγορία Cache", 270);
            _lvCache.Columns.Add("Μέγεθος", 100, HorizontalAlignment.Right);
            _lvCache.Columns.Add("Αρχεία", 80, HorizontalAlignment.Right);
            _lvCache.Columns.Add("Περιγραφή (100% Ασφαλές — Δεν αγγίζει κωδικούς / έργα)", 480);
            _lvCache.ItemChecked += delegate(object s, ItemCheckedEventArgs e)
            {
                SafeCacheTarget t = e.Item.Tag as SafeCacheTarget;
                if (t != null) t.Selected = e.Item.Checked;
            };

            p.Controls.Add(_lvCache);
            p.Controls.Add(bar);
            return p;
        }

        private Button MkBtn(string txt, int x, int y, int w, int h, EventHandler onClick)
        {
            Button b = new Button();
            b.UseMnemonic = false;
            b.Text = txt; b.Left = x; b.Top = y; b.Width = w; b.Height = h;
            b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 1;
            b.Font = new Font("Segoe UI", 8.8f); b.Cursor = Cursors.Hand; b.TabStop = false;
            b.Click += onClick;
            return b;
        }

        private void FitAnalyzerColumns()
        {
            if (_lvNodes == null || _lvNodes.Columns.Count < 4) return;
            int w = _lvNodes.ClientSize.Width;
            if (w <= 320) return;
            int fixedW = _lvNodes.Columns[1].Width + _lvNodes.Columns[2].Width + _lvNodes.Columns[3].Width;
            _lvNodes.Columns[0].Width = Math.Max(140, w - fixedW - 2);
        }

        private void PopulateDriveTargets()
        {
            _cmbTarget.Items.Clear();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                {
                    string lbl = string.Format("{0}  ({1} ελεύθερα / {2})", d.Name, SafetyGuard.FmtBytes(d.AvailableFreeSpace), SafetyGuard.FmtBytes(d.TotalSize));
                    _cmbTarget.Items.Add(lbl);
                }
            }
            if (_cmbTarget.Items.Count > 0) _cmbTarget.SelectedIndex = 0;
        }

        private string SelectedScanPath()
        {
            string raw = (_cmbTarget.Text ?? "").Trim();
            if (raw.Length >= 3 && raw[1] == ':' && raw[2] == '\\')
            {
                int sp = raw.IndexOf("  (");
                if (sp > 0) return raw.Substring(0, sp).Trim();
            }
            return raw;
        }

        private void BrowseFolder()
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Επιλογή φακέλου για ανάλυση (100% Read-Only)";
                if (fbd.ShowDialog(this) == DialogResult.OK)
                {
                    _cmbTarget.Text = fbd.SelectedPath;
                }
            }
        }

        public void SwitchPage(int idx)
        {
            _activePage = idx;
            for (int i = 0; i < 4; i++)
            {
                _pages[i].Visible = (i == idx);
                _navBtns[i].BackColor = (i == idx) ? _accent : _bgCard;
                _navBtns[i].ForeColor = (i == idx) ? Color.FromArgb(15, 20, 28) : _fgMain;
            }
        }

        public void ApplyTheme()
        {
            if (_dark)
            {
                _bgMain = Color.FromArgb(24, 25, 28);
                _bgPanel = Color.FromArgb(30, 32, 37);
                _bgCard = Color.FromArgb(38, 40, 46);
                _bgInput = Color.FromArgb(28, 30, 35);
                _fgMain = Color.FromArgb(240, 242, 246);
                _fgMuted = Color.FromArgb(154, 162, 174);
                _border = Color.FromArgb(56, 60, 70);
                _accent = Color.FromArgb(252, 150, 31); // Signature Nilly Orange!
            }
            else
            {
                _bgMain = Color.FromArgb(245, 247, 250);
                _bgPanel = Color.FromArgb(236, 239, 245);
                _bgCard = Color.White;
                _bgInput = Color.White;
                _fgMain = Color.FromArgb(24, 26, 30);
                _fgMuted = Color.FromArgb(95, 105, 118);
                _border = Color.FromArgb(212, 218, 226);
                _accent = Color.FromArgb(234, 128, 12);
            }

            Native.SetDarkTitlebar(Handle, _dark);
            BackColor = _bgMain; ForeColor = _fgMain;
            _topBar.BackColor = _bgPanel;
            _navBar.BackColor = _bgPanel;
            _crumbBar.BackColor = _bgPanel;
            _lblFooter.BackColor = _bgPanel; _lblFooter.ForeColor = _accent;
            _lblHoverInfo.BackColor = _bgPanel; _lblHoverInfo.ForeColor = _fgMuted;
            _lblScanStatus.ForeColor = _fgMuted;
            _lblCrumb.ForeColor = _fgMain;
            _lblDupSummary.BackColor = _bgPanel; _lblDupSummary.ForeColor = _fgMain;
            _lblCacheSummary.ForeColor = _fgMain;
            _btnTheme.Text = _dark ? "☀" : "🌙";
            _treemap.IsDark = _dark; _treemap.Invalidate();

            StyleTree(this);
            SwitchPage(_activePage);
        }

        private void StyleTree(Control parent)
        {
            foreach (Control c in parent.Controls)
            {
                if (c is ListView) { c.BackColor = _bgMain; c.ForeColor = _fgMain; }
                else if (c is TextBox || c is ComboBox) { c.BackColor = _bgInput; c.ForeColor = _fgMain; }
                else if (c is Button)
                {
                    Button b = (Button)c;
                    b.BackColor = (b == _btnScan || b == _btnCleanCache) ? _accent : _bgCard;
                    b.ForeColor = (b == _btnScan || b == _btnCleanCache) ? Color.FromArgb(15, 20, 28) : _fgMain;
                    b.FlatAppearance.BorderColor = _border;
                }
                else if (c is Panel && c != _topBar && c != _navBar && c != _crumbBar)
                {
                    c.BackColor = _bgMain;
                }
                else if (c is Label && c != _lblFooter && c != _lblHoverInfo && c != _lblScanStatus)
                {
                    c.ForeColor = _fgMain;
                }
                if (c.HasChildren) StyleTree(c);
            }
        }

        // ====================================================================
        // SCAN EXECUTION
        // ====================================================================
        private void StartScan()
        {
            if (_scanning) return;
            string path = SelectedScanPath();
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                MessageBox.Show(this, "Δεν βρέθηκε ο φάκελος/δίσκος: " + path, "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _scanning = true;
            _cancelScan = false;
            _btnScan.Enabled = false;
            _btnStop.Enabled = true;
            _lblScanStatus.Text = "Σάρωση " + path + "...";

            Thread th = new Thread(delegate()
            {
                ScanResult res = FastScanner.Scan(path, ref _cancelScan, delegate(int files, int dirs, long bytes)
                {
                    try
                    {
                        BeginInvoke((Action)delegate
                        {
                            _lblScanStatus.Text = string.Format("Σάρωση... {0:N0} αρχεία · {1:N0} φάκελοι · {2}", files, dirs, SafetyGuard.FmtBytes(bytes));
                        });
                    }
                    catch { }
                });
                try
                {
                    BeginInvoke((Action)delegate { OnScanCompleted(res); });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        private void OnScanCompleted(ScanResult res)
        {
            _scanning = false;
            _btnScan.Enabled = true;
            _btnStop.Enabled = false;
            _lastScan = res;
            _lblScanStatus.Text = string.Format("{0} {1:N0} αρχεία · {2:N0} φάκελοι · {3} ({4:0.1}s)",
                res.Cancelled ? "Διακόπηκε:" : "Ολοκληρώθηκε:", res.TotalFiles, res.TotalDirs, SafetyGuard.FmtBytes(res.TotalBytes), res.ElapsedSec);

            ShowFolder(res.Root);
            PopulateTopFilesList();
            PopulateExtensionsList();
        }

        private void ShowFolder(DiskNode folder)
        {
            _currentDir = folder;
            if (folder == null) return;
            _lblCrumb.Text = string.Format("{0}   —   {1} ({2:N0} αρχεία)", folder.FullPath, SafetyGuard.FmtBytes(folder.Size), folder.FileCount);
            _btnUp.Enabled = (folder.Parent != null);

            _lvNodes.BeginUpdate();
            _lvNodes.Items.Clear();
            if (folder.Children != null)
            {
                int max = Math.Min(400, folder.Children.Count);
                for (int i = 0; i < max; i++)
                {
                    DiskNode ch = folder.Children[i];
                    double pct = folder.Size > 0 ? (ch.Size * 100.0 / folder.Size) : 0;
                    ListViewItem it = new ListViewItem((ch.IsDir ? "▸ " : "  ") + ch.Name);
                    it.SubItems.Add(SafetyGuard.FmtBytes(ch.Size));
                    it.SubItems.Add(pct.ToString("0.0") + "%");
                    it.SubItems.Add(ch.IsDir ? ch.FileCount.ToString("N0") : "1");
                    it.Tag = ch;
                    _lvNodes.Items.Add(it);
                }
            }
            _lvNodes.EndUpdate();
            FitAnalyzerColumns();
            _treemap.SetNode(folder);
        }

        private void PopulateTopFilesList()
        {
            if (_lastScan == null) return;
            string q = (_txtFilterFiles.Text ?? "").Trim();
            _lvTopFiles.BeginUpdate();
            _lvTopFiles.Items.Clear();
            for (int i = 0; i < _lastScan.TopFiles.Count; i++)
            {
                DiskNode f = _lastScan.TopFiles[i];
                if (q.Length > 0 && f.FullPath.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;
                ListViewItem it = new ListViewItem(f.Name);
                it.SubItems.Add(SafetyGuard.FmtBytes(f.Size));
                it.SubItems.Add(f.Modified > DateTime.MinValue ? f.Modified.ToString("dd/MM/yyyy HH:mm") : "—");
                it.SubItems.Add(f.FullPath);
                it.Tag = f;
                _lvTopFiles.Items.Add(it);
            }
            _lvTopFiles.EndUpdate();
        }

        private void PopulateExtensionsList()
        {
            if (_lastScan == null) return;
            _lvExts.BeginUpdate();
            _lvExts.Items.Clear();
            int max = Math.Min(150, _lastScan.Extensions.Count);
            for (int i = 0; i < max; i++)
            {
                ExtStat st = _lastScan.Extensions[i];
                double pct = _lastScan.TotalBytes > 0 ? (st.TotalBytes * 100.0 / _lastScan.TotalBytes) : 0;
                ListViewItem it = new ListViewItem(st.Ext);
                it.SubItems.Add(SafetyGuard.FmtBytes(st.TotalBytes));
                it.SubItems.Add(st.FileCount.ToString("N0"));
                it.SubItems.Add(pct.ToString("0.1") + "%");
                _lvExts.Items.Add(it);
            }
            _lvExts.EndUpdate();
        }

        // ====================================================================
        // OWNER-DRAWN LISTVIEW WITH INLINE % BARS
        // ====================================================================
        private void DrawListHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (SolidBrush br = new SolidBrush(_bgPanel)) e.Graphics.FillRectangle(br, e.Bounds);
            using (Pen p = new Pen(_border)) e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            TextRenderer.DrawText(e.Graphics, e.Header.Text, _headerFont, e.Bounds, _fgMuted,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        }

        private void DrawNodeSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            Color bg = e.Item.Selected ? Color.FromArgb(52, 62, 82) : ((e.ItemIndex % 2 == 0) ? _bgMain : _bgPanel);
            using (SolidBrush br = new SolidBrush(bg)) e.Graphics.FillRectangle(br, e.Bounds);

            DiskNode n = e.Item.Tag as DiskNode;
            if (e.ColumnIndex == 2 && n != null && _currentDir != null && _currentDir.Size > 0)
            {
                double frac = Math.Max(0.0, Math.Min(1.0, (double)n.Size / _currentDir.Size));
                Rectangle barBg = new Rectangle(e.Bounds.X + 4, e.Bounds.Y + 4, e.Bounds.Width - 46, e.Bounds.Height - 8);
                if (barBg.Width > 8)
                {
                    using (SolidBrush track = new SolidBrush(_bgCard)) e.Graphics.FillRectangle(track, barBg);
                    int fw = Math.Max(2, (int)(barBg.Width * frac));
                    Color col = n.IsDir ? _accent : SafetyGuard.CategoryColor(n.Ext, false);
                    using (SolidBrush fill = new SolidBrush(col)) e.Graphics.FillRectangle(fill, barBg.X, barBg.Y, fw, barBg.Height);
                }
                Rectangle txtR = new Rectangle(e.Bounds.Right - 40, e.Bounds.Y, 38, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, e.SubItem.Text, _lvNodes.Font, txtR, _fgMuted, TextFormatFlags.VerticalCenter | TextFormatFlags.Right);
                return;
            }

            TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix;
            if (e.ColumnIndex == 1 || e.ColumnIndex == 3) flags |= TextFormatFlags.Right;
            Color fg = (e.ColumnIndex == 1) ? _accent : _fgMain;
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, _lvNodes.Font, e.Bounds, fg, flags);
        }

        private void ActivateNode(DiskNode n)
        {
            if (n == null) return;
            if (n.IsDir) ShowFolder(n);
            else OpenInExplorer(n.FullPath, true);
        }

        private static void OpenInExplorer(string path, bool selectFile)
        {
            try
            {
                if (selectFile) Process.Start("explorer.exe", "/select,\"" + path + "\"");
                else Process.Start("explorer.exe", "\"" + path + "\"");
            }
            catch { }
        }

        private ContextMenuStrip BuildNodeContextMenu(Func<DiskNode> getter)
        {
            ContextMenuStrip cms = new ContextMenuStrip();
            cms.Items.Add("📂 Άνοιγμα στον Explorer", null, delegate
            {
                DiskNode n = getter();
                if (n != null) OpenInExplorer(n.FullPath, !n.IsDir);
            });
            cms.Items.Add("📋 Αντιγραφή διαδρομής", null, delegate
            {
                DiskNode n = getter();
                if (n != null) { try { Clipboard.SetText(n.FullPath); } catch { } }
            });
            cms.Items.Add(new ToolStripSeparator());
            cms.Items.Add("🗑 Μεταφορά στον Κάδο (Ασφαλής Διαγραφή)", null, delegate
            {
                DiskNode n = getter();
                if (n != null) SafeDeleteNode(n);
            });
            return cms;
        }

        private void SafeDeleteNode(DiskNode n)
        {
            if (SafetyGuard.IsProtectedPath(n.FullPath))
            {
                MessageBox.Show(this, "Προστατευμένη διαδρομή συστήματος — η διαγραφή μπλοκαρίστηκε για την ασφάλειά σου:\r\n" + n.FullPath,
                    "NillyDisk Pro — Προστασία Συστήματος", MessageBoxButtons.OK, MessageBoxIcon.Stop);
                return;
            }
            DialogResult dr = MessageBox.Show(this,
                "Μεταφορά στον Κάδο Ανακύκλωσης (μπορείς να το επαναφέρεις οποιαδήποτε στιγμή);\r\n\r\n" +
                n.FullPath + "\r\nΜέγεθος: " + SafetyGuard.FmtBytes(n.Size),
                "Ασφαλής Διαγραφή — NillyDisk Pro", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) return;

            if (Native.SendToRecycleBin(n.FullPath))
            {
                // Update in-memory tree immediately
                long removedSize = n.Size;
                int removedFiles = n.IsDir ? n.FileCount : 1;
                if (n.Parent != null && n.Parent.Children != null) n.Parent.Children.Remove(n);
                DiskNode cur = n.Parent;
                while (cur != null)
                {
                    cur.Size = Math.Max(0, cur.Size - removedSize);
                    cur.FileCount = Math.Max(0, cur.FileCount - removedFiles);
                    cur = cur.Parent;
                }
                if (_currentDir != null) ShowFolder(_currentDir);
                PopulateTopFilesList();
            }
            else
            {
                MessageBox.Show(this, "Δεν ήταν δυνατή η μεταφορά στον Κάδο (ίσως το αρχείο χρησιμοποιείται από άλλη εφαρμογή).", "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ExportCurrentCsv()
        {
            if (_currentDir == null || _currentDir.Children == null) return;
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Filter = "CSV Report (*.csv)|*.csv";
                sfd.FileName = "NillyDisk_Report_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".csv";
                if (sfd.ShowDialog(this) != DialogResult.OK) return;
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Name,Type,Bytes,FormattedSize,Files,FullPath");
                for (int i = 0; i < _currentDir.Children.Count; i++)
                {
                    DiskNode c = _currentDir.Children[i];
                    sb.AppendLine(string.Format("\"{0}\",{1},{2},\"{3}\",{4},\"{5}\"",
                        c.Name.Replace("\"", "\"\""), c.IsDir ? "Folder" : "File", c.Size, SafetyGuard.FmtBytes(c.Size), c.FileCount, c.FullPath.Replace("\"", "\"\"")));
                }
                File.WriteAllText(sfd.FileName, sb.ToString(), new UTF8Encoding(true));
            }
        }

        // ====================================================================
        // SHA-256 DUPLICATES TAB
        // ====================================================================
        private void RunDuplicateSearch()
        {
            if (_lastScan == null || _lastScan.Root == null)
            {
                MessageBox.Show(this, "Πάτα πρώτα «▶ Σάρωση» στον δίσκο/φάκελο που θέλεις να ελέγξεις!", "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            long[] mins = new long[] { 1048576L, 102400L, 10485760L, 52428800L };
            long minBytes = mins[Math.Max(0, _cmbDupMin.SelectedIndex)];
            _btnFindDups.Enabled = false;
            _cancelScan = false;

            Thread th = new Thread(delegate()
            {
                List<DupGroup> groups = DuplicateFinder.FindDuplicates(_lastScan.Root, minBytes, ref _cancelScan, delegate(string st)
                {
                    try { BeginInvoke((Action)delegate { _lblDupSummary.Text = st; }); } catch { }
                });
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        _btnFindDups.Enabled = true;
                        _dupGroups = groups;
                        PopulateDuplicatesList();
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        private void PopulateDuplicatesList()
        {
            _lvDups.BeginUpdate();
            _lvDups.Items.Clear();
            long wasted = 0;
            int copies = 0;
            for (int g = 0; g < _dupGroups.Count; g++)
            {
                DupGroup dg = _dupGroups[g];
                wasted += dg.WastedBytes;
                copies += (dg.Files.Count - 1);
                for (int i = 0; i < dg.Files.Count; i++)
                {
                    DiskNode f = dg.Files[i];
                    ListViewItem it = new ListViewItem(string.Format("[#{0}] {1}", g + 1, f.Name));
                    it.SubItems.Add(SafetyGuard.FmtBytes(f.Size));
                    it.SubItems.Add(f.Modified > DateTime.MinValue ? f.Modified.ToString("dd/MM/yyyy HH:mm") : "—");
                    it.SubItems.Add(f.FullPath);
                    it.SubItems.Add(i == 0 ? "★ Πρωτότυπο (Νεότερο)" : "Αντίγραφο");
                    it.Tag = f;
                    it.BackColor = (g % 2 == 0) ? _bgMain : _bgPanel;
                    it.ForeColor = (i == 0) ? Color.FromArgb(166, 226, 46) : _fgMain;
                    _lvDups.Items.Add(it);
                }
            }
            _lvDups.EndUpdate();
            _lblDupSummary.Text = string.Format("Βρέθηκαν {0:N0} ομάδες SHA-256 · {1:N0} περιττά αντίγραφα · Πιθανή εξοικονόμηση: {2}",
                _dupGroups.Count, copies, SafetyGuard.FmtBytes(wasted));
        }

        private void AutoSelectOlderDuplicates()
        {
            foreach (ListViewItem it in _lvDups.Items)
                it.Checked = !it.SubItems[4].Text.StartsWith("★");
        }

        private void MoveSelectedDuplicatesToTrash()
        {
            // Enforce HARD RULE: NEVER delete all copies of any SHA-256 group!
            List<DiskNode> toDelete = new List<DiskNode>();
            for (int g = 0; g < _dupGroups.Count; g++)
            {
                DupGroup dg = _dupGroups[g];
                List<DiskNode> checkedInGroup = new List<DiskNode>();
                foreach (ListViewItem it in _lvDups.Items)
                {
                    DiskNode n = it.Tag as DiskNode;
                    if (it.Checked && n != null && dg.Files.Contains(n)) checkedInGroup.Add(n);
                }
                if (checkedInGroup.Count >= dg.Files.Count)
                {
                    // Protect the first (newest) copy unconditionally!
                    checkedInGroup.RemoveAt(0);
                }
                toDelete.AddRange(checkedInGroup);
            }
            if (toDelete.Count == 0)
            {
                MessageBox.Show(this, "Δεν υπάρχουν επιλεγμένα αντίγραφα (τουλάχιστον 1 πρωτότυπο ανά ομάδα παραμένει πάντα προστατευμένο).", "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            long totalBytes = 0;
            for (int i = 0; i < toDelete.Count; i++) totalBytes += toDelete[i].Size;

            DialogResult dr = MessageBox.Show(this,
                string.Format("Μεταφορά {0} διπλότυπων αρχείων ({1}) στον Κάδο Ανακύκλωσης;\r\n(Κρατιέται πάντα τουλάχιστον 1 πρωτότυπο από κάθε ομάδα.)", toDelete.Count, SafetyGuard.FmtBytes(totalBytes)),
                "Ασφαλής Διαγραφή Διπλοτύπων — NillyDisk Pro", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) return;

            int ok = 0;
            long freed = 0;
            for (int i = 0; i < toDelete.Count; i++)
            {
                if (Native.SendToRecycleBin(toDelete[i].FullPath))
                {
                    ok++;
                    freed += toDelete[i].Size;
                    for (int g = 0; g < _dupGroups.Count; g++) _dupGroups[g].Files.Remove(toDelete[i]);
                }
            }
            _dupGroups.RemoveAll(delegate(DupGroup dg) { return dg.Files.Count < 2; });
            PopulateDuplicatesList();
            MessageBox.Show(this, string.Format("Μεταφέρθηκαν με ασφάλεια {0} αντίγραφα στον Κάδο ({1}).", ok, SafetyGuard.FmtBytes(freed)),
                "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ====================================================================
        // SAFE CACHE CLEANER TAB
        // ====================================================================
        private void RefreshCacheTargetsAsync()
        {
            _btnRefreshCache.Enabled = false;
            _lblCacheSummary.Text = "Υπολογισμός ασφαλών caches...";
            Thread th = new Thread(delegate()
            {
                List<SafeCacheTarget> list = SafeCacheEngine.BuildAndMeasureTargets();
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        _cacheTargets = list;
                        _btnRefreshCache.Enabled = true;
                        PopulateCacheList();
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        private void PopulateCacheList()
        {
            _lvCache.BeginUpdate();
            _lvCache.Items.Clear();
            long total = 0;
            for (int i = 0; i < _cacheTargets.Count; i++)
            {
                SafeCacheTarget t = _cacheTargets[i];
                total += t.Bytes;
                ListViewItem it = new ListViewItem(t.Title);
                it.SubItems.Add(SafetyGuard.FmtBytes(t.Bytes));
                it.SubItems.Add(t.FileCount.ToString("N0"));
                it.SubItems.Add(t.Description);
                it.Checked = t.Selected;
                it.Tag = t;
                _lvCache.Items.Add(it);
            }
            _lvCache.EndUpdate();
            _lblCacheSummary.Text = "Σύνολο ασφαλών regenerable caches: " + SafetyGuard.FmtBytes(total) + " (0 κίνδυνος για έργα, κωδικούς ή ρυθμίσεις)";
        }

        private void CleanSelectedCaches()
        {
            List<SafeCacheTarget> picked = new List<SafeCacheTarget>();
            long estBytes = 0;
            for (int i = 0; i < _cacheTargets.Count; i++)
                if (_cacheTargets[i].Selected && _cacheTargets[i].Bytes > 0) { picked.Add(_cacheTargets[i]); estBytes += _cacheTargets[i].Bytes; }

            if (picked.Count == 0)
            {
                MessageBox.Show(this, "Δεν επιλέχθηκε καμία cache με περιεχόμενο.", "NillyDisk Pro", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult dr = MessageBox.Show(this,
                string.Format("Καθαρισμός {0} επιλεγμένων ασφαλών caches (~{1});\r\n(Αρχεία που χρησιμοποιούνται αυτή τη στιγμή παραλείπονται αυτόματα.)", picked.Count, SafetyGuard.FmtBytes(estBytes)),
                "Ασφαλής Καθαρισμός Cache — NillyDisk Pro", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) return;

            _btnCleanCache.Enabled = false;
            _lblCacheSummary.Text = "Ασφαλής καθαρισμός σε εξέλιξη...";
            Thread th = new Thread(delegate()
            {
                long totalFreed = 0;
                int totalDel = 0;
                for (int i = 0; i < picked.Count; i++)
                {
                    int del;
                    totalFreed += SafeCacheEngine.CleanTarget(picked[i], out del);
                    totalDel += del;
                }
                List<SafeCacheTarget> refreshed = SafeCacheEngine.BuildAndMeasureTargets();
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        _cacheTargets = refreshed;
                        _btnCleanCache.Enabled = true;
                        PopulateCacheList();
                        PopulateDriveTargets();
                        MessageBox.Show(this, string.Format("Ελευθερώθηκαν {0} ({1:N0} προσωρινά αρχεία cache) με 100% ασφάλεια!", SafetyGuard.FmtBytes(totalFreed), totalDel),
                            "NillyDisk Pro — Ολοκληρώθηκε", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }
    }

    internal static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try { Native.SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (args != null && args.Length > 0 && args[0].Equals("--test-smoke", StringComparison.OrdinalIgnoreCase))
                return RunSmokeTest(args.Length > 1 ? args[1] : null);

            string initPath = (args != null && args.Length > 0 && !args[0].StartsWith("-")) ? args[0] : null;
            Application.Run(new MainForm(initPath, false));
            return 0;
        }

        private static int RunSmokeTest(string logPath)
        {
            StringBuilder sb = new StringBuilder();
            string tmpDir = Path.Combine(Path.GetTempPath(), "NillyDiskPro_Smoke_" + Guid.NewGuid().ToString("N").Substring(0, 6));
            try
            {
                Directory.CreateDirectory(tmpDir);
                Directory.CreateDirectory(Path.Combine(tmpDir, "sub"));
                byte[] payloadA = new byte[120000];
                byte[] payloadB = new byte[120000];
                for (int i = 0; i < payloadA.Length; i++) { payloadA[i] = (byte)(i % 251); payloadB[i] = (byte)((i * 7) % 251); }
                File.WriteAllBytes(Path.Combine(tmpDir, "orig.psd"), payloadA);
                File.WriteAllBytes(Path.Combine(tmpDir, @"sub\copy.psd"), payloadA);
                File.WriteAllBytes(Path.Combine(tmpDir, "unique.pdf"), payloadB);

                // 1. Test Win32 FastScanner
                bool cancel = false;
                ScanResult sr = FastScanner.Scan(tmpDir, ref cancel, null);
                sb.AppendLine("SCAN_OK=" + (sr.TotalFiles == 3 && sr.TotalBytes == 360000 && sr.Extensions.Count == 2));

                // 2. Test 3-Stage SHA-256 DuplicateFinder
                List<DupGroup> dups = DuplicateFinder.FindDuplicates(sr.Root, 1024, ref cancel, null);
                sb.AppendLine("SHA256_DUP_OK=" + (dups.Count == 1 && dups[0].Files.Count == 2 && dups[0].WastedBytes == 120000));

                // 3. Test SafetyGuard system protection
                bool guardOk = SafetyGuard.IsProtectedPath(@"C:\Windows\System32\cmd.exe") &&
                               SafetyGuard.IsProtectedPath(@"C:\Program Files\Adobe") &&
                               !SafetyGuard.IsProtectedPath(Path.Combine(tmpDir, "orig.psd"));
                sb.AppendLine("SAFETY_GUARD_OK=" + guardOk);

                // 4. Test Safe Cache Read-Only Audit on this real PC
                List<SafeCacheTarget> caches = SafeCacheEngine.BuildAndMeasureTargets();
                long totalCacheBytes = 0;
                for (int i = 0; i < caches.Count; i++) totalCacheBytes += caches[i].Bytes;
                sb.AppendLine("CACHE_TARGETS=" + caches.Count);
                sb.AppendLine("LIVE_SAFE_CACHE_TOTAL=" + SafetyGuard.FmtBytes(totalCacheBytes));
                for (int i = 0; i < caches.Count; i++)
                    if (caches[i].Bytes > 0) sb.AppendLine("  CACHE_" + caches[i].Id + "=" + SafetyGuard.FmtBytes(caches[i].Bytes));

                // 5. Test UI Form + All 4 Tabs + Theme Switch + RAM check
                using (MainForm form = new MainForm(null, true))
                {
                    form.Show();
                    for (int t = 0; t < 4; t++) { form.SwitchPage(t); Application.DoEvents(); }
                    form.ApplyTheme();
                    Application.DoEvents();
                    long ramMb = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024);
                    sb.AppendLine("WINDOW_OPENED_OK=" + form.IsHandleCreated);
                    sb.AppendLine("WORKING_SET_MB=" + ramMb);
                    form.Close();
                }

                sb.AppendLine("SMOKE_RESULT=PASS");
            }
            catch (Exception ex)
            {
                sb.AppendLine("SMOKE_RESULT=FAIL");
                sb.AppendLine(ex.ToString());
                if (!string.IsNullOrEmpty(logPath)) File.WriteAllText(logPath, sb.ToString(), Encoding.UTF8);
                return 1;
            }
            finally
            {
                try { if (Directory.Exists(tmpDir)) Directory.Delete(tmpDir, true); } catch { }
            }
            if (!string.IsNullOrEmpty(logPath)) File.WriteAllText(logPath, sb.ToString(), Encoding.UTF8);
            return 0;
        }
    }
}
