package top.nkbe.splitpatch;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.Inflater;

/**
 * SplitPatch 拆分核心 —— 纯 Java，不依赖任何 Android API，也不依赖第三方库。
 *
 * 为什么不用 java.util.zip.ZipFile？
 * LSPatch / NPatch 用 apkzlib 的 NestedZip 技术，把原始 APK 以 STORED 方式整块
 * 对齐嵌入修补包，并把原包内部条目同时登记到外层中央目录，导致 ZIP 条目数据区
 * 「重叠」。ZipFile 在部分实现上会拒绝这类条目（Python 3.13+ 直接抛 zip bomb），
 * 而且我们需要对 STORED 大块做零解压、逐字节原样导出。所以这里自己解析
 * EOCD → 中央目录 → local file header，按 compress_size 定位数据区，
 * 自行处理 STORED / DEFLATED，并用中央目录 CRC32 校验。
 *
 * 同一个类既给 Android App 用，也能在桌面 JVM 上直接跑 main() 做验证。
 */
public final class SplitCore {

    private static final long EOCD_SIG = 0x06054b50L;
    private static final long CEN_SIG = 0x02014b50L;
    private static final long LOC_SIG = 0x04034b50L;
    private static final int BUF = 1 << 16;

    private SplitCore() {}

    /**
     * 展开分发包时用的临时目录。Android 上 java.io.tmpdir 未必可写，
     * 所以 App 会在启动时把它指向 getCacheDir()；桌面 JVM 留空即可。
     */
    public static File tempBase = null;

    // ---------------------------------------------------------------------
    // 对外的数据结构与回调
    // ---------------------------------------------------------------------
    public interface Progress {
        void on(String text, int percent);
        void log(String msg);
    }

    public static class Options {
        public boolean exportInjected = false;
        public boolean exportPayload = false;
        public boolean makeManifest = true;
    }

    public static class OutFile {
        public String role;        // original / module / injected
        public String name;
        public String path;
        public String sourceEntry;
        public long size;
        public String sha256;
        public boolean crcOk;
        public boolean apkValid;
        public int entries = -1;
        public int dexCount = -1;
        public String note;
    }

    public static class Result {
        public boolean found;
        public String framework = "未识别";
        public String mode = "未知";
        public String prefix = "";
        public String outputDir;
        public int totalEntries;
        public String configJson = "";
        public List<OutFile> files = new ArrayList<OutFile>();
        public List<String> warnings = new ArrayList<String>();
        public List<String> notes = new ArrayList<String>();
        public String manifestPath;
    }

    // ---------------------------------------------------------------------
    // ZIP 底层解析
    // ---------------------------------------------------------------------
    public static class Entry {
        String name;
        int method;
        long crc, csize, usize, localOffset;
    }

    public static class Zip {
        private final RandomAccessFile raf;
        public final List<Entry> entries = new ArrayList<Entry>();

        public Zip(File f) throws IOException {
            raf = new RandomAccessFile(f, "r");
            try {
                parse();
            } catch (IOException e) {
                raf.close();
                throw e;
            }
        }

        public void close() throws IOException { raf.close(); }

        public Entry find(String name) {
            for (Entry e : entries) if (e.name.equals(name)) return e;
            return null;
        }

        private void parse() throws IOException {
            long len = raf.length();
            int tailLen = (int) Math.min(len, 65557L);
            byte[] tail = new byte[tailLen];
            raf.seek(len - tailLen);
            raf.readFully(tail);

            long cdOffset = -1, cdSize = -1;
            for (int i = tailLen - 22; i >= 0; i--) {
                if (u32(tail, i) == EOCD_SIG) {
                    int commentLen = u16(tail, i + 20);
                    if (i + 22 + commentLen > tailLen) continue;
                    cdSize = u32(tail, i + 12);
                    cdOffset = u32(tail, i + 16);
                    break;
                }
            }
            if (cdOffset < 0 || cdSize < 0 || cdOffset + cdSize > len) {
                throw new IOException("找不到有效的 ZIP 中央目录（文件可能不是 APK/ZIP）");
            }
            if (cdSize > Integer.MAX_VALUE) throw new IOException("中央目录过大");

            byte[] cd = new byte[(int) cdSize];
            raf.seek(cdOffset);
            raf.readFully(cd);

            int p = 0;
            while (p + 46 <= cd.length) {
                if (u32(cd, p) != CEN_SIG) break;
                Entry e = new Entry();
                int flags = u16(cd, p + 8);
                e.method = u16(cd, p + 10);
                e.crc = u32(cd, p + 16);
                e.csize = u32(cd, p + 20);
                e.usize = u32(cd, p + 24);
                int nameLen = u16(cd, p + 28);
                int extraLen = u16(cd, p + 30);
                int commentLen = u16(cd, p + 32);
                e.localOffset = u32(cd, p + 42);
                if (p + 46 + nameLen + extraLen + commentLen > cd.length) break;
                e.name = decodeName(cd, p + 46, nameLen, flags);
                if (e.csize == 0xFFFFFFFFL || e.usize == 0xFFFFFFFFL
                        || e.localOffset == 0xFFFFFFFFL) {
                    applyZip64(cd, p + 46 + nameLen, extraLen, e);
                }
                entries.add(e);
                p += 46 + nameLen + extraLen + commentLen;
            }
        }

        /** 按 central directory 的偏移定位 local header，流式导出条目数据。 */
        public Verify extractTo(Entry e, OutputStream out, Progress cb,
                                String label, int base, int span) throws IOException {
            raf.seek(e.localOffset);
            byte[] lh = new byte[30];
            raf.readFully(lh);
            if (u32(lh, 0) != LOC_SIG) {
                throw new IOException("local header 损坏：" + e.name);
            }
            // 必须用 local header 的长度（apkzlib 会在 extra 里塞对齐填充，
            // 与中央目录的 extra 长度不同；用错会读到脏数据）
            int nameLen = u16(lh, 26), extraLen = u16(lh, 28);
            long start = e.localOffset + 30 + nameLen + extraLen;
            raf.seek(start);

            CRC32 crc = new CRC32();
            MessageDigest sha;
            try {
                sha = MessageDigest.getInstance("SHA-256");
            } catch (Exception ex) {
                throw new IOException(ex);
            }

            long remaining = e.csize, written = 0;
            int[] lastPct = {-1};
            byte[] in = new byte[BUF], outBuf = new byte[BUF];
            if (e.method == 0) { // STORED：原样搬运，不解压、不改动一个字节
                while (remaining > 0) {
                    int n = (int) Math.min(BUF, remaining);
                    raf.readFully(in, 0, n);
                    out.write(in, 0, n);
                    crc.update(in, 0, n);
                    sha.update(in, 0, n);
                    remaining -= n;
                    written += n;
                    report(cb, label, base, span, written, e.usize, lastPct);
                }
            } else if (e.method == 8) { // DEFLATED：raw deflate（无 zlib 头）
                Inflater inf = new Inflater(true);
                try {
                    while (remaining > 0) {
                        int n = (int) Math.min(BUF, remaining);
                        raf.readFully(in, 0, n);
                        inf.setInput(in, 0, n);
                        written += drain(inf, outBuf, out, crc, sha);
                        remaining -= n;
                        report(cb, label, base, span, written, e.usize, lastPct);
                    }
                    // 收尾，把解压器缓冲区里剩下的字节抽干净
                    written += drain(inf, outBuf, out, crc, sha);
                    report(cb, label, base, span, written, e.usize, lastPct);
                } finally {
                    inf.end();
                }
            } else {
                throw new IOException("不支持的压缩方法 " + e.method + "：" + e.name);
            }
            return new Verify(written, crc.getValue() == e.crc, hex(sha.digest()));
        }

        /** 抽干解压器当前输入，返回本次写出的字节数；进度由外层按累计量算。 */
        private static long drain(Inflater inf, byte[] buf, OutputStream out,
                                  CRC32 crc, MessageDigest sha) throws IOException {
            long written = 0;
            while (!inf.finished() && !inf.needsInput()) {
                int got;
                try {
                    got = inf.inflate(buf);
                } catch (java.util.zip.DataFormatException e) {
                    throw new IOException("deflate 数据损坏：" + e.getMessage());
                }
                if (got <= 0) break;  // 需要更多输入 / 已结束 / 防死循环
                out.write(buf, 0, got);
                crc.update(buf, 0, got);
                sha.update(buf, 0, got);
                written += got;
            }
            return written;
        }

        public Verify extractToFile(Entry e, File dest, Progress cb,
                                    String label, int base, int span) throws IOException {
            File parent = dest.getParentFile();
            if (parent != null) parent.mkdirs();
            OutputStream out = new BufferedOutputStream(new FileOutputStream(dest), BUF);
            try {
                return extractTo(e, out, cb, label, base, span);
            } finally {
                out.close();
            }
        }

        public byte[] readSmall(Entry e) throws IOException {
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) Math.min(e.usize, 1 << 20));
            extractTo(e, bos, null, "", 0, 0);
            return bos.toByteArray();
        }
    }

    public static class Verify {
        public final long size;
        public final boolean crcOk;
        public final String sha256;
        Verify(long size, boolean crcOk, String sha256) {
            this.size = size; this.crcOk = crcOk; this.sha256 = sha256;
        }
    }

    /** 只在整数百分比变化时回调：241MB 文件按 64KB 分块有 3700+ 块，
     *  不节流会把 Android 主线程刷爆。 */
    private static void report(Progress cb, String label, int base, int span,
                               long written, long total, int[] lastPct) {
        if (cb == null || total <= 0) return;
        int pct = base + (int) (span * Math.min(1.0, written / (double) total));
        if (pct <= lastPct[0]) return;
        lastPct[0] = pct;
        cb.on(label, Math.min(100, pct));
    }

    private static int u16(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8);
    }

    private static long u32(byte[] b, int o) {
        return (u16(b, o) & 0xffffL) | ((long) u16(b, o + 2) << 16);
    }

    private static long u64(byte[] b, int o) {
        return u32(b, o) | (u32(b, o + 4) << 32);
    }

    private static String decodeName(byte[] b, int off, int len, int flags) {
        byte[] raw = Arrays.copyOfRange(b, off, off + len);
        String s = new String(raw, StandardCharsets.UTF_8);
        // 老式压缩包可能用 GBK 且没有 UTF-8 标志位
        if ((flags & 0x800) == 0 && s.indexOf('\uFFFD') >= 0) {
            try {
                s = new String(raw, Charset.forName("GBK"));
            } catch (Exception ignored) {}
        }
        return s;
    }

    private static void applyZip64(byte[] cd, int off, int len, Entry e) {
        int p = off, end = off + len;
        while (p + 4 <= end) {
            int tag = u16(cd, p), size = u16(cd, p + 2);
            p += 4;
            if (p + size > end) break;
            if (tag == 0x0001) {
                int q = p;
                if (e.usize == 0xFFFFFFFFL && q + 8 <= p + size) { e.usize = u64(cd, q); q += 8; }
                if (e.csize == 0xFFFFFFFFL && q + 8 <= p + size) { e.csize = u64(cd, q); q += 8; }
                if (e.localOffset == 0xFFFFFFFFL && q + 8 <= p + size) e.localOffset = u64(cd, q);
            }
            p += size;
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // ---------------------------------------------------------------------
    // 输入加载：裸 APK 或分发包 ZIP
    // ---------------------------------------------------------------------
    private static class Loaded {
        File apk;
        String displayName;
        File tempDir;
        Zip zip;
    }

    private static Loaded load(File source, Progress cb) throws IOException {
        if (!source.isFile()) throw new IOException("文件不存在：" + source);
        Loaded ld = new Loaded();
        String lower = source.getName().toLowerCase();
        if (lower.endsWith(".apk")) {
            ld.apk = source;
            ld.displayName = source.getName();
            ld.zip = new Zip(source);
            return ld;
        }
        Zip outer = new Zip(source);
        List<Entry> apks = new ArrayList<Entry>();
        for (Entry e : outer.entries) {
            if (e.name.toLowerCase().endsWith(".apk")) apks.add(e);
        }
        // 手机端通过 SAF 选文件时名字可能没有扩展名；若外层没有内嵌 APK，
        // 就把它本身当修补 APK 解析，避免误报「找不到 .apk」
        if (apks.isEmpty()) {
            ld.apk = source;
            ld.displayName = source.getName();
            ld.zip = outer;
            return ld;
        }
        Collections.sort(apks, new Comparator<Entry>() {
            public int compare(Entry a, Entry b) { return Long.compare(b.usize, a.usize); }
        });
        File base = tempBase != null
                ? tempBase
                : new File(System.getProperty("java.io.tmpdir", "."));
        ld.tempDir = new File(base, "splitpatch_" + System.currentTimeMillis());
        ld.tempDir.mkdirs();
        try {
            int limit = Math.min(8, apks.size());
            File first = null;
            String firstName = null;
            for (int i = 0; i < limit; i++) {
                Entry e = apks.get(i);
                String name = new File(e.name).getName();
                File cand = new File(ld.tempDir, "candidate_" + i + ".apk");
                String label = "展开分发包：" + name + "（" + (e.usize / 1048576) + " MB）";
                cb.log(label);
                Verify v = outer.extractToFile(e, cand, cb, label, 0, 20);
                if (first == null) { first = cand; firstName = name; }
                Zip z = new Zip(cand);
                Detection d = detect(z, cb);
                if (d.found) {
                    cb.log("定位到修补包：" + name);
                    ld.apk = cand;
                    ld.displayName = name;
                    ld.zip = z;
                    return ld;
                }
                z.close();
                if (!v.crcOk) cb.log("警告：候选包 CRC 校验不通过");
            }
            // 都不带注入结构：仍返回最大的那个，交给 detect 给出诊断而不是直接失败
            cb.log("未在分发包中找到明显的集成注入结构，按主包继续分析");
            ld.apk = first;
            ld.displayName = firstName;
            ld.zip = new Zip(first);
            return ld;
        } catch (IOException e) {
            deleteRecursively(ld.tempDir);
            throw e;
        } finally {
            outer.close();
        }
    }

    // ---------------------------------------------------------------------
    // 检测注入结构
    // ---------------------------------------------------------------------
    public static class Detection {
        public boolean found;
        public String framework = "未识别";
        public String mode = "未知";
        public String prefix = "";
        public String originEntry;
        public String configEntry;
        public final List<String> modules = new ArrayList<String>();
        public final List<String> injected = new ArrayList<String>();
        public final List<String> notes = new ArrayList<String>();
        public String configJson = "";
        public int totalEntries;
        int score;
    }

    private static final String[] LOADER_NAMES = {
            "/loader.dex", "/loader.bin", "/metaloader.dex", "/mtprovider.dex"
    };

    private static boolean endsWithAny(String s, String[] suffixes) {
        for (String x : suffixes) if (s.endsWith(x)) return true;
        return false;
    }

    public static Detection detect(Zip z, Progress cb) {
        Detection d = new Detection();
        d.totalEntries = z.entries.size();
        Set<String> roots = new HashSet<String>();
        for (Entry e : z.entries) {
            String n = e.name;
            if (!n.startsWith("assets/") || n.endsWith("/")) continue;
            String root = null;
            if (n.endsWith("/origin.apk") || n.endsWith("/config.json")
                    || endsWithAny(n, LOADER_NAMES)) {
                root = n.substring(0, n.lastIndexOf('/') + 1);
            } else if (n.contains("/modules/") && n.toLowerCase().endsWith(".apk")) {
                root = n.substring(0, n.indexOf("/modules/")) + "/";
            } else if (n.contains("/so/") && n.toLowerCase().endsWith(".so")) {
                root = n.substring(0, n.indexOf("/so/")) + "/";
            }
            if (root == null) continue;
            int slashes = 0;
            for (int i = 0; i < root.length(); i++) if (root.charAt(i) == '/') slashes++;
            if (slashes >= 2) roots.add(root);  // 至少 assets/<seg>/
        }
        // 去掉被更外层 root 包含的候选
        Set<String> filtered = new HashSet<String>();
        for (String r : roots) {
            boolean covered = false;
            for (String o : roots) if (!o.equals(r) && r.startsWith(o)) { covered = true; break; }
            if (!covered) filtered.add(r);
        }

        String best = null;
        int bestScore = 0;
        for (String root : filtered) {
            int score = 0, mods = 0;
            boolean hasOrigin = false, hasConfig = false, hasLoader = false;
            for (Entry e : z.entries) {
                if (!e.name.startsWith(root)) continue;
                if (e.name.endsWith("/origin.apk")) { hasOrigin = true; score += 5; }
                if (e.name.contains("/modules/") && e.name.toLowerCase().endsWith(".apk")) {
                    mods++; score += 3;
                }
                if (e.name.endsWith("/config.json")) { hasConfig = true; score += 3; }
                if (endsWithAny(e.name, LOADER_NAMES)) { hasLoader = true; score += 2; }
            }
            String seg = root.split("/")[1].toLowerCase();
            if (seg.contains("lspatch") || seg.contains("npatch") || seg.contains("lsp")) score += 2;
            if (score > bestScore) { bestScore = score; best = root; }
        }

        if (best == null || bestScore < 3) {
            d.notes.add("未发现 LSPatch/NPatch 集成注入结构，可能不是集成模式打包的软件。");
            return d;
        }
        d.found = true;
        d.score = bestScore;
        d.prefix = best;
        for (Entry e : z.entries) {
            String n = e.name;
            if (!n.startsWith(best)) continue;
            d.injected.add(n);
            if (n.endsWith("/origin.apk")) d.originEntry = n;
            else if (n.endsWith("/config.json")) d.configEntry = n;
            else if (n.contains("/modules/") && n.toLowerCase().endsWith(".apk")) d.modules.add(n);
        }
        Collections.sort(d.modules);
        Collections.sort(d.injected);

        if (d.configEntry != null) {
            try {
                d.configJson = new String(z.readSmall(z.find(d.configEntry)),
                        StandardCharsets.UTF_8);
            } catch (Exception ex) {
                d.notes.add("config.json 读取失败：" + ex.getMessage());
            }
        }

        String seg = best.split("/")[1].toLowerCase();
        if (seg.contains("npatch")) d.framework = "NPatch";
        else if (seg.contains("lspatch") || seg.contains("lsp") || d.configJson.contains("lspConfig"))
            d.framework = "LSPatch";
        else d.framework = "LSPatch / NPatch 系（目录名已改写）";

        boolean useManager = jsonBool(d.configJson, "useManager", false);
        if (!d.modules.isEmpty() && !useManager) d.mode = "集成模式（--embed，模块已内置）";
        else if (!d.modules.isEmpty()) d.mode = "内置模块";
        else if (useManager) d.mode = "本地模式（--manager，无内置模块）";
        else d.mode = "未内置模块";

        if (d.originEntry != null) {
            Entry oe = z.find(d.originEntry);
            d.notes.add("发现内嵌原始 APK（" + (oe.usize / 1048576) + " MB，STORED 对齐存放），可字节级还原。");
            int overlap = 0;
            for (Entry e : z.entries) {
                if (e.localOffset > oe.localOffset
                        && e.localOffset < oe.localOffset + oe.csize) overlap++;
            }
            if (overlap > 0) {
                d.notes.add("内嵌原包的 " + overlap + " 个条目共享数据区（NestedZip 重叠），"
                        + "本工具用底层读取绕过 zip bomb 误判。");
            }
        } else {
            d.notes.add("该包未内嵌 origin.apk，无法字节级还原原版软件；仍可提取内置模块。");
        }
        if (jsonStr(d.configJson, "originalSignature") != null)
            d.notes.add("配置里记录了原厂签名摘要。");
        String acf = jsonStr(d.configJson, "appComponentFactory");
        if (acf != null) d.notes.add("原始 AppComponentFactory：" + acf);
        return d;
    }

    private static String jsonStr(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static boolean jsonBool(String json, String key, boolean def) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(json);
        return m.find() ? Boolean.parseBoolean(m.group(1)) : def;
    }

    // ---------------------------------------------------------------------
    // 拆分主流程
    // ---------------------------------------------------------------------
    public static Result split(File source, File outDir, Options opt, Progress cb) throws IOException {
        if (opt == null) opt = new Options();
        Result res = new Result();
        Loaded ld = load(source, cb);
        Zip z = ld.zip;
        try {
            Detection d = detect(z, cb);
            res.found = d.found;
            res.framework = d.framework;
            res.mode = d.mode;
            res.prefix = d.prefix;
            res.totalEntries = d.totalEntries;
            res.configJson = d.configJson;
            res.notes.addAll(d.notes);
            res.outputDir = outDir.getAbsolutePath();
            cb.log("检测结果：" + d.framework + " / " + d.mode);
            cb.log("注入目录：" + (d.prefix.isEmpty() ? "（无）" : d.prefix));
            cb.log("内置模块：" + d.modules.size() + " 个");
            for (String n : d.notes) cb.log("  · " + n);

            outDir.mkdirs();
            String stem = safeStem(ld.displayName);

            // 1) 原版软件：STORED 大块，逐字节原样导出
            if (d.originEntry != null) {
                Entry oe = z.find(d.originEntry);
                String name = stem + "_原版.apk";
                File dest = new File(new File(outDir, "原版软件"), name);
                cb.log("还原原版软件 → " + name);
                Verify v = z.extractToFile(oe, dest, cb,
                        "正在还原原版 " + (oe.usize / 1048576) + " MB", 5, 70);
                OutFile f = makeOut("original", name, dest, oe.name, v,
                        "修补器内嵌的原始字节，含原厂签名，可直接安装");
                fillApkStats(dest, f);
                res.files.add(f);
                if (!v.crcOk) res.warnings.add("原版 APK 的 CRC 与中央目录不一致，请勿直接安装。");
                if (!f.apkValid) res.warnings.add("还原出的原版 APK 不是有效 ZIP。");
            } else {
                res.warnings.add("该包未内嵌 origin.apk，无法还原原版软件；请从官方渠道获取原始安装包。");
            }

            // 2) 内置模块
            for (int i = 0; i < d.modules.size(); i++) {
                String entry = d.modules.get(i);
                Entry e = z.find(entry);
                String name = new File(entry).getName();
                File dest = new File(new File(outDir, "内置模块"), name);
                cb.log("提取内置模块 " + (i + 1) + "/" + d.modules.size() + "：" + name);
                Verify v = z.extractToFile(e, dest, cb, "提取模块 " + name, 78, 12);
                OutFile f = makeOut("module", name, dest, e.name, v,
                        "独立的 Xposed 模块 APK，可单独安装或用于重新集成");
                fillApkStats(dest, f);
                res.files.add(f);
                if (!v.crcOk) res.warnings.add("模块 " + name + " CRC 校验不通过。");
            }

            // 3) 注入组件（可选）
            if (opt.exportInjected) {
                for (String entry : d.injected) {
                    if (entry.endsWith("/") || entry.endsWith("/origin.apk")) continue;
                    if (entry.contains("/modules/") && entry.toLowerCase().endsWith(".apk")) continue;
                    Entry e = z.find(entry);
                    if (e.usize > 64L * 1048576) continue;
                    String rel = entry.substring(d.prefix.length());
                    File dest = new File(new File(outDir, "注入组件"), rel);
                    try {
                        // 注入组件都是小文件，不单独刷进度，避免每个文件都重跑一遍百分比
                        Verify v = z.extractToFile(e, dest, null, "", 0, 0);
                        res.files.add(makeOut("injected", rel, dest, e.name, v, "修补器注入的运行时组件"));
                    } catch (Exception ex) {
                        res.warnings.add("注入组件 " + entry + " 导出失败：" + ex.getMessage());
                    }
                }
            }

            // 4) 清单
            if (opt.makeManifest) {
                File mf = new File(outDir, "manifest.json");
                writeText(mf, buildManifest(res, source, ld.displayName));
                res.manifestPath = mf.getAbsolutePath();
            }
            cb.on("拆分完成", 100);
            return res;
        } finally {
            z.close();
            if (ld.tempDir != null) deleteRecursively(ld.tempDir);
        }
    }

    private static OutFile makeOut(String role, String name, File dest, String entry,
                                   Verify v, String note) {
        OutFile f = new OutFile();
        f.role = role; f.name = name; f.path = dest.getAbsolutePath();
        f.sourceEntry = entry; f.size = v.size; f.crcOk = v.crcOk;
        f.sha256 = v.sha256; f.note = note;
        return f;
    }

    private static void fillApkStats(File apk, OutFile f) {
        Zip z = null;
        try {
            z = new Zip(apk);
            f.apkValid = true;
            f.entries = z.entries.size();
            int dex = 0;
            for (Entry e : z.entries) {
                if (e.name.matches("classes\\d*\\.dex")) dex++;
            }
            f.dexCount = dex;
        } catch (Exception ignored) {
            f.apkValid = false;
        } finally {
            if (z != null) try { z.close(); } catch (IOException ignored) {}
        }
    }

    private static String safeStem(String name) {
        int dot = name.lastIndexOf('.');
        String s = dot > 0 ? name.substring(0, dot) : name;
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_").trim();
        return s.isEmpty() ? "output" : s;
    }

    private static String buildManifest(Result r, File source, String innerApk) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"SplitPatch Android\",\n");
        sb.append("  \"generated_at\": \"").append(new java.util.Date().toString()).append("\",\n");
        sb.append("  \"input\": { \"name\": ").append(q(source.getName()))
                .append(", \"size\": ").append(source.length())
                .append(", \"inner_apk\": ").append(q(innerApk)).append(" },\n");
        sb.append("  \"detection\": { \"framework\": ").append(q(r.framework))
                .append(", \"mode\": ").append(q(r.mode))
                .append(", \"prefix\": ").append(q(r.prefix))
                .append(", \"total_entries\": ").append(r.totalEntries).append(" },\n");
        sb.append("  \"outputs\": [\n");
        for (int i = 0; i < r.files.size(); i++) {
            OutFile f = r.files.get(i);
            sb.append("    { \"role\": ").append(q(f.role))
                    .append(", \"name\": ").append(q(f.name))
                    .append(", \"source_entry\": ").append(q(f.sourceEntry))
                    .append(", \"size\": ").append(f.size)
                    .append(", \"sha256\": ").append(q(f.sha256))
                    .append(", \"crc_ok\": ").append(f.crcOk)
                    .append(", \"apk_valid\": ").append(f.apkValid)
                    .append(", \"entries\": ").append(f.entries).append(" }");
            if (i < r.files.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"warnings\": [");
        for (int i = 0; i < r.warnings.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(q(r.warnings.get(i)));
        }
        sb.append("],\n  \"config\": ").append(r.configJson.isEmpty() ? "{}" : r.configJson).append("\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String q(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "") + "\"";
    }

    private static void writeText(File f, String text) throws IOException {
        f.getParentFile().mkdirs();
        OutputStream out = new FileOutputStream(f);
        try {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } finally {
            out.close();
        }
    }

    private static void deleteRecursively(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) deleteRecursively(k);
        }
        f.delete();
    }

    // ---------------------------------------------------------------------
    // 桌面 JVM 自测入口（Android 端不调用）
    // ---------------------------------------------------------------------
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("用法: java top.nkbe.splitpatch.SplitCore <input> <outdir> [--injected]");
            return;
        }
        Progress cb = new Progress() {
            public void on(String text, int percent) {
                if (!text.isEmpty()) System.out.println("[" + percent + "%] " + text);
            }
            public void log(String msg) { System.out.println(msg); }
        };
        Options opt = new Options();
        for (int i = 2; i < args.length; i++) {
            if ("--injected".equals(args[i])) opt.exportInjected = true;
        }
        try {
            Result r = split(new File(args[0]), new File(args[1]), opt, cb);
            System.out.println("\n=== 结果 ===");
            for (OutFile f : r.files) {
                System.out.println("  [" + f.role + "] " + f.name + "  " + f.size
                        + " bytes  CRC=" + f.crcOk + "  APK=" + f.apkValid
                        + "  entries=" + f.entries + "  sha256=" + f.sha256);
            }
            System.out.println("  warnings: " + r.warnings);
        } catch (Exception e) {
            System.out.println("失败：" + e);
            e.printStackTrace(System.out);
        }
    }
}
