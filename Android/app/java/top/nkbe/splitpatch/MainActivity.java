package top.nkbe.splitpatch;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

/**
 * SplitPatch Android 版界面。
 *
 * 全部 UI 用代码构建（不引布局 XML），配色与桌面版一致。
 * 流程：SAF 选文件 → 复制到私有缓存（ZIP 需要随机访问）→ 后台线程拆分
 *      → 结果写入 下载/SplitPatch/（Android 10+ 用 MediaStore，无需任何权限）
 *      → 结果卡片可点击单分享，也有「分享全部」按钮。
 *
 * 零权限：不选 READ/WRITE_EXTERNAL_STORAGE，安装时不会弹权限框。
 */
public class MainActivity extends Activity {

    private static final int REQ_PICK = 1001;

    private static final int BG = 0xFF14161B;
    private static final int PANEL = 0xFF1D2027;
    private static final int INPUT_BG = 0xFF15171C;
    private static final int BORDER = 0xFF2C313B;
    private static final int FG = 0xFFE7EAF1;
    private static final int MUTED = 0xFF8B93A3;
    private static final int ACCENT = 0xFF3AA98A;
    private static final int GREEN = 0xFF7EE0B8;
    private static final int WARN = 0xFFF0B455;

    private TextView tvFile, tvStatus, tvLog;
    private Button btnPick, btnSplit, btnShare;
    private CheckBox chkInjected, chkManifest;
    private ProgressBar progress;
    private LinearLayout results;
    private ScrollView scroller;
    private final StringBuilder logBuf = new StringBuilder();

    private volatile File workFile;     // 后台线程写、主线程读，必须 volatile
    private volatile boolean busy = false;
    private final ArrayList<Uri> exportedUris = new ArrayList<Uri>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SplitCore.tempBase = getCacheDir();   // Android 上 java.io.tmpdir 未必可写
        getWindow().setStatusBarColor(0xFF17181D);
        getWindow().setNavigationBarColor(BG);
        buildUi();
        log("就绪。点「选择安装包」，挑一个修补后的 .apk 或装着它的 .zip。");
        log("仅对你有权处理的安装包使用 · 纯本地静态解包，不联网。");
    }

    // ------------------------------------------------------------------
    // 界面
    // ------------------------------------------------------------------
    private void buildUi() {
        ScrollView root = new ScrollView(this);
        root.setBackgroundColor(BG);
        root.setFitsSystemWindows(true);   // 内容别顶进状态栏
        scroller = root;

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(18), dp(22), dp(18), dp(28));
        root.addView(box, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));

        TextView title = text("🌿  SplitPatch · 集成包拆分器", 20, FG, true);
        box.addView(title);
        TextView sub = text("把 LSPatch / NPatch 集成模式打包的软件，拆成「原版软件」和「内置模块」", 12, MUTED, false);
        sub.setPadding(0, dp(4), 0, dp(16));
        box.addView(sub);

        // 文件卡片
        LinearLayout fileCard = card();
        fileCard.setOrientation(LinearLayout.VERTICAL);
        btnPick = button("① 选择安装包 / 分发包", false);
        fileCard.addView(btnPick);
        tvFile = text("尚未选择文件", 12, MUTED, false);
        tvFile.setPadding(0, dp(10), 0, 0);
        fileCard.addView(tvFile);
        box.addView(fileCard, cardLp());
        btnPick.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { pickFile(); }
        });

        // 选项卡片
        LinearLayout optCard = card();
        optCard.setOrientation(LinearLayout.VERTICAL);
        chkInjected = check("一并导出注入组件（loader / so / config）", false);
        chkManifest = check("同时导出 manifest.json 清单", true);
        optCard.addView(chkInjected);
        optCard.addView(chkManifest);
        box.addView(optCard, cardLp());

        btnSplit = button("② 开始拆分", true);
        box.addView(btnSplit, fullLp(dp(14), dp(6)));
        enableButton(btnSplit, false);
        btnSplit.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { startSplit(); }
        });

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.setIndeterminate(false);
        box.addView(progress, fullLp(0, dp(10)));

        tvStatus = text("就绪", 12, MUTED, false);
        box.addView(tvStatus, fullLp(0, dp(6)));

        results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        box.addView(results, fullLp(0, dp(6)));

        btnShare = button("分享全部结果", false);
        enableButton(btnShare, false);
        box.addView(btnShare, fullLp(0, dp(8)));
        btnShare.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { shareAll(); }
        });

        TextView logTitle = text("运行日志", 13, GREEN, true);
        logTitle.setPadding(0, dp(10), 0, dp(4));
        box.addView(logTitle);
        tvLog = text("", 11, MUTED, false);
        tvLog.setTypeface(Typeface.MONOSPACE);
        tvLog.setBackground(panelDrawable(INPUT_BG));
        tvLog.setPadding(dp(10), dp(8), dp(10), dp(8));
        box.addView(tvLog, fullLp(0, 0));

        TextView foot = text("拆分出的原版 APK 含原厂签名；若已装修补版，需先卸载再安装。", 11, 0xFF6B7280, false);
        foot.setPadding(0, dp(16), 0, 0);
        box.addView(foot);

        setContentView(root);
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private Button button(String s, boolean accent) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextSize(14);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setTextColor(accent ? 0xFF0D1512 : FG);
        b.setBackground(panelDrawable(accent ? ACCENT : 0xFF2B3039));
        b.setPadding(dp(14), dp(8), dp(14), dp(8));
        return b;
    }

    /** 自定义背景的 Button 不会自动变灰，禁用时手动降透明度给出视觉反馈。 */
    private void enableButton(Button b, boolean on) {
        b.setEnabled(on);
        b.setAlpha(on ? 1.0f : 0.45f);
    }

    private CheckBox check(String s, boolean checked) {
        CheckBox c = new CheckBox(this);
        c.setText(s);
        c.setTextSize(12);
        c.setTextColor(FG);
        c.setChecked(checked);
        c.setPadding(dp(2), dp(4), dp(2), dp(4));
        return c;
    }

    private GradientDrawable panelDrawable(int color) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(9));
        g.setStroke(1, BORDER);
        return g;
    }

    private LinearLayout card() {
        LinearLayout l = new LinearLayout(this);
        l.setBackground(panelDrawable(PANEL));
        l.setPadding(dp(14), dp(12), dp(14), dp(12));
        return l;
    }

    private LinearLayout.LayoutParams cardLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(10));
        return lp;
    }

    private LinearLayout.LayoutParams fullLp(int top, int bottom) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, top, 0, bottom);
        return lp;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    // ------------------------------------------------------------------
    // 选文件 → 复制到私有缓存
    // ------------------------------------------------------------------
    private void pickFile() {
        if (busy) return;
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivityForResult(i, REQ_PICK);
        } catch (Exception e) {
            toast("打不开文件选择器：" + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PICK || resultCode != RESULT_OK || data == null) return;
        final Uri uri = data.getData();
        if (uri == null) return;
        final String name = queryName(uri);
        setFileText("已选择：" + name + "\n正在读取到应用缓存…");
        exportedUris.clear();
        results.removeAllViews();
        enableButton(btnShare, false);
        enableButton(btnSplit, false);

        new Thread(new Runnable() {
            public void run() { copyInput(uri, name); }
        }).start();
    }

    private String queryName(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String n = c.getString(idx);
                    if (n != null && !n.isEmpty()) return n;
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        return "input.apk";
    }

    private void copyInput(Uri uri, final String name) {
        InputStream in = null;
        OutputStream out = null;
        try {
            String ext = "";
            int dot = name.lastIndexOf('.');
            if (dot > 0) ext = name.substring(dot);
            File dst = new File(getCacheDir(), "input" + ext.toLowerCase());
            in = getContentResolver().openInputStream(uri);
            if (in == null) throw new IOException("无法读取所选文件");
            out = new FileOutputStream(dst);
            byte[] buf = new byte[1 << 16];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                total += n;
                final long mb = total / 1048576;
                if (total % (16 * 1048576) < buf.length) {
                    setStatus("正在读取所选文件… " + mb + " MB", (int) Math.min(30, total / 8388608));
                }
            }
            out.close(); out = null;
            in.close(); in = null;
            workFile = dst;
            final long size = dst.length();
            runOnUiThread(new Runnable() {
                public void run() {
                    setFileText("已选择：" + name + "\n" + (size / 1048576) + " MB · 已就绪");
                    enableButton(btnSplit, true);
                    progress.setProgress(0);
                    tvStatus.setText("就绪 · 点「开始拆分」");
                    log("已读取 " + size + " 字节到应用缓存（ZIP 需要随机访问）");
                    if (size > 100L * 1048576) {
                        log("大文件：处理期间约需 " + (size * 3 / 1048576)
                                + " MB 空闲空间，请保持App在前台并耐心等待");
                    }
                }
            });
        } catch (final Exception e) {
            log("读取失败：" + e.getMessage());
            setStatus("读取失败：" + e.getMessage(), 0);
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }
    }

    // ------------------------------------------------------------------
    // 拆分
    // ------------------------------------------------------------------
    private void startSplit() {
        if (busy) return;
        if (workFile == null || !workFile.isFile()) {
            toast("请先选择安装包");
            return;
        }
        busy = true;
        enableButton(btnPick, false);
        enableButton(btnSplit, false);
        enableButton(btnShare, false);
        results.removeAllViews();
        exportedUris.clear();
        log("────────────────────────────");
        final File input = workFile;
        final boolean exportInjected = chkInjected.isChecked();
        final boolean makeManifest = chkManifest.isChecked();
        new Thread(new Runnable() {
            public void run() { doSplit(input, exportInjected, makeManifest); }
        }).start();
    }

    private void doSplit(File input, boolean exportInjected, boolean makeManifest) {
        final File outDir = new File(getCacheDir(), "split_" + System.currentTimeMillis());
        outDir.mkdirs();
        SplitCore.Options opt = new SplitCore.Options();
        opt.exportInjected = exportInjected;
        opt.makeManifest = makeManifest;

        SplitCore.Progress cb = new SplitCore.Progress() {
            public void on(final String text, final int percent) {
                if (isFinishing()) return;
                runOnUiThread(new Runnable() {
                    public void run() {
                        progress.setProgress(percent);
                        if (!text.isEmpty()) tvStatus.setText(text);
                    }
                });
            }
            public void log(final String msg) { MainActivity.this.log(msg); }
        };

        try {
            final SplitCore.Result r = SplitCore.split(input, outDir, opt, cb);
            log("结果：" + r.framework + " / " + r.mode);
            for (String w : r.warnings) log("⚠ " + w);

            // 导出到公共下载目录
            int count = 0;
            for (final SplitCore.OutFile f : r.files) {
                final String display = f.name.replace('/', '_').replace('\\', '_');
                setStatus("正在保存 " + display, 96);
                final Uri uri = exportOne(new File(f.path), display, mimeOf(display));
                if (uri != null) exportedUris.add(uri);
                count++;
                addCard(f, uri);
            }
            if (makeManifest && r.manifestPath != null) {
                Uri u = exportOne(new File(r.manifestPath), "manifest.json", "application/json");
                if (u != null) exportedUris.add(u);
                count++;
            }
            final int total = count;
            runOnUiThread(new Runnable() {
                public void run() {
                    progress.setProgress(100);
                    tvStatus.setText("拆分完成 ✓ 已保存 " + total + " 个文件到 下载/SplitPatch/");
                    enableButton(btnShare, !exportedUris.isEmpty());
                    if (Build.VERSION.SDK_INT < 29) {
                        log("提示：当前系统版本较低，文件保存在应用专属目录 " + fallbackDir());
                    }
                }
            });
            log("完成 ✓ 共导出 " + count + " 个文件");
        } catch (final Exception e) {
            log("拆分失败：" + e);
            runOnUiThread(new Runnable() {
                public void run() {
                    tvStatus.setText("拆分失败：" + e.getMessage());
                    toast("拆分失败：" + e.getMessage());
                }
            });
        } finally {
            busy = false;
            runOnUiThread(new Runnable() {
                public void run() {
                    enableButton(btnPick, true);
                    enableButton(btnSplit, true);
                }
            });
            deleteRecursively(outDir);   // 缓存里的中间产物，导出后即可清掉
        }
    }

    private String mimeOf(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".apk")) return "application/vnd.android.package-archive";
        if (n.endsWith(".json")) return "application/json";
        if (n.endsWith(".html")) return "text/html";
        return "application/octet-stream";
    }

    /** Android 10+ 走 MediaStore（无需权限）；低版本退到应用专属目录。 */
    private Uri exportOne(File src, String displayName, String mime) throws IOException {
        if (Build.VERSION.SDK_INT >= 29) {
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.Downloads.DISPLAY_NAME, displayName);
            cv.put(MediaStore.Downloads.MIME_TYPE, mime);
            cv.put(MediaStore.Downloads.RELATIVE_PATH,
                    Environment.DIRECTORY_DOWNLOADS + "/SplitPatch");
            cv.put(MediaStore.Downloads.IS_PENDING, 1);
            Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (uri == null) throw new IOException("无法在下载目录创建文件：" + displayName);
            OutputStream out = getContentResolver().openOutputStream(uri);
            if (out == null) throw new IOException("无法写入：" + displayName);
            copyStream(new FileInputStream(src), out);
            ContentValues done = new ContentValues();
            done.put(MediaStore.Downloads.IS_PENDING, 0);
            getContentResolver().update(uri, done, null, null);
            return uri;
        }
        File dir = new File(fallbackDir(), "SplitPatch");
        dir.mkdirs();
        copyStream(new FileInputStream(src), new FileOutputStream(new File(dir, displayName)));
        return null; // 低版本返回 file:// 会在分享时触发 FileUriExposedException，故不分享
    }

    private File fallbackDir() {
        File d = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        return d != null ? d : getFilesDir();
    }

    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        try {
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        } finally {
            try { in.close(); } catch (Exception ignored) {}
            try { out.close(); } catch (Exception ignored) {}
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) try { c.close(); } catch (Exception ignored) {}
    }

    private static void deleteRecursively(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) deleteRecursively(k);
        }
        f.delete();
    }

    // ------------------------------------------------------------------
    // 结果卡片 / 分享 / 日志
    // ------------------------------------------------------------------
    private void addCard(final SplitCore.OutFile f, final Uri uri) {
        if (isFinishing()) return;
        runOnUiThread(new Runnable() {
            public void run() {
                String role = "original".equals(f.role) ? "原版软件"
                        : "module".equals(f.role) ? "内置模块" : "注入组件";
                String size = f.size >= 1048576
                        ? String.format("%.2f MB", f.size / 1048576.0)
                        : String.format("%.1f KB", f.size / 1024.0);
                StringBuilder sb = new StringBuilder();
                sb.append(role).append("  ·  ").append(f.name).append('\n');
                sb.append(size).append("  ·  CRC ").append(f.crcOk ? "✓" : "✗");
                if (f.entries >= 0) sb.append("  ·  ").append(f.entries).append(" 条目");
                sb.append("\nSHA-256 ").append(f.sha256.substring(0, Math.min(16, f.sha256.length()))).append("…");
                TextView c = text(sb.toString(), 12, f.crcOk ? GREEN : WARN, false);
                c.setBackground(panelDrawable(PANEL));
                c.setPadding(dp(12), dp(10), dp(12), dp(10));
                LinearLayout.LayoutParams lp = fullLp(dp(8), 0);
                results.addView(c, lp);
                if (uri != null) {
                    c.setOnClickListener(new View.OnClickListener() {
                        public void onClick(View v) { shareOne(uri); }
                    });
                }
                log("  [" + role + "] " + f.name + " " + size + " CRC=" + f.crcOk);
            }
        });
    }

    private void shareOne(Uri uri) {
        try {
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("*/*");
            i.putExtra(Intent.EXTRA_STREAM, uri);
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(i, "分享文件"));
        } catch (Exception e) {
            toast("分享失败：" + e.getMessage());
        }
    }

    private void shareAll() {
        if (exportedUris.isEmpty()) return;
        try {
            Intent i = new Intent(Intent.ACTION_SEND_MULTIPLE);
            i.setType("*/*");
            i.putParcelableArrayListExtra(Intent.EXTRA_STREAM, new ArrayList<Uri>(exportedUris));
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(i, "分享拆分结果"));
        } catch (Exception e) {
            toast("分享失败：" + e.getMessage());
        }
    }

    private void log(final String msg) {
        if (isFinishing()) return;
        runOnUiThread(new Runnable() {
            public void run() {
                logBuf.append(msg).append('\n');
                // 只保留最后 120 行，避免长时间运行把 TextView 撑爆
                String all = logBuf.toString();
                int lines = 0, cut = all.length();
                for (int i = all.length() - 1; i >= 0; i--) {
                    if (all.charAt(i) == '\n') {
                        lines++;
                        if (lines == 120) { cut = i + 1; break; }
                    }
                }
                if (cut < all.length()) {
                    logBuf.delete(0, cut);
                    all = logBuf.toString();
                }
                tvLog.setText(all);
                scroller.post(new Runnable() {
                    public void run() { scroller.fullScroll(View.FOCUS_DOWN); }
                });
            }
        });
    }

    private void setStatus(final String s, final int pct) {
        if (isFinishing()) return;
        runOnUiThread(new Runnable() {
            public void run() {
                tvStatus.setText(s);
                if (pct >= 0) progress.setProgress(pct);
            }
        });
    }

    private void setFileText(final String s) {
        runOnUiThread(new Runnable() {
            public void run() { tvFile.setText(s); }
        });
    }

    private void toast(final String s) {
        runOnUiThread(new Runnable() {
            public void run() { Toast.makeText(MainActivity.this, s, Toast.LENGTH_LONG).show(); }
        });
    }
}
