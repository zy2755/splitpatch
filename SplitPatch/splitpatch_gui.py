# -*- coding: utf-8 -*-
"""
SplitPatch · 集成包拆分器 —— 图形界面
=====================================================================

依赖：Python 3.10+ 且带 tkinter（本机 C:\\Python314 的 3.14 可用）。
拆分逻辑全部在 splitpatch.py 里，这个文件只负责界面和线程调度。

启动：双击「启动拆分工具.bat」，或 py -3.14 splitpatch_gui.py [文件路径]
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
from pathlib import Path

try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 高分屏别糊
except Exception:
    pass

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import splitpatch as sp

# ---------------------------------------------------------------------------
# 配色（深色 + 薄荷绿点缀）
# ---------------------------------------------------------------------------
BG = "#17181d"
PANEL = "#212329"
INPUT_BG = "#1a1d23"
BORDER = "#333944"
FG = "#e7eaf1"
MUTED = "#8b93a3"
ACCENT = "#4cc2a1"
ACCENT_DARK = "#3aa98a"
BLUE = "#6aa9ff"
WARN = "#f0b455"
BAD = "#f08080"

FONT = ("Microsoft YaHei UI", 10)
FONT_B = ("Microsoft YaHei UI", 10, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 17, "bold")
FONT_SMALL = ("Microsoft YaHei UI", 9)
MONO = ("Consolas", 9)


class App:
    def __init__(self, root: tk.Tk, initial: str | None = None):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.busy = False

        # 分析结果缓存：拆一个 200MB+ 的分发包要展开一次 APK，
        # 「分析」后紧接着「拆分」就别重复展开了。
        self._pkg: sp.Package | None = None
        self._det: sp.Detection | None = None
        self._key: str | None = None
        self.result: dict | None = None

        self.var_input = tk.StringVar()
        self.var_out = tk.StringVar()
        self.var_status = tk.StringVar(value="就绪 · 请选择待拆分文件")
        self.var_report = tk.BooleanVar(value=True)
        self.var_injected = tk.BooleanVar(value=False)
        self.var_payload = tk.BooleanVar(value=False)

        self.build_ui()
        if initial and Path(initial).is_file():
            self.var_input.set(str(Path(initial)))
            self.auto_output()

        self.root.after(80, self.poll)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -----------------------------------------------------------------------
    # 界面
    # -----------------------------------------------------------------------
    def build_ui(self) -> None:
        r = self.root
        r.title(f"SplitPatch · 集成包拆分器  v{sp.__version__}")
        r.geometry("1020x740")  # 默认宽度下三个选项正好一行放得下；拉窄会自动换行
        r.minsize(860, 620)
        r.configure(bg=BG)

        style = ttk.Style(r)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TProgressbar", background=ACCENT, troughcolor="#252932",
                        borderwidth=0, thickness=12)
        style.configure("Treeview", background="#1b1e24", fieldbackground="#1b1e24",
                        foreground=FG, borderwidth=0, rowheight=26, font=FONT)
        style.configure("Treeview.Heading", background="#282d36", foreground="#b9c2d2",
                        font=FONT_B, relief="flat")
        style.map("Treeview", background=[("selected", "#2f4b45")],
                  foreground=[("selected", FG)])

        # ---- 标题 ----
        head = tk.Frame(r, bg=BG)
        head.pack(fill="x", padx=22, pady=(18, 12))
        tk.Label(head, text="🌿  SplitPatch · 集成包拆分器", font=FONT_TITLE,
                 bg=BG, fg=FG).pack(anchor="w")
        tk.Label(head, text="把 LSPatch / NPatch 集成模式打包的软件，拆成「原版软件」和「内置模块」两部分",
                 font=FONT_SMALL, bg=BG, fg=MUTED).pack(anchor="w", pady=(3, 0))

        # ---- 输入 / 输出 ----
        form = tk.Frame(r, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        form.pack(fill="x", padx=22, pady=(0, 10))
        form.columnconfigure(1, weight=1)

        self._add_row(form, 0, "① 待拆分文件", self.var_input, self.choose_input)
        self._add_row(form, 1, "② 输出目录", self.var_out, self.choose_output)

        self.btn_auto = self.mkbutton(form, "自动", self.auto_output, small=True)
        self.btn_auto.grid(row=1, column=3, padx=(6, 12), pady=8)

        # 选项区：宽度不够时自动换行。原先三个复选框硬排一行，
        # 窗口没最大化 / 系统 DPI 放大字体后，最后一项会被父容器直接裁掉。
        opts = tk.Frame(form, bg=PANEL)
        opts.grid(row=2, column=0, columnspan=4, sticky="we", padx=14, pady=(2, 12))
        self.opt_frame = opts
        self.opt_checks: list[tk.Checkbutton] = []
        self._opt_width: int | None = None
        for text, var in [
            ("生成 HTML 拆分报告", self.var_report),
            ("一并导出注入组件（loader / so / config）", self.var_injected),
            ("无原版时导出散文件（仅供分析）", self.var_payload),
        ]:
            cb = tk.Checkbutton(opts, text=text, variable=var, bg=PANEL, fg=FG,
                                selectcolor="#2b3039", activebackground=PANEL,
                                activeforeground=FG, font=FONT_SMALL, bd=0,
                                highlightthickness=0)
            self.opt_checks.append(cb)
        opts.bind("<Configure>", self._relayout_opts)
        self.root.after_idle(self._relayout_opts)

        # ---- 操作按钮 ----
        bar = tk.Frame(r, bg=BG)
        bar.pack(fill="x", padx=22, pady=(2, 10))
        self.btn_analyze = self.mkbutton(bar, "分析结构", self.analyze)
        self.btn_analyze.pack(side="left")
        self.btn_split = self.mkbutton(bar, "开始拆分", self.start_split, accent=True)
        self.btn_split.pack(side="left", padx=8)
        self.btn_open = self.mkbutton(bar, "打开输出目录", self.open_output, small=True)
        self.btn_open.pack(side="left", padx=4)
        self.btn_report = self.mkbutton(bar, "查看报告", self.open_report, small=True)
        self.btn_report.pack(side="left", padx=4)
        self.btn_open.config(state="disabled")
        self.btn_report.config(state="disabled")

        # ---- 结果树 + 日志 ----
        pane = tk.PanedWindow(r, orient=tk.HORIZONTAL, bg=BG, sashwidth=6,
                              sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True, padx=22, pady=(0, 10))

        left = tk.Frame(pane, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tk.Label(left, text="检测结果", font=FONT_B, bg=PANEL, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=12, pady=(9, 6))
        tw = tk.Frame(left, bg=PANEL)
        tw.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree = ttk.Treeview(tw, columns=("item", "value", "note"), show="headings",
                                 selectmode="browse")
        for col, title, width in [("item", "项目", 110), ("value", "值", 240), ("note", "说明", 220)]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(tw, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("ok", foreground="#7ee0b8")
        self.tree.tag_configure("warn", foreground=WARN)
        self.tree.tag_configure("muted", foreground=MUTED)
        self.tree.tag_configure("blue", foreground=BLUE)

        right = tk.Frame(pane, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tk.Label(right, text="运行日志", font=FONT_B, bg=PANEL, fg=ACCENT,
                 anchor="w").pack(fill="x", padx=12, pady=(9, 6))
        tw2 = tk.Frame(right, bg=PANEL)
        tw2.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.txt = tk.Text(tw2, bg="#15171c", fg=FG, insertbackground=FG,
                           relief="flat", font=MONO, wrap="word", padx=10, pady=8)
        sb2 = ttk.Scrollbar(tw2, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb2.set)
        self.txt.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")
        for tag, color in [("ok", "#7ee0b8"), ("warn", WARN), ("bad", BAD), ("muted", MUTED)]:
            self.txt.tag_configure(tag, foreground=color)
        self.txt.config(state="disabled")

        pane.add(left, minsize=420)
        pane.add(right, minsize=330)

        # ---- 进度 / 状态 ----
        bottom = tk.Frame(r, bg=BG)
        bottom.pack(fill="x", padx=22, pady=(0, 6))
        self.pb = ttk.Progressbar(bottom, mode="determinate", maximum=100)
        self.pb.pack(fill="x", side="top")
        line = tk.Frame(bottom, bg=BG)
        line.pack(fill="x", pady=(5, 0))
        tk.Label(line, textvariable=self.var_status, font=FONT_SMALL, bg=BG,
                 fg=MUTED, anchor="w").pack(side="left")
        tk.Label(line, text="仅对你有权处理的安装包使用 · 纯本地静态解包，不联网",
                 font=FONT_SMALL, bg=BG, fg="#6b7280").pack(side="right")

        self.log("就绪。选一个修补后的 .apk，或装着它的 .zip / .apks / .xapk。", "muted")
        self.log("小提示：也可以把文件路径直接粘贴进上面的输入框。", "muted")

    def _add_row(self, parent, row, label, var, cmd):
        tk.Label(parent, text=label, font=FONT_B, bg=PANEL, fg=FG,
                 anchor="w").grid(row=row, column=0, padx=(14, 10), pady=8, sticky="w")
        e = tk.Entry(parent, textvariable=var, bg=INPUT_BG, fg=FG, insertbackground=FG,
                     relief="flat", highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT, font=FONT)
        e.grid(row=row, column=1, sticky="ew", pady=8, ipady=4)
        self.mkbutton(parent, "浏览…", cmd, small=True).grid(row=row, column=2, padx=8)

    def mkbutton(self, parent, text, cmd, accent=False, small=False):
        bg = ACCENT_DARK if accent else "#2b3039"
        fg = "#0d1512" if accent else FG
        return tk.Button(
            parent, text=text, command=cmd, bg=bg, fg=fg,
            activebackground=ACCENT if accent else "#3a4150",
            activeforeground=fg, disabledforeground="#6b7280",
            relief="flat", bd=0, cursor="hand2",
            font=FONT_SMALL if small else FONT_B,
            padx=10 if small else 16, pady=5 if small else 7,
        )

    def _relayout_opts(self, event=None):
        """按当前宽度给复选框贪心分行，窗口再窄也不会被裁掉。

        pack(side="left") 放不下时 tkinter 是直接裁切、不会换行；改用 grid，
        容器尺寸变化时重新算「这一行还能塞几个」。DPI 缩放把字体放大时也照样生效。
        """
        avail = self.opt_frame.winfo_width()
        if avail < 80:
            return
        if self._opt_width == avail:  # 同宽度不重复布局，避免 Configure 反复触发
            return
        self._opt_width = avail

        gap = 20
        widths = []
        for cb in self.opt_checks:
            cb.update_idletasks()
            widths.append(max(120, cb.winfo_reqwidth()))  # 纯控件宽，间隔单独算

        rows: list[list[int]] = []
        cur: list[int] = []
        used = 0
        for idx, w in enumerate(widths):
            need = w + (gap if cur else 0)  # 只有行内第二项起才需要前面的间隔
            if cur and used + need > avail:
                rows.append(cur)
                cur, used = [], 0
                need = w
            cur.append(idx)
            used += need
        if cur:
            rows.append(cur)

        for cb in self.opt_checks:
            cb.grid_forget()
        for r, row in enumerate(rows):
            for c, idx in enumerate(row):
                self.opt_checks[idx].grid(row=r, column=c, sticky="w",
                                         padx=(0, gap), pady=(0, 3))

    # -----------------------------------------------------------------------
    # 交互
    # -----------------------------------------------------------------------
    def choose_input(self):
        p = filedialog.askopenfilename(
            title="选择待拆分的文件",
            filetypes=[("安装包 / 分发包", "*.apk *.zip *.apks *.xapk"),
                       ("APK", "*.apk"), ("所有文件", "*.*")],
        )
        if not p:
            return
        self.var_input.set(p)
        self.auto_output()
        self.clear_detection()
        self.log(f"已选择：{p}", "muted")

    def choose_output(self):
        p = filedialog.askdirectory(title="选择输出目录")
        if p:
            self.var_out.set(p)

    def auto_output(self):
        src = self.var_input.get().strip()
        if not src:
            return
        p = Path(src)
        self.var_out.set(str(p.parent / f"{sp._safe_stem(p.name)}_拆分结果"))

    def clear_detection(self):
        self.tree.delete(*self.tree.get_children())
        self._release_pkg()
        self.result = None
        self.btn_open.config(state="disabled")
        self.btn_report.config(state="disabled")
        self.pb["value"] = 0

    def _release_pkg(self):
        if self._pkg:
            try:
                self._pkg.close()
            except Exception:
                pass
        self._pkg = None
        self._det = None
        self._key = None

    def _input_key(self, path: str) -> str:
        p = Path(path)
        try:
            return f"{p}|{p.stat().st_size}|{p.stat().st_mtime_ns}"
        except OSError:
            return str(p)

    def analyze(self):
        self._start(self._work_analyze)

    def start_split(self):
        self._start(self._work_split)

    def _start(self, target):
        if self.busy:
            return
        src = self.var_input.get().strip()
        if not src or not Path(src).is_file():
            messagebox.showwarning("还没选文件", "请先在「待拆分文件」里选一个 .apk 或分发包。")
            return
        if not self.var_out.get().strip():
            self.auto_output()
        # tkinter 的变量/控件只能在主线程碰。后台线程一律只拿这份纯 Python 快照，
        # 否则会抛 "main thread is not in main loop"（甚至随机崩溃）。
        ctx = {
            "path": src,
            "outdir": self.var_out.get().strip(),
            "export_injected": bool(self.var_injected.get()),
            "export_payload": bool(self.var_payload.get()),
            "make_report": bool(self.var_report.get()),
        }
        self.set_busy(True)
        self.log("─" * 46, "muted")
        threading.Thread(target=target, args=(ctx,), daemon=True).start()

    def set_busy(self, flag: bool):
        self.busy = flag
        state = "disabled" if flag else "normal"
        for b in (self.btn_analyze, self.btn_split, self.btn_auto):
            b.config(state=state)
        if flag:
            self.pb["value"] = 0
            self.var_status.set("处理中…")

    # -----------------------------------------------------------------------
    # 后台线程（只往队列里丢消息，绝不碰控件）
    # -----------------------------------------------------------------------
    def _emit(self, msg: str, tag: str = "info"):
        self.q.put(("log", (msg, tag)))

    def _progress(self):
        state = {"last": -1.0}

        def cb(text: str, pct: float):
            # 大文件每读 1MB 会回调一次，节流一下免得刷屏
            if pct - state["last"] >= 0.01 or pct >= 1.0:
                state["last"] = pct
                self.q.put(("progress", (text, pct)))
        return cb

    def _work_analyze(self, ctx: dict):
        try:
            path = ctx["path"]
            self._release_pkg()
            self._emit("正在展开并读取中央目录…")
            pkg = sp.open_package(path, log=self._emit)
            det = sp.detect(pkg)
            self._pkg, self._det, self._key = pkg, det, self._input_key(path)
            self.q.put(("detect", det))
            for n in det.notes:
                self._emit(f"  · {n}", "muted")
            self.q.put(("done_analyze", None))
        except Exception as exc:
            self.q.put(("error", (str(exc), traceback.format_exc())))

    def _work_split(self, ctx: dict):
        try:
            path = ctx["path"]
            key = self._input_key(path)
            if self._det is None or self._key != key:
                self._release_pkg()
                self._emit("正在展开并读取中央目录…")
                pkg = sp.open_package(path, log=self._emit)
                det = sp.detect(pkg)
                self._pkg, self._det, self._key = pkg, det, key
                self.q.put(("detect", det))
            pkg, det = self._pkg, self._det
            assert pkg is not None and det is not None

            self._emit(f"框架：{det.framework}　模式：{det.mode}", "ok")
            self._emit(f"内嵌原版：{det.origin_entry or '（无）'}")
            self._emit(f"内置模块：{len(det.module_entries)} 个")
            if not det.found:
                self._emit("没检测到集成注入结构，仍会生成一份诊断报告。", "warn")
            for n in det.notes:
                self._emit(f"  · {n}", "muted")

            result = sp.split(
                pkg, det, Path(ctx["outdir"]),
                export_injected=ctx["export_injected"],
                export_payload=ctx["export_payload"],
                make_report=ctx["make_report"],
                log=self._emit,
                progress=self._progress(),
            )
            self.q.put(("done_split", result))
        except Exception as exc:
            self.q.put(("error", (str(exc), traceback.format_exc())))

    # -----------------------------------------------------------------------
    # 主线程消费队列
    # -----------------------------------------------------------------------
    def poll(self):
        try:
            for _ in range(300):
                kind, payload = self.q.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.root.after(80, self.poll)

    def _handle(self, kind, payload):
        if kind == "log":
            self.log(*payload)
        elif kind == "progress":
            text, pct = payload
            self.pb["value"] = max(0, min(100, pct * 100))
            self.var_status.set(text)
        elif kind == "detect":
            self.show_detection(payload)
        elif kind == "done_analyze":
            self.set_busy(False)
            self.pb["value"] = 100
            self.var_status.set("分析完成 · 点「开始拆分」即可导出")
            self.log("分析完成 ✓ 已缓存展开结果，拆分时不会重复解压。", "ok")
        elif kind == "done_split":
            self.set_busy(False)
            self.pb["value"] = 100
            self.result = payload
            self.btn_open.config(state="normal")
            if payload.get("report_path"):
                self.btn_report.config(state="normal")
            originals = [i for i in payload["outputs"] if i["role"] == "original"]
            modules = [i for i in payload["outputs"] if i["role"] == "module"]
            self.var_status.set(f"拆分完成 · 原版 {len(originals)} 个 / 模块 {len(modules)} 个")
            self.log(f"拆分完成 ✓ 输出目录：{payload['output_dir']}", "ok")
            for i in originals + modules:
                self.log(f"  [{i['role']}] {i['name']}　{sp._mb(i['size'])}　"
                         f"CRC {'✓' if i['crc_ok'] else '✗'}", "ok")
            for w in payload["warnings"]:
                self.log(f"  ⚠ {w}", "warn")
            messagebox.showinfo(
                "拆分完成",
                f"原版软件：{len(originals)} 个\n内置模块：{len(modules)} 个\n\n"
                f"输出目录：\n{payload['output_dir']}",
            )
        elif kind == "error":
            msg, tb = payload
            self.set_busy(False)
            self.var_status.set("出错了，详见日志")
            self.log(f"错误：{msg}", "bad")
            self.log(tb.strip(), "muted")
            messagebox.showerror("拆分失败", msg)

    def show_detection(self, det: sp.Detection):
        self.tree.delete(*self.tree.get_children())
        if not det.found:
            self.tree.insert("", "end", values=("未识别", "不是集成模式安装包", "请看日志诊断"), tag="warn")
            return
        self.tree.insert("", "end", values=("打包框架", det.framework, "自动识别"), tags=("ok",))
        self.tree.insert("", "end", values=("打包模式", det.mode, "由 config.json + 模块目录推断"), tags=("blue",))
        self.tree.insert("", "end", values=("注入目录", det.prefix, f"共 {len(det.injected_entries)} 个注入条目"), tags=("muted",))
        self.tree.insert("", "end", values=("中央目录", f"{det.total_entries} 条目", "修补包 ZIP 条目总数"), tags=("muted",))

        assert self._pkg is not None and self._pkg.zf is not None
        if det.origin_entry:
            zi = self._pkg.zf.getinfo(det.origin_entry)
            self.tree.insert("", "end", values=("原版软件", "origin.apk", sp._mb(zi.file_size) + " · 可字节级还原"), tags=("ok",))
        else:
            self.tree.insert("", "end", values=("原版软件", "未内嵌", "无法还原，需另找原版"), tags=("warn",))

        for m in det.module_entries:
            zi = self._pkg.zf.getinfo(m)
            self.tree.insert("", "end", values=("内置模块", Path(m).name, sp._mb(zi.file_size)), tags=("blue",))
        if not det.module_entries:
            self.tree.insert("", "end", values=("内置模块", "0 个", "本地模式或已被移除"), tags=("muted",))

        for n in det.notes[:6]:
            self.tree.insert("", "end", values=("诊断", n[:34] + ("…" if len(n) > 34 else ""), "完整内容见右侧日志"), tags=("muted",))

    def log(self, msg: str, tag: str = "info"):
        self.txt.config(state="normal")
        self.txt.insert("end", str(msg) + "\n", tag)
        self.txt.see("end")
        self.txt.config(state="disabled")

    # -----------------------------------------------------------------------
    def open_output(self):
        p = Path(self.var_out.get().strip())
        if not p.exists() and self.result:
            p = Path(self.result["output_dir"])
        if p.exists():
            os.startfile(str(p))  # noqa: Windows only
        else:
            messagebox.showinfo("还没有输出", "先点「开始拆分」生成结果吧。")

    def open_report(self):
        if not self.result or not self.result.get("report_path"):
            messagebox.showinfo("没有报告", "本次拆分没有生成 HTML 报告。")
            return
        p = Path(self.result["report_path"])
        if p.exists():
            os.startfile(str(p))
        else:
            messagebox.showwarning("找不到报告", str(p))

    def on_close(self):
        self._release_pkg()  # 清理展开到临时目录的 APK
        self.root.destroy()


def main():
    # --check：只验证解释器 / tkinter / 引擎是否齐备，不弹窗口（排障用）
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        print(f"Python {sys.version.split()[0]} | tkinter {tk.TkVersion} "
              f"| SplitPatch engine v{sp.__version__}")
        print("Environment OK.")
        return
    root = tk.Tk()
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    App(root, initial)
    root.mainloop()


if __name__ == "__main__":
    main()
