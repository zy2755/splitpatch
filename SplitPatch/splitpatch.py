# -*- coding: utf-8 -*-
"""
SplitPatch · 集成模式安装包拆分引擎
=====================================================================

用途
----
把 LSPatch / NPatch「集成模式(--embed)」修补出来的 APK，拆成两堆互不相干的东西：

    * 原版软件  —— 修补器完整内嵌的 assets/<ns>/origin.apk
    * 内置模块  —— assets/<ns>/modules/*.apk（例如哔哩哔哩漫游模块）

也支持外层是 .zip / .apks / .xapk 分发包（里面套着修补 APK）的情况。

为什么不能直接用 zipfile.read()
-------------------------------
LSPatch 用 apkzlib 的 NestedZip 技术，把原始 APK 以 STORED（不压缩）方式
整块对齐嵌入修补包，并且把原包内部的条目**同时登记在修补包的中央目录里**。
于是外层 ZIP 的条目在数据区上互相重叠：

    assets/lspatch/origin.apk   offset=848    csize=241561212
    assets/dexopt/baseline.prof offset=4096  csize=46201      <-- 落在上一块内部

CPython 3.13 起，zipfile.open() 会检测这种重叠并抛
    BadZipFile: Overlapped entries: '...' (possible zip bomb)
但字节本身完全完好。所以本模块自己按「中央目录的 header_offset →
local file header → 跳过 name/extra → 按 compress_size 读取」来取数据，
并用中央目录里的 CRC32 逐块校验，保证拆出来的是原封不动的原始文件。

合规说明
--------
本工具只做静态解包与文件还原，不修改、不绕过任何软件的授权/签名校验逻辑。
请只对你有权处理的安装包使用。

命令行示例
----------
    python splitpatch.py "D:\\xx\\内置模块.zip"
    python splitpatch.py patched.apk -o D:\\out --export-injected
    python splitpatch.py patched.apk --dry-run          # 只检测，不写文件
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator

__version__ = "1.0.0"
TOOL_NAME = "SplitPatch · 集成包拆分器"

# ZIP local file header: 签名/版本/标志/压缩方法/时间/日期/CRC/压缩大小/原始大小/名长/扩展长
_LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
_LOCAL_MAGIC = b"PK\x03\x04"
_ZIP_MAGIC = b"PK\x03\x04"
_CHUNK = 1 << 20  # 1 MiB，流式读写，避免把 240MB 原包整个吃进内存

APK_SUFFIXES = {".apk", ".apks", ".xapk", ".zip"}


class SplitError(Exception):
    """可预期的、需要展示给用户的错误。"""


# ---------------------------------------------------------------------------
# 一、底层 ZIP 条目读取（本工具的核心）
# ---------------------------------------------------------------------------

def _locate_entry_data(raw_fp: BinaryIO, info: zipfile.ZipInfo) -> tuple[int, int, int]:
    """返回 (数据起始偏移, 压缩后字节数, 压缩方法)。

    注意：必须用 **local header** 里的 name_len / extra_len，不能用中央目录的。
    apkzlib 会在 local header 的 extra 里塞对齐填充（本样本 3193 字节），
    两边长度并不一致；用错的话会读到一堆脏数据。
    """
    raw_fp.seek(info.header_offset)
    header = raw_fp.read(30)
    if len(header) != 30 or header[:4] != _LOCAL_MAGIC:
        raise SplitError(f"条目 {info.filename!r} 的 local header 损坏或偏移不对")

    values = _LOCAL_HEADER.unpack(header)
    name_len, extra_len = values[9], values[10]
    raw_fp.read(name_len)
    raw_fp.read(extra_len)

    # 压缩大小以中央目录为准（若用了 data descriptor，local header 里是 0）
    csize = info.compress_size
    method = info.compress_type
    return raw_fp.tell(), csize, method


def iter_entry_raw(raw_fp: BinaryIO, info: zipfile.ZipInfo) -> Iterator[bytes]:
    """按块产出条目的**解压后**字节，绕开 zipfile 的重叠检查。"""
    start, csize, method = _locate_entry_data(raw_fp, info)
    raw_fp.seek(start)

    remaining = csize
    if method == zipfile.ZIP_STORED:
        while remaining > 0:
            buf = raw_fp.read(min(_CHUNK, remaining))
            if not buf:
                raise SplitError(f"条目 {info.filename!r} 数据被截断")
            remaining -= len(buf)
            yield buf
    elif method == zipfile.ZIP_DEFLATED:
        dec = zlib.decompressobj(-15)  # -15 = raw deflate，不要 zlib 头
        while remaining > 0:
            buf = raw_fp.read(min(_CHUNK, remaining))
            if not buf:
                raise SplitError(f"条目 {info.filename!r} 数据被截断")
            remaining -= len(buf)
            out = dec.decompress(buf)
            if out:
                yield out
        tail = dec.flush()
        if tail:
            yield tail
    else:
        raise SplitError(f"暂不支持压缩方法 {method}（条目 {info.filename!r}）")


def read_entry_raw(raw_fp: BinaryIO, info: zipfile.ZipInfo) -> tuple[bytes, bool]:
    """小条目专用：一次性读出，返回 (字节, CRC 是否吻合)。"""
    data = b"".join(iter_entry_raw(raw_fp, info))
    crc_ok = (zlib.crc32(data) & 0xFFFFFFFF) == info.CRC
    return data, crc_ok


def extract_entry_raw(
    raw_fp: BinaryIO,
    info: zipfile.ZipInfo,
    dest: Path,
    progress: Callable[[str, float], None] | None = None,
) -> dict:
    """大条目专用：边读边写到 dest，同时算 CRC32 / SHA-256，返回校验信息。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    crc = 0
    sha = hashlib.sha256()
    written = 0
    with open(dest, "wb") as out:
        for buf in iter_entry_raw(raw_fp, info):
            out.write(buf)
            crc = zlib.crc32(buf, crc)
            sha.update(buf)
            written += len(buf)
            if progress and info.compress_size:
                ratio = min(1.0, written / max(1, info.file_size))
                progress(f"正在还原 {dest.name} … {written / 1048576:.1f} MB", ratio)
    crc &= 0xFFFFFFFF
    return {
        "size": written,
        "crc32": f"{crc:08x}",
        "expected_crc32": f"{info.CRC:08x}",
        "crc_ok": crc == info.CRC,
        "sha256": sha.hexdigest(),
    }


# ---------------------------------------------------------------------------
# 二、输入加载：把 apk / zip / apks 统一成一个可随机访问的 APK 文件
# ---------------------------------------------------------------------------

@dataclass
class Package:
    path: Path                      # 实际被分析的 APK（可能是临时抽出来的）
    display_name: str               # 分发包里那个 APK 的名字，用于命名输出
    source: Path                    # 用户最初选择的文件
    temp_dir: Path | None = None
    zf: zipfile.ZipFile | None = None
    raw_fp: BinaryIO | None = None

    def close(self) -> None:
        if self.raw_fp:
            self.raw_fp.close()
            self.raw_fp = None
        if self.zf:
            self.zf.close()
            self.zf = None
        # 只清理本工具自己创建的临时目录
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _open_apk(path: Path, source: Path, display_name: str, temp_dir: Path | None) -> Package:
    # ZipFile 传路径字符串，让它自己管理自己的句柄；raw_fp 另开一个独立句柄，
    # 两者 seek 互不干扰（zipfile 每次读都会重新定位，底层读取也会重新定位）。
    try:
        zf = zipfile.ZipFile(path)
    except Exception:
        raise SplitError(f"不是有效的 ZIP/APK 文件：{path}")
    try:
        raw_fp = open(path, "rb")
    except Exception:
        zf.close()
        raise
    return Package(path, display_name, source, temp_dir, zf, raw_fp)


def open_package(
    source: str | Path,
    log: Callable[[str], None] = print,
    progress: Callable[[str, float], None] | None = None,
) -> Package:
    """支持三种输入：裸 APK、单 APK 分发 ZIP、多 APK 的 .apks/.xapk。"""
    src = Path(source).expanduser()
    if not src.is_file():
        raise SplitError(f"文件不存在：{src}")
    if src.suffix.lower() not in APK_SUFFIXES:
        raise SplitError(f"不支持的文件类型 {src.suffix}，请选 .apk / .zip / .apks / .xapk")

    if src.suffix.lower() == ".apk":
        return _open_apk(src, src, src.name, None)

    # 外层是分发包：把里面的 APK 抽到临时目录，之后用普通文件随机访问。
    # 不直接嵌套 ZipFile 是因为 ZipExtFile.seek() 对 deflate 流代价很高，
    # 从 240MB 处往回跳会反复解压整条流，慢得离谱。
    temp_dir = Path(tempfile.mkdtemp(prefix="splitpatch_"))
    first: tuple[Path, str] | None = None
    with zipfile.ZipFile(src) as outer:
        apks = [i for i in outer.infolist() if i.filename.lower().endswith(".apk")]
        if not apks:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise SplitError(f"分发包里没找到 .apk：{src.name}")
        # 优先大的（主包）；抽一个测一个，命中就停，避免把整组 split APK 都展开
        apks.sort(key=lambda i: i.file_size, reverse=True)
        for idx, info in enumerate(apks[:8]):
            safe = temp_dir / f"candidate_{idx}.apk"
            name = Path(info.filename).name
            log(f"展开分发包：{info.filename}（{info.file_size / 1048576:.1f} MB）")
            with outer.open(info) as fin, open(safe, "wb") as fout:
                shutil.copyfileobj(fin, fout, _CHUNK)
            if first is None:
                first = (safe, name)
            pkg = _open_apk(safe, src, name, temp_dir)
            if detect(pkg).found:
                log(f"定位到修补包：{name}")
                return pkg
            pkg.close()

    # 都不带注入结构，就返回最大的那个，交给 detect 给出诊断
    log("未在分发包中找到明显的集成注入结构，按主包继续分析")
    assert first is not None
    return _open_apk(first[0], src, first[1], temp_dir)


# ---------------------------------------------------------------------------
# 三、检测：找出修补器塞进来的东西
# ---------------------------------------------------------------------------

# 常见的注入文件名（不同版本/分支略有差异，全部按名字模糊匹配）
_LOADER_NAMES = ("loader.dex", "loader.bin", "metaloader.dex", "mtprovider.dex")
_CONFIG_KEYS = ("useManager", "sigBypassLevel", "originalSignature", "appComponentFactory", "lspConfig")


@dataclass
class Detection:
    found: bool = False
    framework: str = "未识别"
    mode: str = "未知"
    prefix: str = ""                # 例如 assets/lspatch/
    origin_entry: str | None = None
    module_entries: list[str] = field(default_factory=list)
    loader_entries: list[str] = field(default_factory=list)
    config_entry: str | None = None
    so_entries: list[str] = field(default_factory=list)
    injected_entries: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    score: int = 0
    notes: list[str] = field(default_factory=list)
    total_entries: int = 0

    def summary(self) -> dict:
        return {
            "found": self.found,
            "framework": self.framework,
            "mode": self.mode,
            "prefix": self.prefix,
            "origin_entry": self.origin_entry,
            "modules": self.module_entries,
            "config": self.config,
            "notes": self.notes,
            "score": self.score,
            "total_entries": self.total_entries,
        }


def detect(pkg: Package, silent: bool = False) -> Detection:
    """扫描中央目录，按目录分组给候选"注入目录"打分，选最强的一个。

    不写死 assets/lspatch 或 assets/npatch：有些分支会改目录名规避检测，
    所以只要某目录下出现 origin.apk / modules/*.apk / config.json 的组合就认。
    """
    assert pkg.zf is not None
    names = pkg.zf.namelist()
    det = Detection(total_entries=len(names))

    # 先找「注入根目录」。注意 modules/*.apk、so/<abi>/*.so 在更下一级，
    # 不能按它们的直接父目录分组，否则模块会被算成另一个组而漏掉。
    roots: set[str] = set()
    for n in names:
        if not n.startswith("assets/") or n.endswith("/"):
            continue
        root = None
        if n.endswith("/origin.apk") or n.endswith("/config.json") or n.endswith(_LOADER_NAMES):
            root = n.rsplit("/", 1)[0] + "/"
        elif "/modules/" in n and n.lower().endswith(".apk"):
            root = n.split("/modules/", 1)[0] + "/"
        elif "/so/" in n and n.lower().endswith(".so"):
            root = n.split("/so/", 1)[0] + "/"
        # 至少是 assets/<seg>/ 这一级，避免把整个 assets/ 当成一个候选
        if root and root.count("/") >= 2:
            roots.add(root)
    # 若某 root 是另一个 root 的前缀，只保留外层那个（合并嵌套候选）
    roots = {r for r in roots if not any(o != r and r.startswith(o) for o in roots)}

    best_prefix, best_files, best_score = "", [], 0
    for prefix in sorted(roots):
        files = [n for n in names if n.startswith(prefix)]
        score = 0
        if any(f.endswith("/origin.apk") for f in files):
            score += 5
        mods = [f for f in files if "/modules/" in f and f.lower().endswith(".apk")]
        score += min(6, 3 * len(mods))
        if any(f.endswith("/config.json") for f in files):
            score += 3
        if any(f.endswith(_LOADER_NAMES) for f in files):
            score += 2
        seg = prefix.split("/")[1].lower() if "/" in prefix else ""
        if any(k in seg for k in ("lspatch", "npatch", "lsp")):
            score += 2
        if score > best_score:
            best_prefix, best_files, best_score = prefix, files, score

    if best_score < 3:
        det.notes.append("未发现 LSPatch/NPatch 集成注入结构，可能不是集成模式打包的软件。")
        return det

    det.found = True
    det.score = best_score
    det.prefix = best_prefix
    det.origin_entry = next((f for f in best_files if f.endswith("/origin.apk")), None)
    det.module_entries = sorted(f for f in best_files if "/modules/" in f and f.lower().endswith(".apk"))
    det.loader_entries = sorted(f for f in best_files if f.endswith(_LOADER_NAMES))
    det.so_entries = sorted(f for f in best_files if "/so/" in f and f.lower().endswith(".so"))
    det.config_entry = next((f for f in best_files if f.endswith("/config.json")), None)
    det.injected_entries = sorted(
        n for n in names if n.startswith(best_prefix.rstrip("/") + "/")
    )

    # 读配置（小文件，直接走底层读法，顺便验 CRC）
    if det.config_entry and pkg.raw_fp:
        try:
            raw, ok = read_entry_raw(pkg.raw_fp, pkg.zf.getinfo(det.config_entry))
            det.config = json.loads(raw.decode("utf-8", "replace"))
            if not ok:
                det.notes.append("config.json 的 CRC 校验不通过，元信息可能不完整。")
        except Exception as exc:
            det.notes.append(f"config.json 解析失败：{exc}")

    # 判定框架
    seg = best_prefix.split("/")[1].lower() if "/" in best_prefix else ""
    if "npatch" in seg:
        det.framework = "NPatch"
    elif "lspatch" in seg or "lsp" in seg or "lspConfig" in det.config:
        det.framework = "LSPatch"
    else:
        det.framework = "LSPatch / NPatch 系（目录名已改写）"

    # 判定模式
    use_manager = det.config.get("useManager")
    if det.module_entries and use_manager is False:
        det.mode = "集成模式（--embed，模块已内置）"
    elif det.module_entries:
        det.mode = "内置模块（配置未声明 useManager）"
    elif use_manager is True:
        det.mode = "本地模式（--manager，无内置模块）"
    else:
        det.mode = "未内置模块"

    # 补充诊断
    if det.origin_entry:
        info = pkg.zf.getinfo(det.origin_entry)
        det.notes.append(
            f"发现内嵌原始 APK（{info.file_size / 1048576:.1f} MB，"
            f"STORED 对齐存放），可字节级还原。"
        )
        # 检测 NestedZip 重叠：原包内部条目被登记到外层目录里
        overlapping = sum(
            1 for i in pkg.zf.infolist()
            if info.header_offset < i.header_offset < info.header_offset + info.compress_size
        )
        if overlapping:
            det.notes.append(
                f"内嵌原包的 {overlapping} 个条目也被登记在外层中央目录、共享同一数据区"
                "（NestedZip 重叠），标准 zipfile 会误判为 zip bomb，本工具用底层读取绕过。"
            )
    else:
        det.notes.append("该包未内嵌 origin.apk，无法字节级还原原版软件；仍可提取内置模块。")

    if det.config.get("originalSignature"):
        det.notes.append("配置里记录了原厂签名摘要，可用于核对还原包的来源。")
    if det.config.get("appComponentFactory"):
        det.notes.append(
            f"原始 AppComponentFactory：{det.config['appComponentFactory']}"
            "（修补时被换成加载器 stub，还原包里不需要改回）"
        )
    return det


# ---------------------------------------------------------------------------
# 四、拆分
# ---------------------------------------------------------------------------

@dataclass
class OutputItem:
    role: str                 # original | module | injected | payload
    name: str
    path: str
    source_entry: str
    size: int = 0
    sha256: str = ""
    crc_ok: bool | None = None
    apk_valid: bool | None = None
    entries: int | None = None
    dex_count: int | None = None
    note: str = ""


def _apk_stats(path: Path) -> dict:
    """检查拆出来的 APK 是不是一个能正常打开的 ZIP，并数一下 dex / 条目。"""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            return {
                "apk_valid": True,
                "entries": len(names),
                "has_manifest": "AndroidManifest.xml" in names,
                "dex_count": len([n for n in names if re.match(r"classes\d*\.dex$", n)]),
                "sig_files": [n for n in names if n.startswith("META-INF/")
                              and n.upper().endswith((".RSA", ".SF", ".MF", ".DSA", ".EC"))],
            }
    except Exception as exc:
        return {"apk_valid": False, "error": str(exc)}


def _safe_stem(name: str) -> str:
    stem = Path(name).stem
    # 去掉 Windows 文件名不友好的字符
    return re.sub(r'[\\/:*?"<>|]+', "_", stem).strip() or "output"


def split(
    pkg: Package,
    det: Detection,
    outdir: str | Path,
    *,
    export_injected: bool = False,
    export_payload: bool = False,
    make_report: bool = True,
    log: Callable[[str], None] = print,
    progress: Callable[[str, float], None] | None = None,
) -> dict:
    """执行拆分，返回完整结果字典（同时写 manifest.json 与 HTML 报告）。"""
    assert pkg.zf is not None and pkg.raw_fp is not None
    out = Path(outdir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    items: list[OutputItem] = []
    warnings: list[str] = []

    def tick(text: str, pct: float) -> None:
        log(text)
        if progress:
            progress(text, pct)

    # ---- 1. 原版软件 ------------------------------------------------------
    if det.origin_entry:
        info = pkg.zf.getinfo(det.origin_entry)
        name = f"{_safe_stem(pkg.display_name)}_原版.apk"
        dest = out / "原版软件" / name
        tick(f"还原原版软件 → 原版软件/{name}", 0.05)
        verify = extract_entry_raw(pkg.raw_fp, info, dest, progress)
        stats = _apk_stats(dest)
        if not verify["crc_ok"]:
            warnings.append("原版 APK 的 CRC 与中央目录不一致，文件可能已损坏，请勿直接安装。")
        if not stats.get("apk_valid"):
            warnings.append(f"还原出的原版 APK 无法作为 ZIP 打开：{stats.get('error')}")
        items.append(OutputItem(
            role="original", name=name, path=str(dest),
            source_entry=det.origin_entry, size=verify["size"],
            sha256=verify["sha256"], crc_ok=verify["crc_ok"],
            apk_valid=stats.get("apk_valid"), entries=stats.get("entries"),
            dex_count=stats.get("dex_count"),
            note="修补器内嵌的原始字节，含原厂签名，可直接安装（若已装修补版需先卸载）",
        ))
        tick(f"原版校验完成：CRC {'一致 ✓' if verify['crc_ok'] else '不一致 ✗'}，"
             f"{stats.get('entries', '?')} 个条目", 0.55)
    else:
        warnings.append("该包未内嵌 origin.apk，无法还原原版软件；请从官方渠道获取原始安装包。")

    # ---- 2. 内置模块 ------------------------------------------------------
    total_mods = len(det.module_entries)
    for idx, entry in enumerate(det.module_entries):
        info = pkg.zf.getinfo(entry)
        name = Path(entry).name
        dest = out / "内置模块" / name
        tick(f"提取内置模块 {idx + 1}/{total_mods}：{name}", 0.6 + 0.2 * idx / max(1, total_mods))
        verify = extract_entry_raw(pkg.raw_fp, info, dest, progress)
        stats = _apk_stats(dest)
        if not verify["crc_ok"]:
            warnings.append(f"模块 {name} 的 CRC 校验不通过。")
        items.append(OutputItem(
            role="module", name=name, path=str(dest), source_entry=entry,
            size=verify["size"], sha256=verify["sha256"], crc_ok=verify["crc_ok"],
            apk_valid=stats.get("apk_valid"), entries=stats.get("entries"),
            dex_count=stats.get("dex_count"),
            note="独立的 Xposed 模块 APK，可单独安装或用于重新集成",
        ))
    tick(f"模块提取完成：{total_mods} 个", 0.82)

    # ---- 3. 注入组件（可选） ----------------------------------------------
    if export_injected:
        for entry in det.injected_entries:
            if entry.endswith("/"):
                continue
            info = pkg.zf.getinfo(entry)
            if entry.endswith("/origin.apk"):
                continue  # 已经在「原版软件」里字节级还原过了
            if "/modules/" in entry and entry.lower().endswith(".apk"):
                continue  # 模块已经在「内置模块」里单独导出过了
            if info.file_size > 64 * 1048576:
                continue  # 兜底：不重复搬运超大块
            rel = entry[len(det.prefix):]
            dest = out / "注入组件" / rel
            try:
                verify = extract_entry_raw(pkg.raw_fp, info, dest, None)
                items.append(OutputItem(
                    role="injected", name=rel, path=str(dest), source_entry=entry,
                    size=verify["size"], sha256=verify["sha256"], crc_ok=verify["crc_ok"],
                    note="修补器注入的运行时组件",
                ))
            except Exception as exc:
                warnings.append(f"注入组件 {entry} 导出失败：{exc}")
        tick("注入组件已导出", 0.9)

    # ---- 4. 无原版时的降级：导出非注入内容 --------------------------------
    if export_payload and not det.origin_entry:
        base = out / "软件内容"
        count = 0
        for info in pkg.zf.infolist():
            n = info.filename
            if n.endswith("/") or n.startswith(det.prefix) or n.startswith("META-INF/"):
                continue
            dest = base / n
            try:
                extract_entry_raw(pkg.raw_fp, info, dest, None)
                count += 1
            except Exception:
                pass
        tick(f"已导出 {count} 个非注入文件到 软件内容/（未签名，仅供分析）", 0.9)
        warnings.append("软件内容/ 只是散文件，不是可安装包；AndroidManifest 仍指向加载器 stub，"
                        "需要 apktool 还原后重新签名才能使用。")

    # ---- 5. 清单 + 报告 ---------------------------------------------------
    from dataclasses import asdict
    result = {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input": {
            "path": str(pkg.source),
            "name": pkg.source.name,
            "size": pkg.source.stat().st_size,
            "sha256": _sha256_of(pkg.source),
            "inner_apk": pkg.display_name,
        },
        "detection": det.summary(),
        "outputs": [asdict(i) for i in items],
        "injected_entries": det.injected_entries,
        "warnings": warnings,
        "output_dir": str(out),
    }
    (out / "manifest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if make_report:
        report = out / "拆分报告.html"
        report.write_text(build_report(result), encoding="utf-8")
        result["report_path"] = str(report)
    tick(f"完成 ✓ 输出目录：{out}", 1.0)
    return result


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(_CHUNK), b""):
            h.update(buf)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 五、HTML 报告
# ---------------------------------------------------------------------------

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#14161b;color:#e7eaf1;font:14px/1.7 "Microsoft YaHei UI","Segoe UI",sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:36px 24px 64px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:.5px}
h2{font-size:17px;margin:32px 0 14px;color:#8ee6c8;border-left:3px solid #4cc2a1;padding-left:10px}
.sub{color:#8b93a3;font-size:13px;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.card{background:#1d2027;border:1px solid #2c313b;border-radius:12px;padding:16px 18px}
.card .k{color:#8b93a3;font-size:12px;margin-bottom:6px}
.card .v{font-size:16px;font-weight:600;word-break:break-all}
.ok{color:#7ee0b8}.warn{color:#f0b455}.bad{color:#f08080}.muted{color:#8b93a3}
table{width:100%;border-collapse:collapse;background:#1d2027;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid #292e38;font-size:13px;vertical-align:top}
th{background:#232730;color:#a9b2c3;font-weight:600}
tr:last-child td{border-bottom:none}
code{background:#262b34;padding:2px 6px;border-radius:4px;font-size:12px;color:#b8d8ff;word-break:break-all}
.note{background:#1d2027;border:1px solid #2c313b;border-left:3px solid #4cc2a1;border-radius:8px;padding:14px 18px;margin:10px 0;color:#c7cdd9}
.foot{margin-top:40px;padding-top:18px;border-top:1px solid #292e38;color:#767e8e;font-size:12px}
details{margin-top:12px}summary{cursor:pointer;color:#8ee6c8}
pre{background:#191c22;border:1px solid #2c313b;border-radius:8px;padding:14px;overflow:auto;font-size:12px;color:#b9c2d2}
"""


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _mb(n: int) -> str:
    return f"{n / 1048576:.2f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB"


def build_report(r: dict) -> str:
    """生成纯静态深色报告，所有动态文本都做 HTML 转义。"""
    d = r["detection"]
    p: list[str] = []
    a = p.append

    a("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>")
    a("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    a(f"<title>{_esc(TOOL_NAME)} · 拆分报告</title><style>{_CSS}</style></head><body><div class='wrap'>")
    a(f"<h1>🌿 {_esc(TOOL_NAME)}</h1>")
    a(f"<div class='sub'>拆分报告 · 生成于 {_esc(r['generated_at'])} · 引擎 v{_esc(r['version'])}</div>")

    a("<h2>概览</h2><div class='grid'>")
    for k, v, cls in [
        ("输入文件", r["input"]["name"], ""),
        ("输入大小", _mb(r["input"]["size"]), ""),
        ("打包框架", d["framework"], "ok" if d["found"] else "warn"),
        ("打包模式", d["mode"], ""),
        ("内嵌原始 APK", "有 ✓" if d["origin_entry"] else "无 ✗", "ok" if d["origin_entry"] else "bad"),
        ("内置模块数量", str(len(d["modules"])), ""),
    ]:
        a(f"<div class='card'><div class='k'>{_esc(k)}</div><div class='v {cls}'>{_esc(v)}</div></div>")
    a("</div>")

    a("<h2>拆分结果</h2>")
    rows = [i for i in r["outputs"] if i["role"] in ("original", "module")]
    if rows:
        a("<table><tr><th>类别</th><th>文件</th><th>大小</th><th>校验</th><th>说明</th></tr>")
        for i in rows:
            role = "原版软件" if i["role"] == "original" else "内置模块"
            crc = ("<span class='ok'>CRC ✓</span>" if i.get("crc_ok") else "<span class='bad'>CRC ✗</span>")
            valid = ("<span class='ok'>APK 完整</span>" if i.get("apk_valid") else "<span class='warn'>需检查</span>")
            a(f"<tr><td><b>{role}</b></td><td><code>{_esc(i['name'])}</code></td>"
              f"<td>{_mb(i['size'])}</td><td>{crc}<br>{valid}</td>"
              f"<td class='muted'>{_esc(i.get('note', ''))}</td></tr>")
        a("</table>")
    else:
        a("<div class='note'>没有可拆出的原版 APK 或模块。</div>")

    a("<h2>文件指纹（SHA-256）</h2><table><tr><th>文件</th><th>哈希</th></tr>")
    for i in rows:
        a(f"<tr><td>{_esc(i['name'])}</td><td><code>{_esc(i['sha256'])}</code></td></tr>")
    a(f"<tr><td>输入文件</td><td><code>{_esc(r['input']['sha256'])}</code></td></tr></table>")

    if d["config"]:
        a("<h2>修补配置（config.json）</h2><table><tr><th>字段</th><th>值</th></tr>")
        for k, v in d["config"].items():
            text = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
            a(f"<tr><td><code>{_esc(k)}</code></td><td>{_esc(text[:400])}</td></tr>")
        a("</table>")

    a("<h2>诊断与技术说明</h2>")
    for n in d["notes"]:
        a(f"<div class='note'>{_esc(n)}</div>")
    a("<div class='note'>原版 APK 是修补器以 STORED 方式整块嵌入的<strong>原始字节</strong>，"
      "因此包含原厂签名，不需要重签。若设备上已安装签名不同的修补版，需先卸载再安装原版。</div>")
    a("<div class='note'>关于 NestedZip：修补包把原包内部条目也登记到自己的中央目录，"
      "造成 ZIP 条目数据区重叠；Python 3.13+ 的 zipfile 会误判为 zip bomb 并拒绝读取。"
      "本工具按 local file header 自行定位数据区，并用中央目录 CRC32 逐块校验，"
      "保证还原结果与原文件逐字节一致。</div>")

    if r["warnings"]:
        a("<h2>注意事项</h2>")
        for w in r["warnings"]:
            a(f"<div class='note warn'>⚠ {_esc(w)}</div>")

    a(f"<details><summary>查看 manifest.json 原始数据</summary><pre>{_esc(json.dumps(r, ensure_ascii=False, indent=2))}</pre></details>")
    a("<div class='foot'>本工具仅做静态解包与文件还原，不修改、不绕过任何软件的授权或签名校验逻辑。"
      "请只对你有权处理的安装包使用。<br>SplitPatch · 生成于本地，报告不含任何外部资源。</div>")
    a("</div></body></html>")
    return "".join(p)


# ---------------------------------------------------------------------------
# 六、命令行入口
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        prog="splitpatch",
        description="把 LSPatch / NPatch 集成模式打包的 APK 拆成「原版软件 + 内置模块」",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：python splitpatch.py '内置模块.zip' -o D:\\out --export-injected",
    )
    parser.add_argument("input", help="修补后的 .apk，或包着它的 .zip / .apks / .xapk")
    parser.add_argument("-o", "--output", help="输出目录（默认：输入文件旁的 <文件名>_拆分结果）")
    parser.add_argument("--export-injected", action="store_true", help="一并导出 loader/so/config 等注入组件")
    parser.add_argument("--export-payload", action="store_true",
                        help="无内嵌原版时，导出补丁包内的非注入散文件（仅供分析）")
    parser.add_argument("--no-report", action="store_true", help="不生成 HTML 报告")
    parser.add_argument("--dry-run", action="store_true", help="只检测并打印结构，不写任何文件")
    parser.add_argument("--json", action="store_true", help="把最终结果以 JSON 打印到 stdout")
    args = parser.parse_args(argv)

    src = Path(args.input).expanduser()
    outdir = Path(args.output) if args.output else src.parent / f"{_safe_stem(src.name)}_拆分结果"

    quiet = bool(args.json)

    def log(msg: str) -> None:
        if not quiet:
            print(msg, flush=True)

    pkg = None
    try:
        pkg = open_package(src, log=log)
        det = detect(pkg)
        log(f"\n检测结果：{det.framework} / {det.mode}")
        log(f"注入目录：{det.prefix or '（无）'}　中央目录条目：{det.total_entries}")
        log(f"内嵌原版：{det.origin_entry or '（无）'}")
        log(f"内置模块：{len(det.module_entries)} 个 -> {', '.join(Path(m).name for m in det.module_entries) or '（无）'}")
        for n in det.notes:
            log(f"  · {n}")

        if args.dry_run:
            print(json.dumps({"input": str(src), "detection": det.summary()},
                             ensure_ascii=False, indent=2))
            return 0

        result = split(
            pkg, det, outdir,
            export_injected=args.export_injected,
            export_payload=args.export_payload,
            make_report=not args.no_report,
            log=log,
        )
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            log(f"\n输出：{result['output_dir']}")
            for i in result["outputs"]:
                if i["role"] in ("original", "module"):
                    log(f"  [{i['role']}] {i['name']}  {_mb(i['size'])}  CRC {'✓' if i['crc_ok'] else '✗'}")
            if result.get("report_path"):
                log(f"  报告：{result['report_path']}")
        return 0
    except SplitError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"未预期的错误：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    finally:
        if pkg:
            pkg.close()


if __name__ == "__main__":
    raise SystemExit(main())
