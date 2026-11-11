# -*- coding: utf-8 -*-
"""
SplitPatch Android 版构建脚本（不依赖 Gradle、不联网）
=====================================================================
直接用本机 Android SDK 的命令行工具串起完整构建链：

    aapt2 compile  →  aapt2 link  →  javac  →  d8  →  合入 dex
      →  zipalign  →  keytool 自签  →  apksigner sign / verify

用法：python build_apk.py
产物：out/SplitPatch-Android.apk（可直接安装）
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
APP = HERE / "app"
BUILD = HERE / "build"
OUT = HERE / "out"
KEYSTORE_DIR = HERE / "keystore"
FINAL_APK = OUT / "SplitPatch-Android.apk"

# SDK 位置从环境变量读，不写死任何一台机器的绝对路径
SDK = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "")
BUILD_TOOLS = SDK / "build-tools" / "35.0.0"
ANDROID_JAR = SDK / "platforms" / "android-35" / "android.jar"
AAPT2 = BUILD_TOOLS / "aapt2.exe"
ZIPALIGN = BUILD_TOOLS / "zipalign.exe"
D8_JAR = BUILD_TOOLS / "lib" / "d8.jar"
APKSIGNER_JAR = BUILD_TOOLS / "lib" / "apksigner.jar"

MIN_SDK = 26       # Android 8.0
TARGET_SDK = 34    # 本地分发，避开 Android 15 强制 edge-to-edge 导致的标题遮挡
STORE_PASS = "splitpatch-local"
KEY_PASS = "splitpatch-local"


def run(cmd: list[str], label: str) -> str:
    print(f"  → {label}")
    proc = subprocess.run(
        [str(c) for c in cmd], capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        print("    [stdout]", (proc.stdout or "").strip()[:2000])
        print("    [stderr]", (proc.stderr or "").strip()[:2000])
        raise RuntimeError(f"{label} 失败（退出码 {proc.returncode}）")
    out = (proc.stdout or "").strip()
    if out:
        for line in out.splitlines()[:6]:
            print("    " + line)
    return out


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not str(SDK) or not SDK.is_dir():
        print("请先设置 ANDROID_HOME（或 ANDROID_SDK_ROOT）指向本机 Android SDK。")
        return 2
    for p in (AAPT2, ZIPALIGN, D8_JAR, APKSIGNER_JAR, ANDROID_JAR):
        if not p.exists():
            print(f"缺少工具：{p}\n请确认 SDK 里装了 build-tools 35.0.0 与 platforms/android-35。")
            return 2

    if BUILD.exists():
        shutil.rmtree(BUILD)
    OUT.mkdir(parents=True, exist_ok=True)
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    gen_dir = BUILD / "gen"
    classes_dir = BUILD / "classes"
    dex_dir = BUILD / "dex"
    for d in (gen_dir, classes_dir, dex_dir):
        d.mkdir(parents=True, exist_ok=True)

    print("[1/9] 编译资源")
    res_zip = BUILD / "res.zip"
    run([AAPT2, "compile", "--dir", APP / "res", "-o", res_zip], "aapt2 compile")

    print("[2/9] 链接 AndroidManifest / 资源，生成 R.java")
    base_apk = BUILD / "base.apk"
    run([
        AAPT2, "link", "-o", base_apk,
        "-I", ANDROID_JAR,
        "--manifest", APP / "AndroidManifest.xml",
        "-R", res_zip,
        "--auto-add-overlay",   # 自定义 string 资源作为 overlay 合入，需显式允许新增
        "--java", gen_dir,
        "--min-sdk-version", MIN_SDK,
        "--target-sdk-version", TARGET_SDK,
        "--version-code", "1",
        "--version-name", "1.0",
    ], "aapt2 link")

    print("[3/9] 编译 Java 源码")
    sources = sorted((APP / "java").rglob("*.java")) + sorted(gen_dir.rglob("*.java"))
    if not sources:
        raise RuntimeError("没找到 Java 源码")
    # JDK 17 用 -source/-target 8 编译 Android 代码；android.jar 只作为 classpath
    run([
        "javac", "-encoding", "UTF-8", "-source", "8", "-target", "8",
        "-classpath", ANDROID_JAR,
        "-d", classes_dir,
        *sources,
    ], f"javac（{len(sources)} 个源文件）")

    print("[4/9] 打包 class → d8 生成 classes.dex")
    classes_jar = BUILD / "classes.jar"
    run(["jar", "cf", classes_jar, "-C", classes_dir, "."], "jar cf")
    run([
        "java", "-cp", D8_JAR, "com.android.tools.r8.D8",
        "--lib", ANDROID_JAR,
        "--min-api", MIN_SDK,
        "--output", dex_dir,
        classes_jar,
    ], "d8")
    dex_file = dex_dir / "classes.dex"
    if not dex_file.exists():
        raise RuntimeError("d8 没有产出 classes.dex")

    print("[5/9] 把 classes.dex 合入 APK")
    with zipfile.ZipFile(base_apk, "a", zipfile.ZIP_DEFLATED) as z:
        z.write(dex_file, "classes.dex")

    print("[6/9] zipalign 对齐")
    aligned = BUILD / "aligned.apk"
    run([ZIPALIGN, "-f", "-p", "4", base_apk, aligned], "zipalign")

    print("[7/9] 准备自签证书（只生成一次，保证以后能覆盖安装）")
    ks = KEYSTORE_DIR / "splitpatch.jks"
    if not ks.exists():
        run([
            "keytool", "-genkeypair",
            "-alias", "splitpatch",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10950",
            "-keystore", ks,
            "-storepass", STORE_PASS, "-keypass", KEY_PASS,
            "-dname", "CN=SplitPatch, OU=Local Tool, O=Local, L=Binzhou, S=Shandong, C=CN",
        ], "keytool")

    print("[8/9] apksigner 签名（v1 + v2 + v3）")
    if FINAL_APK.exists():
        FINAL_APK.unlink()
    run([
        "java", "-jar", APKSIGNER_JAR, "sign",
        "--ks", ks,
        "--ks-pass", f"pass:{STORE_PASS}",
        "--key-pass", f"pass:{KEY_PASS}",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", FINAL_APK,
        aligned,
    ], "apksigner sign")

    print("[9/9] 校验产物")
    run(["java", "-jar", APKSIGNER_JAR, "verify", "--verbose", FINAL_APK], "apksigner verify")
    badging = run([AAPT2, "dump", "badging", FINAL_APK], "aapt2 dump badging")
    print("\n" + "=" * 60)
    print(f"完成 ✓  {FINAL_APK}  ({FINAL_APK.stat().st_size / 1024:.1f} KB)")
    for line in badging.splitlines():
        if line.startswith(("package:", "application-label", "sdkVersion", "targetSdkVersion", "launchable-activity")):
            print("  " + line)
    print("=" * 60)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"构建失败：{exc}")
        raise SystemExit(1)
