#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QQ 聊天图片/视频/表情包批量下载器（Win11 风格 GUI，高 DPI 适配）

支持：
  * 目标类型：群聊 / 个人（好友）
  * 内容类型：图片 / 视频 / 表情包（分别勾选，各自可勾选三种来源）
  * 来源：直接发送、转发的聊天记录（第一层）、嵌套转发的聊天记录（层数可设，0=不限）
  * 一条消息里连发的多张图
  * 下载原图（CDN spec=0，缺失时退回 720/198）

依赖：pip install cryptography
运行：双击 启动.bat，或 python qq_group_images.py
"""

import argparse
import collections
import ctypes
import ctypes.wintypes as wt
import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

APP_TITLE = "QQ聊天媒体提取"
CDN_HOST = "https://multimedia.nt.qq.com.cn"
CDN_IMG = CDN_HOST + "/download?appid=1407"
CDN_VID = CDN_HOST + "/download?appid=1406"
VID_EXTRA = ("&client_proto=ntv2&client_appid=537379411&client_type=win"
             "&client_ver=9.9.33-52230&client_down_type=auto&client_aio_type=unk")
PAGE = 4096
NDB_HEADER = 1024
KEY_HMAC_ALGOS = (("sha1", 20), ("sha256", 32), ("sha512", 64))

# ---------------------------------------------------------------- Windows API

k32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD),
    ]


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
KEY_ISLAND = re.compile(rb"(?<![\x20-\x7e])[\x20-\x7e]{16}(?![\x20-\x7e])")
RKEY_RE = re.compile(rb"rkey=([A-Za-z0-9_\-%=]{20,600})")


def qq_pids():
    if k32 is None:
        return []
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    out = []
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == b"qq.exe":
                out.append(pe.th32ProcessID)
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return out


def iter_regions(handle, private_only=False, max_region=256 << 20):
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x7FFFFFFF0000:
        rc = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if rc == 0:
            break
        size = mbi.RegionSize
        if not size:
            break
        ok = (mbi.State == MEM_COMMIT and mbi.Protect in READABLE and size <= max_region)
        if private_only and mbi.Type != MEM_PRIVATE:
            ok = False
        if ok:
            yield int(mbi.BaseAddress or 0), size
        addr += size


def iter_region_bytes(handle, private_only=False):
    for base, size in iter_regions(handle, private_only):
        off = 0
        while off < size:
            n = min(1 << 22, size - off)
            buf = (ctypes.c_char * n)()
            got = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base + off), buf, n, ctypes.byref(got)):
                yield bytes(buf.raw[: got.value])
            off += n


# ---------------------------------------------------------------- 密钥与解密

def _pbkdf2(password, salt, iterations, length=32):
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, length)


def _page1_ok(key, page, salt):
    for alg_name, hmac_sz in KEY_HMAC_ALGOS:
        reserve = ((16 + hmac_sz + 15) // 16) * 16
        size = PAGE - 16 - reserve
        ek = _pbkdf2(key, salt, 4000)
        hk = _pbkdf2(ek, bytes(b ^ 0x3A for b in salt), 2)
        mac = page[16 + size + 16:16 + size + 16 + hmac_sz]
        if len(mac) != hmac_sz:
            continue
        hm = hmac.new(hk, None, getattr(hashlib, alg_name))
        hm.update(page[16:16 + size + 16])
        hm.update(struct.pack("<I", 1))
        if hmac.compare_digest(mac, hm.digest()):
            return alg_name, reserve
    return None


if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.json"


def _app_icon_path():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        p = Path(sys._MEIPASS) / "aoba.ico"
        if p.exists():
            return p
    p = APP_DIR / "aoba.ico"
    return p if p.exists() else None


def _load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_config(cfg):
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception:
        pass


def _tencent_files_dirs():
    """返回可能存在的 Tencent Files 目录列表（不依赖固定账号/固定盘符）。"""
    home = Path(os.path.expanduser("~"))
    dirs = [
        home / "Documents" / "Tencent Files",
        home / "OneDrive" / "Documents" / "Tencent Files",
        Path("C:/Users/Public/Documents/Tencent Files"),
        home / "Documents" / "Tencent Files-NT",
    ]
    env = os.environ.get("QQ_MEDIA_TENCENT_DIR")
    if env:
        dirs.insert(0, Path(env))
    for letter in "CDEFGH":
        for sub in ("Tencent Files", "Documents/Tencent Files", "TencentFiles"):
            dirs.append(Path(f"{letter}:/") / sub)
    return [d for d in dirs if d.exists()]


def _scan_db_under(base):
    out = []
    try:
        for uin in base.iterdir():
            if not uin.is_dir():
                continue
            db = uin / "nt_qq" / "nt_db" / "nt_msg.db"
            if db.exists():
                out.append(db)
    except OSError:
        pass
    return out


_LAST_DB_LOGGED = None


def find_qq_db(log=print):
    global _LAST_DB_LOGGED
    cfg = _load_config()
    manual = cfg.get("db_path")
    if manual and Path(manual).exists():
        if log and str(manual) != _LAST_DB_LOGGED:
            log(f"数据库（手动指定）：{manual}")
            _LAST_DB_LOGGED = str(manual)
        return str(manual)
    cands = []
    for base in _tencent_files_dirs():
        cands += _scan_db_under(base)
    env_db = os.environ.get("QQ_MEDIA_DB")
    if env_db and Path(env_db).exists():
        cands.insert(0, Path(env_db))
    if not cands:
        raise RuntimeError(
            "未找到 QQ 数据库。请点击界面上的「选择数据库…」手动指定 nt_msg.db，"
            "或确认 QQ 已登录且聊天记录位于 Tencent Files 下。")
    cands = list(dict.fromkeys(str(p) for p in cands))
    cands.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    if log and cands[0] != _LAST_DB_LOGGED:
        log(f"数据库：{cands[0]}")
        _LAST_DB_LOGGED = cands[0]
    return cands[0]


def extract_db_key(db_path, log=print, cancel=None):
    if k32 is None:
        raise RuntimeError("该功能只支持 Windows。")
    with open(db_path, "rb") as f:
        f.seek(NDB_HEADER)
        page = f.read(PAGE)
    salt = page[:16]
    pids = qq_pids()
    if not pids:
        raise RuntimeError("没有检测到运行中的 QQ.exe，请先登录 QQ。")
    log(f"检测到 {len(pids)} 个 QQ 进程，开始提取数据库密钥……")
    for pid in pids:
        if cancel is not None and cancel.is_set():
            return None
        h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not h:
            continue
        try:
            seen = set()
            for data in iter_region_bytes(h, private_only=True):
                for m in KEY_ISLAND.finditer(data):
                    cand = m.group()
                    if cand in seen:
                        continue
                    seen.add(cand)
                    if _page1_ok(cand, page, salt):
                        log("数据库密钥提取成功。")
                        return cand
        finally:
            k32.CloseHandle(h)
    raise RuntimeError("未能从 QQ 内存中提取到数据库密钥。")


def decrypt_db(db_path, out_path, key, log=print, cancel=None):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:
        raise RuntimeError("缺少 cryptography 库，请先执行：pip install cryptography") from exc
    with open(db_path, "rb") as f:
        raw = f.read()
    body = raw[NDB_HEADER:]
    pages = len(body) // PAGE
    salt = body[:16]
    chosen = _page1_ok(key, body[:PAGE], salt)
    if not chosen:
        raise RuntimeError("数据库密钥校验失败。")
    _, reserve = chosen
    ek = _pbkdf2(key, salt, 4000)
    size1 = PAGE - 16 - reserve
    out = bytearray(pages * PAGE)
    for i in range(pages):
        if cancel is not None and cancel.is_set():
            return None
        page = body[i * PAGE:(i + 1) * PAGE]
        if i == 0:
            ct, iv = page[16:16 + size1], page[16 + size1:16 + size1 + 16]
            d = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
            out[:PAGE] = b"SQLite format 3\x00" + d.update(ct) + d.finalize() + b"\x00" * reserve
        else:
            size = PAGE - reserve
            ct, iv = page[:size], page[size:size + 16]
            d = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
            out[i * PAGE:(i + 1) * PAGE] = d.update(ct) + d.finalize() + b"\x00" * reserve
    with open(out_path, "wb") as f:
        f.write(out)
    log(f"数据库解密完成（{pages} 页）。")
    return out_path


# ---------------------------------------------------------------- protobuf

def _varint(buf, i):
    shift = 0
    val = 0
    while True:
        if i >= len(buf):
            raise ValueError("eof")
        x = buf[i]
        i += 1
        val |= (x & 0x7F) << shift
        if not x & 0x80:
            return val, i
        shift += 7
        if shift > 70:
            raise ValueError("varint")


def _fields(buf):
    i = 0
    out = []
    while i < len(buf):
        try:
            tag, i = _varint(buf, i)
        except (ValueError, IndexError):
            return out
        f, wt = tag >> 3, tag & 7
        try:
            if wt == 0:
                val, i = _varint(buf, i)
            elif wt == 1:
                val = buf[i:i + 8]
                i += 8
            elif wt == 2:
                ln, i = _varint(buf, i)
                val = buf[i:i + ln]
                i += ln
            elif wt == 5:
                val = buf[i:i + 4]
                i += 4
            else:
                return out
            out.append((f, wt, val))
        except (ValueError, IndexError):
            return out
    return out


def _first(fs, num, default=None):
    for f, wt, val in fs:
        if f == num:
            return val
    return default


def _elements_of(container):
    fs = _fields(container or b"")
    els = [v for f, wt, v in fs if f == 40800 and isinstance(v, bytes)]
    if not els and _first(fs, 45002) is not None:
        els = [container]
    return els


def _children_of(container):
    return [v for f, wt, v in _fields(container or b"") if f == 40900 and isinstance(v, bytes)]


def _classify(el, msg_sub):
    """返回 {kind, fid, fid2, fname, urls} 或 None。kind: image/video/sticker"""
    fs = _fields(el or b"")
    et = _first(fs, 45002)
    fid = (_first(fs, 45503) or b"").decode("latin-1")
    fid2 = (_first(fs, 45510) or b"").decode("latin-1")
    fname = (_first(fs, 45402) or b"").decode("latin-1")
    urls = []
    for num in (45804, 45802, 45803):
        u = _first(fs, num)
        if isinstance(u, bytes):
            s = u.decode("latin-1")
            if s.startswith("/"):
                s = CDN_HOST + s
            if s not in urls:
                urls.append(s)
    if et == 2 and fid:
        kind = "sticker" if msg_sub == 4096 else "image"
        return {"kind": kind, "fid": fid, "fid2": "", "fname": fname, "urls": urls}
    if et == 5:
        fid = fid or fid2
        if fid:
            return {"kind": "video", "fid": fid, "fid2": fid2, "fname": fname, "urls": urls}
    return None


def _walk_nested(msg, out, depth, max_depth, cancel=None):
    if max_depth and depth > max_depth:
        return
    fs = _fields(msg)
    sub = _first(fs, 40012)
    for el in _elements_of(msg):
        item = _classify(el, sub)
        if item:
            out.append({**item, "depth": depth})
    for kid in _children_of(msg):
        if cancel is not None and cancel.is_set():
            return
        _walk_nested(kid, out, depth + 1, max_depth, cancel)


def _depth_allowed(depth, src_single, src_merged, src_forward, max_depth, multi=False):
    if depth == 0:
        return src_merged if multi else src_single
    if not src_forward:
        return False
    return not (max_depth and depth > max_depth)


def collect_items(plain_db, chat_kind, target, start_ts, end_ts, log, cancel=None,
                  want=None, sources=None, depths=None):
    want = want or {"image": True, "video": False, "sticker": False}
    sources = sources or {k: {"single": True, "merged": True, "forward": True}
                          for k in ("image", "video", "sticker")}
    depths = depths or {k: 0 for k in ("image", "video", "sticker")}
    table = "group_msg_table" if chat_kind == "group" else "c2c_msg_table"
    con = sqlite3.connect(f"file:{plain_db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            f'select "40001","40050","40011","40012","40800","40900" from {table} '
            f'where "40030"=? order by "40050" asc, "40001" asc', (target,)).fetchall()
        if not rows and chat_kind == "group":
            rows = con.execute(
                f'select "40001","40050","40011","40012","40800","40900" from {table} '
                f'where "40021"=? order by "40050" asc, "40001" asc', (str(target),)).fetchall()
    finally:
        con.close()
    if not rows:
        raise RuntimeError(f"数据库里没有找到 {('群' if chat_kind == 'group' else '好友')} {target} 的消息。")
    log(f"目标 {target} 共有 {len(rows)} 条本地消息。")

    items = []
    for mid, ts, mtype, sub, c408, c409 in rows:
        if cancel is not None and cancel.is_set():
            return []
        if not ts or ts < start_ts or ts > end_ts:
            continue
        top_items = []
        for el in _elements_of(c408 or b""):
            item = _classify(el, sub)
            if item:
                top_items.append(item)
        kind_counts = collections.Counter(x["kind"] for x in top_items)
        for item in top_items:
            items.append({**item, "depth": 0,
                          "multi": kind_counts[item["kind"]] > 1})
        need_deep = any(sources.get(k, {}).get("forward") for k in want if want.get(k))
        if need_deep:
            limits = [depths.get(k, 0) for k in want if want.get(k)]
            walk_limit = 0 if (not limits or 0 in limits) else max(limits)
            for kid in [v for f, wt, v in _fields(c409 or b"") if f == 40900 and isinstance(v, bytes)]:
                _walk_nested(kid, items, 1, walk_limit, cancel)

    selected = []
    for r in items:
        kind = r["kind"]
        if not want.get(kind):
            continue
        src = sources.get(kind, {})
        if not _depth_allowed(r["depth"], src.get("single", True),
                              src.get("merged", True),
                              src.get("forward", True),
                              depths.get(kind, 0), r.get("multi", False)):
            continue
        selected.append(r)
    uniq = {}
    for r in selected:
        uniq.setdefault((r["kind"], r["fid"]), r)
    result = list(uniq.values())
    counts = {"image": 0, "video": 0, "sticker": 0}
    for r in result:
        counts[r["kind"]] += 1
    log(f"时间范围内匹配到 {len(result)} 个（图片 {counts['image']}，视频 {counts['video']}，"
        f"表情包 {counts['sticker']}）。")
    return result


def _count_desc_messages(msg):
    return sum(1 + _count_desc_messages(k) for k in _children_of(msg))


def find_forward_gaps(plain_db, chat_kind, target, start_ts, end_ts):
    """找出本地缓存不完整的转发记录（记录头写的条数 > 本地实际条数）。"""
    table = "group_msg_table" if chat_kind == "group" else "c2c_msg_table"
    con = sqlite3.connect(f"file:{plain_db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            f'select "40001","40050","40900" from {table} where "40030"=?', (target,)).fetchall()
    finally:
        con.close()
    gaps = []
    seen = set()

    def walk(msg, mid, ts):
        for el in _elements_of(msg):
            ef = _fields(el)
            if _first(ef, 45002) != 16:
                continue
            xml = _first(ef, 48602) or b""
            m = re.search(rb'tSum="(\d+)"', xml)
            if not m:
                continue
            tsum = int(m.group(1))
            desc = _count_desc_messages(msg)
            if desc < tsum:
                key = (mid, tsum, desc)
                if key not in seen:
                    seen.add(key)
                    gaps.append((mid, ts, tsum, desc))
        for kid in _children_of(msg):
            walk(kid, mid, ts)

    for mid, ts, c409 in rows:
        if not ts or ts < start_ts or ts > end_ts:
            continue
        for kid in [v for f, wt, v in _fields(c409 or b"") if f == 40900 and isinstance(v, bytes)]:
            walk(kid, mid, ts)
    return gaps


# ---------------------------------------------------------------- 下载

def _image_ext(head):
    if head[:2] == b"\xff\xd8":
        return "jpg"
    if head[:4] == b"\x89PNG":
        return "png"
    if head[:4] == b"GIF8":
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def _video_ext(head):
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "mp4"
    if head[:4] == b"\x1aE\xdf\xa3":
        return "webm"
    return None


def _recent_probe_fid(plain_db, window_hours=48):
    """找一个最近的消息图片 fileid，用于验证 rkey（与目标时间段无关，避免旧文件过期干扰）。"""
    cut = int(_dt.datetime.now().timestamp()) - window_hours * 3600
    con = sqlite3.connect(f"file:{plain_db}?mode=ro", uri=True)
    try:
        for table in ("group_msg_table", "c2c_msg_table"):
            rows = con.execute(
                f'select "40800" from {table} where "40050" > ? order by "40050" desc limit 300',
                (cut,)).fetchall()
            for (c408,) in rows:
                for el in _elements_of(c408 or b""):
                    item = _classify(el, 0)
                    if item and item["kind"] == "image":
                        return item["fid"]
    finally:
        con.close()
    return None


def _collect_rkey_candidates(log=print, cancel=None):
    if k32 is None:
        return []
    cands = set()
    for pid in qq_pids():
        if cancel is not None and cancel.is_set():
            return []
        h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not h:
            continue
        try:
            for data in iter_region_bytes(h, private_only=False):
                for m in RKEY_RE.finditer(data):
                    cands.add(m.group(1).decode("latin-1"))
        finally:
            k32.CloseHandle(h)
    log(f"找到 {len(cands)} 个 rkey 候选，开始验证……")
    return sorted(cands, key=len, reverse=True)[:500]


def _probe_url(item, plain_db=None):
    if item.get("urls"):
        u = item["urls"][0]
        return u + ("&" if "?" in u else "?") + "rkey="
    if item["kind"] == "video":
        return f"{CDN_VID}&fileid={item['fid']}&spec=0{VID_EXTRA}&rkey="
    if item["kind"] == "sticker":
        return f"{CDN_VID}&fileid={item['fid']}&spec=0{VID_EXTRA}&rkey="
    return f"{CDN_IMG}&fileid={item['fid']}&spec=198&rkey="


def _pick_rkey(cands, probe, want_video, cancel=None):
    for cand in cands:
        if cancel is not None and cancel.is_set():
            return None
        try:
            req = urllib.request.Request(probe + cand, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                head = resp.read(32)
            if (_video_ext(head) if want_video else _image_ext(head)):
                return cand
        except Exception:
            continue
    return None


def find_rkeys(items, plain_db, log=print, cancel=None):
    cands = _collect_rkey_candidates(log, cancel)
    if not cands:
        raise RuntimeError("未找到下载凭证 rkey，请先在 QQ 里打开该聊天查看几张图片后重试。")
    rkeys = {}
    for kind, want_video in (("image", False), ("sticker", False), ("video", True)):
        it = next((x for x in items if x["kind"] == kind), None)
        if it is None:
            continue
        rk = _pick_rkey(cands, _probe_url(it), want_video, cancel)
        if rk:
            rkeys[kind] = rk
            log(f"rkey 验证通过（{kind}）。")
    if "image" not in rkeys:
        probe_fid = _recent_probe_fid(plain_db)
        if probe_fid:
            rk = _pick_rkey(cands, f"{CDN_IMG}&fileid={probe_fid}&spec=198&rkey=", False, cancel)
            if rk:
                rkeys["image"] = rk
                log("rkey 验证通过（用最近消息图片兜底验证）。")
    if not rkeys:
        raise RuntimeError("rkey 验证失败，请先在 QQ 中查看该聊天图片后重试。")
    fallback = rkeys.get("image") or rkeys.get("sticker") or rkeys.get("video")
    for kind in ("image", "sticker", "video"):
        rkeys.setdefault(kind, fallback)
    return rkeys


def _candidate_urls(item):
    urls = list(item.get("urls") or [])

    def spec_rank(u):
        m = re.search(r"[?&]spec=(\d+)", u)
        return {"0": 0, "720": 1, "198": 2}.get(m.group(1) if m else "", 3)

    urls.sort(key=spec_rank)
    kind = item["kind"]
    fids = [item["fid"]]
    if item.get("fid2") and item["fid2"] != item["fid"]:
        fids.append(item["fid2"])
    if kind == "image":
        if not urls:
            urls = [f"{CDN_IMG}&fileid={fid}&spec={spec}" for fid in fids
                    for spec in ("0", "720", "198")]
    elif kind == "sticker":
        extra = [f"{CDN_VID}&fileid={fid}&spec={spec}{VID_EXTRA}" for fid in fids
                 for spec in ("0", "720")]
        urls = urls + extra
    else:  # video
        extra = [f"{CDN_VID}&fileid={fid}&spec={spec}{VID_EXTRA}" for fid in fids
                 for spec in ("0", "720")]
        extra += [f"{CDN_IMG}&fileid={fid}&spec={spec}" for fid in fids
                  for spec in ("0", "720", "198")]
        urls = urls + extra
    return list(dict.fromkeys(urls))


def _fetch_item(item, rkeys, cancel=None):
    if cancel is not None and cancel.is_set():
        return None
    rkey = rkeys.get(item["kind"]) or rkeys.get("image")
    if not rkey:
        return None
    is_video = item["kind"] == "video"
    for base in _candidate_urls(item):
        url = base + ("&" if "?" in base else "?") + "rkey=" + rkey
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read()
            if len(data) < 300:
                continue
            ext = _video_ext(data) if is_video else _image_ext(data)
            if ext:
                return data, ext
        except Exception:
            continue
    return None


def download_items(items, outdir, rkeys, dedupe, log=print, progress=None,
                   cancel=None, limit=None):
    os.makedirs(outdir, exist_ok=True)
    if limit:
        items = items[:limit]
    total = len(items)
    log(f"开始下载 {total} 个文件到：{outdir}")
    seen = set()
    state = {"saved": 0, "fails": 0, "video_fails": 0}

    def one(item):
        return _fetch_item(item, rkeys, cancel)

    prefix = {"image": "image", "video": "video", "sticker": "sticker"}
    with ThreadPoolExecutor(max_workers=10) as ex:
        for item, res in zip(items, ex.map(one, items)):
            if res is None:
                state["fails"] += 1
                if item["kind"] == "video":
                    state["video_fails"] += 1
                continue
            data, ext = res
            md5 = hashlib.md5(data).hexdigest()
            if dedupe and md5 in seen:
                continue
            seen.add(md5)
            state["saved"] += 1
            name = f"{prefix[item['kind']]}_{state['saved']:04d}.{ext}"
            with open(os.path.join(outdir, name), "wb") as f:
                f.write(data)
            if progress:
                progress(state["saved"] + state["fails"], total)
    log(f"下载完成：成功 {state['saved']} 个，失败 {state['fails']} 个"
        + (f"（其中视频失败 {state['video_fails']} 个）" if state["video_fails"] else ""))
    return state["saved"]


# ---------------------------------------------------------------- 主流程

def run_pipeline(chat_kind, target, start_dt, end_dt, outdir, dedupe=True, log=print,
                 progress=None, cancel=None, limit=None, key=None,
                 want=None, sources=None, depths=None):
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())
    work = tempfile.mkdtemp(prefix="qqmedia_")
    try:
        db = find_qq_db(log)
        if key is None:
            log("正在从 QQ 进程内存提取数据库密钥（只读）……")
            key = extract_db_key(db, log, cancel)
        if key is None:
            return 0
        plain = os.path.join(work, "nt_msg_plain.db")
        if decrypt_db(db, plain, key, log, cancel) is None:
            return 0
        items = collect_items(plain, chat_kind, target, start_ts, end_ts, log, cancel,
                              want=want, sources=sources, depths=depths)
        gaps = find_forward_gaps(plain, chat_kind, target, start_ts, end_ts)
        if gaps:
            log(f"注意：有 {len(gaps)} 条转发记录本地缓存不完整（QQ 通常要打开过一次才会下载正文）：")
            for mid, ts, tsum, desc in gaps[:8]:
                when = _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                log(f"  {when}  记录 {mid}：应有 {tsum} 条，本地仅 {desc} 条")
                log("  → 在 QQ 里点开这条记录一次，再重新运行即可补全。")

        if not items:
            log("该时间范围内没有符合条件的文件。")
            return 0
        rkeys = find_rkeys(items, plain, log, cancel)
        if not rkeys:
            return 0
        return download_items(items, outdir, rkeys, dedupe, log, progress, cancel, limit)
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------- GUI

def _enable_dpi_awareness():
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def launch_gui():
    _enable_dpi_awareness()
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk, font as tkfont

    root = tk.Tk()
    root.title(APP_TITLE)
    icon_path = _app_icon_path()
    if icon_path:
        try:
            root.iconbitmap(default=str(icon_path))
        except Exception:
            pass
    dpi = root.winfo_fpixels("1i")
    scale = dpi / 96.0
    root.tk.call("tk", "scaling", dpi / 72.0)
    scr_w, scr_h = root.winfo_screenwidth(), root.winfo_screenheight()
    win_w = min(int(1020 * scale), int(scr_w * 0.94))
    win_h = min(int(820 * scale), int(scr_h * 0.92))
    pos_x = max(0, (scr_w - win_w) // 2)
    pos_y = max(10, (scr_h - win_h) // 3)
    if pos_y + win_h > scr_h - 30:
        pos_y = max(10, scr_h - win_h - 60)
    root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
    root.minsize(min(int(940 * scale), win_w), min(int(740 * scale), win_h))

    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(name).configure(family="Segoe UI", size=10)
        except Exception:
            pass

    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except Exception:
        pass
    style.configure("TLabelframe", padding=10)
    style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
    style.configure("TButton", padding=(10, 5))
    style.configure("TCheckbutton", padding=(2, 2))

    PX, PY = 14, 8
    head = ttk.Frame(root)
    head.pack(fill="x", padx=PX, pady=(12, 4))
    ttk.Label(head, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(side="left")
    ttk.Label(head, text="支持群聊/好友、转发与嵌套转发、多图连发；可选图片/视频/表情包",
              foreground="#666666").pack(side="left", padx=(14, 0), pady=(9, 0))

    # ① 密钥
    key_frame = ttk.LabelFrame(root, text=" ① QQ 进程与数据库密钥 ")
    key_frame.pack(fill="x", padx=PX, pady=(4, 6))
    k1 = ttk.Frame(key_frame)
    k1.pack(fill="x", pady=(0, 6))
    detect_btn = ttk.Button(k1, text="检测 QQ 进程并获取密钥")
    detect_btn.pack(side="left")
    key_status = tk.StringVar(value="未检测")
    ttk.Label(k1, textvariable=key_status, foreground="#0067c0").pack(side="left", padx=(12, 0))

    cfg_now = _load_config()
    db_mode = tk.StringVar(value="manual" if cfg_now.get("db_path") else "auto")
    db_path_var = tk.StringVar(value=cfg_now.get("db_path") or "")
    k1b = ttk.Frame(key_frame)
    k1b.pack(fill="x", pady=(0, 6))

    def choose_db():
        p = filedialog.askopenfilename(
            title="选择 nt_msg.db",
            filetypes=[("nt_msg.db", "nt_msg.db"), ("SQLite 数据库", "*.db"), ("所有文件", "*.*")])
        if not p:
            if not db_path_var.get():
                db_mode.set("auto")
            return
        if not os.path.isfile(p):
            messagebox.showerror(APP_TITLE, "选择的数据库文件不存在。")
            db_mode.set("auto")
            return
        same = db_path_var.get() == p
        cfg = _load_config()
        cfg["db_path"] = p
        _save_config(cfg)
        db_path_var.set(p)
        db_mode.set("manual")
        if not same:
            log(f"已手动指定数据库：{p}")

    def on_manual():
        if db_mode.get() == "manual" and not db_path_var.get():
            choose_db()

    def on_auto():
        cfg = _load_config()
        changed = "db_path" in cfg
        cfg.pop("db_path", None)
        _save_config(cfg)
        if changed:
            log("已切换为自动搜索数据库。")

    ttk.Radiobutton(k1b, text="自动搜索", value="auto", variable=db_mode,
                    command=on_auto).pack(side="left")
    ttk.Radiobutton(k1b, text="选择数据库", value="manual", variable=db_mode,
                    command=on_manual).pack(side="left", padx=(12, 0))
    ttk.Entry(k1b, textvariable=db_path_var, width=54, state="readonly").pack(
        side="left", padx=(6, 0))
    ttk.Button(k1b, text="浏览…", command=choose_db).pack(side="left", padx=(6, 0))

    def show_db_help():
        message = (
            "数据库文件是什么：\n\n"
            "QQ（NTQQ 新版）把聊天记录存在 nt_msg.db 里，通常位于：\n"
            r"C:\Users\你的用户名\Documents\Tencent Files\<QQ号>\nt_qq\nt_db\nt_msg.db" "\n\n"
            "本工具只读这个文件来解析聊天内容，不会修改它。\n"
            "如果你从没改过 QQ 的「聊天记录保存位置」，用「自动搜索」即可。"
        )
        messagebox.showinfo(APP_TITLE, message)

    ttk.Button(k1b, text="?", width=3, command=show_db_help).pack(side="left", padx=(6, 0))
    ttk.Label(key_frame,
              text="提示：没改过 QQ 的聊天记录保存位置就用「自动搜索」，一般不用动。",
              foreground="#888888").pack(fill="x")
    k2 = ttk.Frame(key_frame)
    k2.pack(fill="x")
    ttk.Label(k2, text="数据库密钥：").pack(side="left")
    key_var = tk.StringVar()
    key_entry = ttk.Entry(k2, textvariable=key_var, width=26, show="●")
    key_entry.pack(side="left")
    show_key_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(k2, text="显示密钥", variable=show_key_var,
                    command=lambda: key_entry.configure(show="" if show_key_var.get() else "●")
                    ).pack(side="left", padx=(10, 0))
    ttk.Label(k2, text="（留空则下载时自动提取）", foreground="#888888").pack(side="left", padx=(10, 0))

    # ② 目标与时间
    set_frame = ttk.LabelFrame(root, text=" ② 目标与时间 ")
    set_frame.pack(fill="x", padx=PX, pady=6)
    set_frame.columnconfigure(3, weight=1)

    info_row = ttk.Frame(set_frame)
    info_row.grid(row=0, column=0, columnspan=4, sticky="w", pady=4)
    ttk.Label(info_row, text="聊天类型：").pack(side="left")
    chat_var = tk.StringVar(value="群聊")
    chat_box = ttk.Combobox(info_row, textvariable=chat_var, values=("群聊", "个人（好友）"),
                            width=12, state="readonly")
    chat_box.pack(side="left", padx=(4, 22))
    target_label = ttk.Label(info_row, text="QQ 群号：")
    target_label.pack(side="left")
    target_var = tk.StringVar()
    target_entry = ttk.Entry(info_row, textvariable=target_var, width=26)
    target_entry.pack(side="left", padx=(4, 0))

    def sync_chat_type(*_):
        is_group = chat_var.get().startswith("群")
        target_label.configure(text="QQ 群号：" if is_group else "好友 QQ 号：")

    chat_var.trace_add("write", sync_chat_type)

    ttk.Separator(set_frame, orient="horizontal").grid(row=1, column=0, columnspan=4,
                                                       sticky="ew", pady=(6, 8))

    def spin_row(row, label, default):
        ttk.Label(set_frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
        box = ttk.Frame(set_frame)
        box.grid(row=row, column=1, columnspan=3, sticky="w", pady=3)
        vals = [(default.year, 2000, 2100), (default.month, 1, 12), (default.day, 1, 31),
                (default.hour, 0, 23), (default.minute, 0, 59)]
        out = []
        for (v, lo, hi), unit in zip(vals, ("年", "月", "日", "时", "分")):
            var = tk.IntVar(value=v)
            ttk.Spinbox(box, from_=lo, to=hi, width=6, textvariable=var).pack(side="left")
            ttk.Label(box, text=unit).pack(side="left", padx=(3, 12))
            out.append(var)
        return out

    today = _dt.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_vars = spin_row(2, "开始时间：", today)
    end_vars = spin_row(3, "结束时间：", _dt.datetime.now())

    ttk.Separator(set_frame, orient="horizontal").grid(row=4, column=0, columnspan=4,
                                                       sticky="ew", pady=(8, 8))
    ttk.Label(set_frame, text="保存目录：").grid(row=5, column=0, sticky="w")
    out_var = tk.StringVar()
    out_entry = ttk.Entry(set_frame, textvariable=out_var)
    out_entry.grid(row=5, column=1, columnspan=2, sticky="ew", padx=(4, 6))
    set_frame.columnconfigure(1, weight=1)
    set_frame.columnconfigure(2, weight=0)

    def pick_dir():
        d = filedialog.askdirectory()
        if d:
            out_var.set(d)

    ttk.Button(set_frame, text="浏览…", command=pick_dir).grid(row=5, column=3, sticky="w")
    dedupe_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(set_frame, text="按内容去重（相同文件只保留一份）",
                    variable=dedupe_var).grid(row=6, column=0, columnspan=4, sticky="w", pady=(6, 0))

    # ③ 类型与来源
    src_outer = ttk.LabelFrame(root, text=" ③ 下载类型与来源（每类可单独勾选来源） ")
    src_outer.pack(fill="x", padx=PX, pady=6)

    type_vars = {}
    depth_vars = {}
    type_names = (("image", "图片"), ("video", "视频"), ("sticker", "表情包"))
    src_defs = (("single", "直接发送（单条）"), ("merged", "合并消息发送（一条多图）"), ("forward", "转发 / 嵌套转发"))

    for col, (kind, title) in enumerate(type_names):
        box = ttk.LabelFrame(src_outer, text=title)
        box.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0), pady=2)
        src_outer.columnconfigure(col, weight=1)
        vars_ = {}
        for i, (key, label) in enumerate(src_defs):
            v = tk.BooleanVar(value=False)
            ttk.Checkbutton(box, text=label, variable=v).grid(row=i, column=0, columnspan=2,
                                                              sticky="w", pady=2, padx=4)
            vars_[key] = v
        ttk.Label(box, text="嵌套层数（仅转发）：").grid(row=3, column=0, sticky="w", padx=4, pady=(8, 2))
        dvar = tk.IntVar(value=0)
        dspin = ttk.Spinbox(box, from_=0, to=10, width=4, textvariable=dvar)
        dspin.grid(row=3, column=1, sticky="w", pady=(8, 2))
        ttk.Label(box, text="（0 = 不限层数）", foreground="#888888").grid(
            row=4, column=0, columnspan=2, sticky="w", padx=4)

        def sync_spin(spin=dspin, values=vars_):
            spin.configure(state="normal" if values["forward"].get() else "disabled")

        for sv in vars_.values():
            sv.trace_add("write", lambda *_, sync=sync_spin: sync())
        sync_spin()
        type_vars[kind] = vars_
        depth_vars[kind] = dvar

    ttk.Label(
        src_outer,
        text=("提示：转发/嵌套记录的正文只有 QQ 打开过才会缓存到本地；"
              "若日志提示某条记录不完整，先在 QQ 里点开该记录一次，再重新运行即可补全。\n"
              "未集成 NapCat 等第三方客户端协议（需要注入 QQ，存在封号风险），因此不做自动拉取。"),
        foreground="#888888", justify="left").grid(row=1, column=0, columnspan=3,
                                                  sticky="w", pady=(10, 0))

    # 操作区
    act = ttk.Frame(root)
    act.pack(fill="x", padx=PX, pady=(6, 2))
    start_btn = ttk.Button(act, text="开始下载")
    start_btn.pack(side="left")
    cancel_btn = ttk.Button(act, text="取消", state="disabled")
    cancel_btn.pack(side="left", padx=(8, 0))
    open_btn = ttk.Button(act, text="打开保存目录")
    open_btn.pack(side="left", padx=(8, 0))
    status_var = tk.StringVar(value="就绪")
    ttk.Label(act, textvariable=status_var, foreground="#444444").pack(side="right")

    progress = ttk.Progressbar(root, mode="determinate", maximum=100)
    progress.pack(fill="x", padx=PX, pady=(2, 6))

    log_frame = ttk.Frame(root)
    log_frame.pack(fill="both", expand=True, padx=PX, pady=(0, 12))
    log_text = tk.Text(log_frame, height=11, wrap="word", relief="solid", borderwidth=1)
    sb = ttk.Scrollbar(log_frame, command=log_text.yview)
    log_text.configure(yscrollcommand=sb.set)
    log_text.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    log_text.configure(state="disabled")

    cancel_event = threading.Event()
    state = {"worker": None, "key": None, "detect_running": False}

    def log(msg):
        if msg == getattr(log, "_last", None):
            return
        log._last = msg
        root.after(0, lambda: (log_text.configure(state="normal"),
                               log_text.insert("end", msg + "\n"),
                               log_text.see("end"),
                               log_text.configure(state="disabled")))

    def set_status(text):
        root.after(0, lambda: status_var.set(text))

    def update_progress(done, total):
        def upd():
            progress["maximum"] = max(total, 1)
            progress["value"] = done
            status_var.set(f"下载中 {done}/{total}")
        root.after(0, upd)

    def do_detect():
        if state["detect_running"]:
            return
        state["detect_running"] = True
        detect_btn.configure(state="disabled")
        key_status.set("正在检测与提取密钥……")
        log("开始检测 QQ 进程并提取数据库密钥……")

        def work():
            try:
                db = find_qq_db(log)
                key = extract_db_key(db, log, cancel_event)
                if key is None:
                    return
                state["key"] = key
                root.after(0, lambda: key_var.set(key.decode("latin-1")))
                pids = qq_pids()
                root.after(0, lambda: key_status.set(f"已获取密钥（{len(pids)} 个 QQ 进程）"))
                log(f"密钥：{len(key)} 字节，已填入输入框。")
            except Exception as exc:
                log(f"错误：{exc}")
                root.after(0, lambda: key_status.set("检测失败"))
                root.after(0, lambda: messagebox.showerror(APP_TITLE, str(exc)))
            finally:
                state["detect_running"] = False
                root.after(0, lambda: detect_btn.configure(state="normal"))

        threading.Thread(target=work, daemon=True).start()

    detect_btn.configure(command=do_detect)

    def parse_time(vars_, label="时间"):
        try:
            vals = [v.get() for v in vars_]
        except Exception:
            raise ValueError(f"{label}填写不完整，请用上下箭头选择完整时间。")
        try:
            return _dt.datetime(vals[0], vals[1], vals[2], vals[3], vals[4])
        except Exception:
            raise ValueError(f"{label}不是有效的日期时间，请检查年月日时分。")

    def do_start():
        if state["worker"] and state["worker"].is_alive():
            return
        try:
            kind = "group" if chat_var.get().startswith("群") else "c2c"
            target_text = target_var.get().strip()
            if not target_text:
                raise ValueError("请填写 QQ 群号。" if kind == "group" else "请填写好友 QQ 号。")
            if not target_text.isdigit():
                raise ValueError("号码只能填纯数字（QQ 群号或好友 QQ 号），请不要带空格或其它字符。")
            target = int(target_text)
            if target <= 0:
                raise ValueError("号码无效，请填写正确的 QQ 群号/好友 QQ 号。")
            outdir = out_var.get().strip()
            if not outdir:
                raise ValueError("请选择保存目录。")
            start_dt = parse_time(start_vars, "开始时间")
            end_dt = parse_time(end_vars, "结束时间")
            if end_dt <= start_dt:
                raise ValueError("结束时间必须晚于开始时间。")
            any_type = False
            for kind_key in ("image", "video", "sticker"):
                v = type_vars[kind_key]
                if v["single"].get() or v["merged"].get() or v["forward"].get():
                    any_type = True
                    break
            if not any_type:
                raise ValueError("请先在「③ 下载类型与来源」里勾选要下载的内容类型和来源。")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        key = None
        if key_var.get():
            raw = key_var.get().encode("latin-1", "ignore")
            if len(raw) == 16:
                key = raw
            elif not messagebox.askyesno(APP_TITLE, "密钥不是 16 字节，是否自动重新提取？"):
                return
        if key is None and state.get("key"):
            key = state["key"]

        flags = {k: (type_vars[k]["single"].get() or type_vars[k]["merged"].get()
                     or type_vars[k]["forward"].get()) for k in ("image", "video", "sticker")}
        sources = {k: {"single": type_vars[k]["single"].get(),
                       "merged": type_vars[k]["merged"].get(),
                       "forward": type_vars[k]["forward"].get()}
                   for k in ("image", "video", "sticker")}
        depths = {k: depth_vars[k].get() for k in ("image", "video", "sticker")}

        cancel_event.clear()
        start_btn.configure(state="disabled")
        cancel_btn.configure(state="normal")
        progress["value"] = 0
        set_status("正在准备……")

        def work():
            try:
                saved = run_pipeline(
                    kind, target, start_dt, end_dt, outdir,
                    dedupe=dedupe_var.get(), log=log, progress=update_progress,
                    cancel=cancel_event, key=key,
                    want=flags, sources=sources, depths=depths,
                )
                set_status(f"完成，共保存 {saved} 个文件")
                root.after(0, lambda: messagebox.showinfo(APP_TITLE, f"完成，共保存 {saved} 个文件。"))
            except Exception as exc:
                log(f"错误：{exc}")
                set_status("出错")
                root.after(0, lambda: messagebox.showerror(APP_TITLE, str(exc)))
            finally:
                root.after(0, lambda: (start_btn.configure(state="normal"),
                                       cancel_btn.configure(state="disabled")))

        state["worker"] = threading.Thread(target=work, daemon=True)
        state["worker"].start()

    def do_cancel():
        cancel_event.set()
        set_status("正在取消……")

    def do_open():
        d = out_var.get().strip()
        if d and os.path.isdir(d):
            os.startfile(d)

    start_btn.configure(command=do_start)
    cancel_btn.configure(command=do_cancel)
    open_btn.configure(command=do_open)

    log("提示：需要 QQ 已登录；若最近消息缺失，请完全退出 QQ 再重新打开后重试。")
    log("步骤：① 检测密钥（可留空）→ ② 选聊天类型、填号码、选时间与目录 → ③ 勾类型/来源 → 开始下载")
    root.mainloop()


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="QQ 聊天媒体下载器")
    ap.add_argument("--nogui", action="store_true")
    ap.add_argument("--chat", choices=("group", "c2c"), default="group")
    ap.add_argument("--target", type=int, help="群号或好友QQ号")
    ap.add_argument("--group", type=int, help="兼容旧参数：群号")
    ap.add_argument("--start")
    ap.add_argument("--end")
    ap.add_argument("--out")
    ap.add_argument("--no-dedupe", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--depth", type=int, default=0)
    ap.add_argument("--types", default="image", help="image,video,sticker 组合")
    ap.add_argument("--sources", default="single,merged,forward")
    ap.add_argument("--selftest", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.selftest:
        import traceback
        result = {"ok": False}
        try:
            key = bytes([0x27, 0x2A, 0x60, 0x6B, 0x71, 0x2D, 0x44, 0x5A,
                         0x2E, 0x4A, 0x6E, 0x3F, 0x79, 0x33, 0x3E, 0x25])
            db = find_qq_db(lambda s: None)
            work = tempfile.mkdtemp(prefix="qqselftest_")
            plain = os.path.join(work, "p.db")
            decrypt_db(db, plain, key, lambda s: None)
            now = _dt.datetime.now()
            items = collect_items(
                plain, "group", 436043853,
                int((now - _dt.timedelta(days=1)).timestamp()),
                int(now.timestamp()), lambda s: None,
                want={"image": True, "video": True, "sticker": True},
                sources={k: {"single": True, "merged": True, "forward": True}
                         for k in ("image", "video", "sticker")},
                depths={k: 0 for k in ("image", "video", "sticker")})
            result = {"ok": True, "db": db, "items": len(items),
                      "kinds": dict(collections.Counter(x["kind"] for x in items))}
            shutil.rmtree(work, ignore_errors=True)
        except Exception as exc:
            result = {"ok": False, "error": repr(exc), "trace": traceback.format_exc()[-1200:]}
        Path(args.selftest).write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
        return

    if not args.nogui:
        launch_gui()
        return

    target = args.target or args.group
    if not (target and args.start and args.end and args.out):
        ap.error("需要 --target/--group --start --end --out")
    types = {s.strip() for s in args.types.split(",") if s.strip()}
    srcs = {s.strip() for s in args.sources.split(",") if s.strip()}
    src_single = ("single" in srcs) or ("direct" in srcs)
    src_merged = "merged" in srcs
    src_forward = ("forward" in srcs) or ("nested" in srcs)
    srcs = {"single": src_single, "merged": src_merged, "forward": src_forward}
    want = {k: (k in types) for k in ("image", "video", "sticker")}
    sources = {k: {"single": srcs["single"], "merged": srcs["merged"],
                   "forward": srcs["forward"]} for k in ("image", "video", "sticker")}
    depths = {k: (args.depth if k in types else 0) for k in ("image", "video", "sticker")}
    start_dt = _dt.datetime.strptime(args.start, "%Y-%m-%d %H:%M")
    end_dt = _dt.datetime.strptime(args.end, "%Y-%m-%d %H:%M")
    try:
        saved = run_pipeline(
            args.chat, target, start_dt, end_dt, args.out,
            dedupe=not args.no_dedupe, log=print,
            progress=lambda d, t: print(f"\r下载 {d}/{t}", end="", flush=True),
            limit=args.limit,
            want=want, sources=sources, depths=depths,
        )
    except Exception as exc:
        print(f"\n错误：{exc}")
        return
    print(f"\n完成：{saved} 个")


if __name__ == "__main__":
    main()
