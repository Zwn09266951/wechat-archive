"""微信 4.x 本地数据库只读快照、SQLCipher4 解密与 WAL 增量帧合并模块。"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("wechat_archive.decryptor")

PAGE_SZ = 4096


def _load_wcdb_tool(wcdb_tool_dir: str):
    tool_dir = os.path.abspath(wcdb_tool_dir)
    if tool_dir not in sys.path:
        sys.path.insert(0, tool_dir)
    if sys.platform == "win32":
        import wcdb_key_tool_windows as wkt  # type: ignore
    elif sys.platform == "darwin":
        import wcdb_key_tool_macos as wkt  # type: ignore
    else:
        import wcdb_key_tool as wkt  # type: ignore
    return wkt


def auto_detect_db_storage_dir(wcdb_tool_dir: str) -> Optional[str]:
    """尝试自动检测当前平台的微信 db_storage 目录。"""
    wkt = _load_wcdb_tool(wcdb_tool_dir)
    finder = getattr(wkt, "auto_detect_db_dir", None)
    if callable(finder):
        return finder()
    return None


def _wal_checksum(data: bytes, s0: int, s1: int, big_endian: bool) -> Tuple[int, int]:
    fmt = ">2I" if big_endian else "<2I"
    for i in range(0, len(data), 8):
        x0, x1 = struct.unpack_from(fmt, data, i)
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF
    return s0, s1


def load_keys(keys_file: str) -> Dict[str, dict]:
    if not os.path.exists(keys_file):
        return {}
    with open(keys_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)}


def refresh_keys(db_storage_dir: str, keys_file: str, wcdb_tool_dir: str) -> Dict[str, dict]:
    """按平台刷新微信数据库密钥文件。"""
    wkt = _load_wcdb_tool(wcdb_tool_dir)
    os.makedirs(os.path.dirname(os.path.abspath(keys_file)), exist_ok=True)

    if sys.platform == "win32":
        logger.info("正在从运行中的 Weixin.exe 只读扫描数据库密钥...")
        wkt._scan_memory_raw_key(db_storage_dir, keys_file)
        return load_keys(keys_file)

    if sys.platform == "darwin":
        db_files, salt_to_dbs = wkt.collect_db_files(db_storage_dir)
        if not db_files:
            raise RuntimeError(f"未在 {db_storage_dir} 找到微信数据库文件")

        # 1. 优先使用已缓存的 passphrase 进行 PBKDF2 派生（无需 root / 无需重启微信）
        passphrase_hex = wkt.load_passphrase()
        if passphrase_hex:
            logger.info("正在使用已缓存的 macOS passphrase 派生数据库密钥（约需 30-60 秒）...")
            key_map = wkt._derive_keys_from_passphrase(bytes.fromhex(passphrase_hex), db_files, salt_to_dbs)
            if key_map:
                wkt._save_results(db_files, salt_to_dbs, key_map, db_storage_dir, keys_file)
                return load_keys(keys_file)
            logger.warning("已缓存的 passphrase 未能验证通过，将继续尝试提取...")

        # 2. 尝试内存扫描（微信 4.0.x 且具备 root 权限时有效）
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                logger.info("正在尝试从 macOS WeChat 进程扫描内存密钥...")
                wkt._scan_memory_raw_key(db_storage_dir, keys_file)
                return load_keys(keys_file)
            except Exception as e:
                logger.warning("macOS 内存扫描未能获取到密钥: %s", e)

        tool_script = os.path.join(os.path.abspath(wcdb_tool_dir), "wcdb_key_tool_macos.py")
        raise RuntimeError(
            "macOS 首次提取微信 4.1+ 数据库密钥需要 root 权限与 LLDB 断点捕获（只需执行一次）。\n"
            "请先在终端运行：\n"
            f'  sudo python3 "{tool_script}" extract --db-dir "{db_storage_dir}" --output "{keys_file}"\n'
            "如提示签名校验失败，请先执行一次重签名并重启微信：\n"
            "  sudo codesign --force --deep --sign - /Applications/WeChat.app"
        )

    # Linux 等其他平台回退
    logger.info("正在尝试扫描数据库密钥...")
    wkt._scan_memory_raw_key(db_storage_dir, keys_file)
    return load_keys(keys_file)


def _lookup_key(keys: Dict[str, dict], rel_path: str) -> Optional[bytes]:
    norm = rel_path.replace("/", "\\")
    candidates = [norm, rel_path.replace("\\", "/"), os.path.basename(rel_path)]
    for cand in candidates:
        info = keys.get(cand)
        if info and info.get("enc_key"):
            return bytes.fromhex(info["enc_key"])
    return None


def _apply_wal_frames(
    dec_base_path: str,
    wal_path: str,
    enc_key: bytes,
    wkt,
    out_path: str,
) -> Tuple[bool, int]:
    """校验并解密 WAL 中已提交的增量帧，合并到解密后的主库中。"""
    if not os.path.exists(wal_path) or os.path.getsize(wal_path) <= 32:
        shutil.copy2(dec_base_path, out_path)
        return True, 0

    with open(wal_path, "rb") as f:
        wal = f.read()

    if len(wal) < 32:
        shutil.copy2(dec_base_path, out_path)
        return True, 0

    magic, _fmt, pg_sz, _ckpt, salt1, salt2, ck1, ck2 = struct.unpack(">8I", wal[:32])
    if magic not in (0x377F0682, 0x377F0683) or pg_sz != PAGE_SZ:
        shutil.copy2(dec_base_path, out_path)
        return True, 0

    big_endian = magic == 0x377F0683
    s0, s1 = _wal_checksum(wal[:24], 0, 0, big_endian)
    if (s0, s1) != (ck1, ck2):
        logger.debug("WAL header checksum 不匹配，回退使用基础库: %s", wal_path)
        shutil.copy2(dec_base_path, out_path)
        return False, 0

    frame_sz = 24 + pg_sz
    n_frames = (len(wal) - 32) // frame_sz
    valid_frames: List[Tuple[int, int, bytes]] = []
    last_commit_idx = -1

    for i in range(n_frames):
        off = 32 + i * frame_sz
        fhdr = wal[off : off + 24]
        pgno, db_size, fs1, fs2, fck1, fck2 = struct.unpack(">6I", fhdr)
        if fs1 != salt1 or fs2 != salt2 or pgno == 0:
            break
        page = wal[off + 24 : off + frame_sz]
        s0, s1 = _wal_checksum(fhdr[:8], s0, s1, big_endian)
        s0, s1 = _wal_checksum(page, s0, s1, big_endian)
        if (s0, s1) != (fck1, fck2):
            break
        valid_frames.append((pgno, db_size, page))
        if db_size > 0:
            last_commit_idx = i

    committed = valid_frames[: last_commit_idx + 1] if last_commit_idx >= 0 else []
    if not committed:
        shutil.copy2(dec_base_path, out_path)
        return True, 0

    with open(dec_base_path, "rb") as f:
        db_bytes = bytearray(f.read())

    final_db_pages = committed[-1][1]
    for pgno, _db_size, enc_page in committed:
        dec_page = wkt._decrypt_page(enc_key, enc_page, pgno)
        pos = (pgno - 1) * pg_sz
        if pos + pg_sz > len(db_bytes):
            db_bytes.extend(b"\x00" * (pos + pg_sz - len(db_bytes)))
        db_bytes[pos : pos + pg_sz] = dec_page

    if final_db_pages > 0 and len(db_bytes) > final_db_pages * pg_sz:
        db_bytes = db_bytes[: final_db_pages * pg_sz]

    with open(out_path, "wb") as f:
        f.write(db_bytes)

    return True, len(committed)


def _check_sqlite_ok(db_path: str) -> bool:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            res = conn.execute("PRAGMA quick_check").fetchone()
            return bool(res and res[0] == "ok")
        finally:
            conn.close()
    except Exception:
        return False


def decrypt_single_db(
    db_storage_dir: str,
    rel_path: str,
    enc_key: bytes,
    work_dir: str,
    wcdb_tool_dir: str,
    max_retries: int = 2,
) -> str:
    """对单个微信数据库执行只读快照、解密和 WAL 合并，返回解密后的临时路径。"""
    wkt = _load_wcdb_tool(wcdb_tool_dir)
    src_db = os.path.join(db_storage_dir, rel_path)
    src_wal = src_db + "-wal"
    if not os.path.exists(src_db):
        raise FileNotFoundError(f"数据库不存在: {src_db}")

    safe_name = rel_path.replace("\\", "_").replace("/", "_")
    snap_db = os.path.join(work_dir, f"snap_{safe_name}")
    snap_wal = snap_db + "-wal"
    dec_base = os.path.join(work_dir, f"base_{safe_name}")
    dec_final = os.path.join(work_dir, f"merged_{safe_name}")

    for attempt in range(1, max_retries + 1):
        # 紧邻复制主库和 WAL，减少并发写入导致的快照不一致窗口
        shutil.copy2(src_db, snap_db)
        if os.path.exists(src_wal):
            shutil.copy2(src_wal, snap_wal)
        elif os.path.exists(snap_wal):
            os.remove(snap_wal)

        ok = wkt._decrypt_database(snap_db, dec_base, enc_key)
        if not ok:
            raise RuntimeError(f"数据库 HMAC 校验或解密失败: {rel_path}")

        _wal_ok, wal_frames = _apply_wal_frames(dec_base, snap_wal, enc_key, wkt, dec_final)
        if _check_sqlite_ok(dec_final):
            logger.info("解密完成: %s (合并 WAL 帧: %d)", rel_path, wal_frames)
            return dec_final

        if attempt < max_retries:
            logger.warning("快照 %s 遇到微信并发写入，重试 (%d/%d)...", rel_path, attempt, max_retries)
            time.sleep(0.3)

    # 若 WAL 合并仍因极端并发校验失败，回退至基础库（仍做完整度检查）
    if _check_sqlite_ok(dec_base):
        logger.warning("WAL 合并校验未通过，回退使用基础库快照: %s", rel_path)
        return dec_base

    raise RuntimeError(f"解密后 SQLite 完整性校验失败: {rel_path}")


def discover_target_dbs(db_storage_dir: str, include_biz: bool = False) -> List[str]:
    """发现归档所需的联系人、会话及所有消息分库（message_0.db, message_1.db, ...）。"""
    targets: List[str] = []
    for fixed in (os.path.join("contact", "contact.db"), os.path.join("session", "session.db")):
        if os.path.exists(os.path.join(db_storage_dir, fixed)):
            targets.append(fixed)

    msg_dir = Path(db_storage_dir) / "message"
    if msg_dir.is_dir():
        for p in sorted(msg_dir.glob("message_*.db")):
            # 跳过 message_fts.db / message_resource.db
            stem = p.stem
            suffix = stem[len("message_") :]
            if suffix.isdigit():
                targets.append(os.path.relpath(str(p), db_storage_dir))
        if include_biz:
            for p in sorted(msg_dir.glob("biz_message_*.db")):
                targets.append(os.path.relpath(str(p), db_storage_dir))

    return targets


class DecryptedWorkspace:
    """上下文管理器：自动创建临时解密工作区并在退出时彻底清理明文库。"""

    def __init__(
        self,
        db_storage_dir: str,
        keys_file: str,
        wcdb_tool_dir: str,
        include_biz: bool = False,
        force_refresh_keys: bool = False,
    ) -> None:
        self.db_storage_dir = db_storage_dir
        self.keys_file = keys_file
        self.wcdb_tool_dir = wcdb_tool_dir
        self.include_biz = include_biz
        self.force_refresh_keys = force_refresh_keys
        self._tmp_dir: Optional[str] = None
        self.decrypted_paths: Dict[str, str] = {}

    def __enter__(self) -> Dict[str, str]:
        self._tmp_dir = tempfile.mkdtemp(prefix="wx_archive_dec_")
        targets = discover_target_dbs(self.db_storage_dir, include_biz=self.include_biz)
        if not targets:
            raise RuntimeError(f"未在 {self.db_storage_dir} 找到微信数据库文件")

        keys = {} if self.force_refresh_keys else load_keys(self.keys_file)
        missing = [rel for rel in targets if _lookup_key(keys, rel) is None]
        if missing:
            logger.info("缺少 %d 个数据库密钥，尝试自动从微信进程刷新密钥...", len(missing))
            keys = refresh_keys(self.db_storage_dir, self.keys_file, self.wcdb_tool_dir)

        for rel in targets:
            enc_key = _lookup_key(keys, rel)
            if enc_key is None:
                logger.warning("仍未找到密钥，跳过: %s", rel)
                continue
            dec_path = decrypt_single_db(
                db_storage_dir=self.db_storage_dir,
                rel_path=rel,
                enc_key=enc_key,
                work_dir=self._tmp_dir,
                wcdb_tool_dir=self.wcdb_tool_dir,
            )
            self.decrypted_paths[rel.replace("\\", "/")] = dec_path

        return self.decrypted_paths

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
