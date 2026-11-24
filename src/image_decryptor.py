"""微信 4.x 本地图片附件（.dat）索引、V1/V2 解密与账号图片密钥只读提取模块。

零第三方依赖：
- Windows：基于原生 CNG (bcrypt.dll) 进行 AES-128-ECB 解密
- macOS：基于系统原生 CommonCrypto (CCCrypt) 进行 AES-128-ECB 解密
"""
from __future__ import annotations

import collections
import ctypes
import ctypes.util
import json
import logging
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("wechat_archive.image_decryptor")

V1_MAGIC = b"\x07\x08V1\x08\x07"
V2_MAGIC = b"\x07\x08V2\x08\x07"
V1_AES_KEY = b"cfcd208495d565ef"

HEX32_RE = re.compile(rb"[0-9a-fA-F]{32}")
MEM_HEX16_RE = re.compile(rb"(?<![0-9a-zA-Z])[0-9a-fA-F]{16}(?![0-9a-zA-Z])")
MEM_HEX32_RE = re.compile(rb"(?<![0-9a-zA-Z])[0-9a-fA-F]{32}(?![0-9a-zA-Z])")
MEM_ALNUM16_RE = re.compile(rb"(?<![0-9a-zA-Z])[0-9a-z]{16}(?![0-9a-zA-Z])")
MEM_ALNUM32_RE = re.compile(rb"(?<![0-9a-zA-Z])[0-9a-z]{32}(?![0-9a-zA-Z])")


# ============================================================
# 跨平台原生 AES-128-ECB 高性能解密器（Windows CNG / macOS CommonCrypto）
# ============================================================

if sys.platform == "win32":
    import ctypes.wintypes as wt

    _bcrypt = ctypes.WinDLL("bcrypt")
    _bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(wt.HANDLE),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_ulong,
    ]
    _bcrypt.BCryptSetProperty.argtypes = [
        wt.HANDLE,
        ctypes.c_wchar_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    _bcrypt.BCryptGenerateSymmetricKey.argtypes = [
        wt.HANDLE,
        ctypes.POINTER(wt.HANDLE),
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    _bcrypt.BCryptDecrypt.argtypes = [
        wt.HANDLE,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_ulong,
    ]
    _bcrypt.BCryptDestroyKey.argtypes = [wt.HANDLE]
    _bcrypt.BCryptCloseAlgorithmProvider.argtypes = [wt.HANDLE, ctypes.c_ulong]

elif sys.platform == "darwin":
    _libSystem = ctypes.CDLL(ctypes.util.find_library("System"))
    _libSystem.CCCrypt.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _libSystem.CCCrypt.restype = ctypes.c_int32
    _kCCDecrypt = 1
    _kCCAlgorithmAES = 0
    _kCCOptionECBMode = 2


class AesEcbDecryptor:
    """跨平台 AES-ECB 解密器（Windows 走 CNG bcrypt.dll，macOS 走 CommonCrypto CCCrypt）。"""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"无效 AES 密钥长度: {len(key)}")
        self._key_bytes = key
        self._h_alg = None
        self._h_key = None

        if sys.platform == "win32":
            self._h_alg = wt.HANDLE()
            self._h_key = wt.HANDLE()
            status = _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(self._h_alg), "AES", None, 0)
            if status != 0:
                raise RuntimeError(f"BCryptOpenAlgorithmProvider failed: {status:#x}")
            try:
                mode = "ChainingModeECB\x00".encode("utf-16-le")
                status = _bcrypt.BCryptSetProperty(self._h_alg, "ChainingMode", mode, len(mode), 0)
                if status != 0:
                    raise RuntimeError(f"BCryptSetProperty failed: {status:#x}")
                status = _bcrypt.BCryptGenerateSymmetricKey(
                    self._h_alg, ctypes.byref(self._h_key), None, 0, key, len(key), 0
                )
                if status != 0:
                    raise RuntimeError(f"BCryptGenerateSymmetricKey failed: {status:#x}")
            except Exception:
                self.close()
                raise
        elif sys.platform != "darwin":
            raise RuntimeError(f"当前平台 {sys.platform} 暂不支持内置 AES-ECB 解密")

    def decrypt(self, data: bytes) -> bytes:
        if not data:
            return b""
        if sys.platform == "win32":
            out = ctypes.create_string_buffer(len(data))
            out_len = wt.ULONG(0)
            status = _bcrypt.BCryptDecrypt(
                self._h_key,
                data,
                len(data),
                None,
                None,
                0,
                out,
                len(data),
                ctypes.byref(out_len),
                0,
            )
            if status != 0:
                raise RuntimeError(f"BCryptDecrypt failed: {status:#x}")
            return out.raw[: out_len.value]

        # macOS CommonCrypto AES-ECB（无 padding，与 Windows CNG 行为一致）
        out = ctypes.create_string_buffer(len(data) + 16)
        out_len = ctypes.c_size_t(0)
        status = _libSystem.CCCrypt(
            _kCCDecrypt,
            _kCCAlgorithmAES,
            _kCCOptionECBMode,
            self._key_bytes,
            len(self._key_bytes),
            None,
            data,
            len(data),
            out,
            len(out),
            ctypes.byref(out_len),
        )
        if status != 0:
            raise RuntimeError(f"CommonCrypto CCCrypt failed: status={status}")
        return out.raw[: out_len.value]

    def close(self) -> None:
        if sys.platform == "win32":
            if self._h_key and self._h_key.value:
                _bcrypt.BCryptDestroyKey(self._h_key)
                self._h_key = wt.HANDLE()
            if self._h_alg and self._h_alg.value:
                _bcrypt.BCryptCloseAlgorithmProvider(self._h_alg, 0)
                self._h_alg = wt.HANDLE()

    def __enter__(self) -> "AesEcbDecryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# ============================================================
# 图片格式检测与 XOR / V1 / V2 解密
# ============================================================

def detect_image_ext(data: bytes) -> Optional[str]:
    """根据魔数判断常见图片格式扩展名。"""
    if len(data) < 4:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if data[:4] == b"wxgf":
        return ".wxgf"
    if data[:2] == b"BM" and len(data) >= 14 and data[6:10] == b"\x00\x00\x00\x00":
        return ".bmp"
    return None


def _is_valid_first_block(block16: bytes) -> bool:
    """快速判断 16 字节解密首块是否为合法图片魔数。"""
    if block16[:3] == b"\xff\xd8\xff":
        return True
    if block16[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if block16[:6] in (b"GIF87a", b"GIF89a"):
        return True
    if block16[:4] == b"RIFF" and block16[8:12] == b"WEBP":
        return True
    if block16[:4] == b"wxgf":
        return True
    return False


def _unpad_pkcs7(data: bytes, expected_len: int) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        unpadded = data[:-pad]
        if expected_len <= 0 or len(unpadded) == expected_len:
            return unpadded
    if 0 < expected_len <= len(data):
        return data[:expected_len]
    return data


def _xor_bytes(data: bytes, xor_key: int) -> bytes:
    if xor_key == 0 or not data:
        return data
    tbl = bytes(i ^ xor_key for i in range(256))
    return data.translate(tbl)


def detect_xor_key_from_attach_dir(attach_dir: str, max_samples: int = 120) -> Optional[int]:
    """通过扫描本地缩略图 .dat 末尾的 JPEG 结束标记 (FF D9) 自动反推账号 XOR 密钥。"""
    if not os.path.isdir(attach_dir):
        return None
    counts: collections.Counter[int] = collections.Counter()
    checked = 0
    for dp, _dn, fn in os.walk(attach_dir):
        for f in fn:
            if not f.endswith("_t.dat"):
                continue
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fp:
                    hdr = fp.read(14)
                    if len(hdr) < 14 or hdr[:6] not in (V1_MAGIC, V2_MAGIC):
                        continue
                    xor_sz = struct.unpack("<I", hdr[10:14])[0]
                    if xor_sz < 2:
                        continue
                    fp.seek(-2, os.SEEK_END)
                    tail = fp.read(2)
                    if len(tail) == 2:
                        k1 = tail[0] ^ 0xFF
                        k2 = tail[1] ^ 0xD9
                        if k1 == k2:
                            counts[k1] += 1
                    checked += 1
                    if checked >= max_samples:
                        break
            except OSError:
                continue
        if checked >= max_samples:
            break
    if not counts:
        return None
    best_key, best_cnt = counts.most_common(1)[0]
    logger.info("自动反推图片 XOR 密钥: 0x%02x (命中 %d/%d 个样本)", best_key, best_cnt, checked)
    return best_key


def _collect_v2_samples(attach_dir: str, limit: int = 6) -> List[bytes]:
    """收集若干 V2 .dat 文件的前 16 字节 AES 密文块用于校验密钥。"""
    samples: List[bytes] = []
    if not os.path.isdir(attach_dir):
        return samples
    for dp, _dn, fn in os.walk(attach_dir):
        for f in fn:
            if not f.endswith("_t.dat"):
                continue
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fp:
                    data = fp.read(31)
                if len(data) == 31 and data[:6] == V2_MAGIC:
                    block = data[15:31]
                    if block not in samples:
                        samples.append(block)
                        if len(samples) >= limit:
                            return samples
            except OSError:
                continue
    return samples


def verify_v2_aes_key(key_bytes: bytes, samples: Sequence[bytes]) -> bool:
    """用多个 V2 .dat 首块密文校验 AES-128 密钥是否正确。"""
    if len(key_bytes) != 16 or not samples:
        return False
    try:
        with AesEcbDecryptor(key_bytes) as dec:
            hits = 0
            for blk in samples:
                plain = dec.decrypt(blk)
                if _is_valid_first_block(plain):
                    hits += 1
            return hits >= min(2, len(samples))
    except Exception:
        return False


# ============================================================
# 从运行中的 Weixin.exe 进程只读扫描 V2 图片 AES 密钥
# ============================================================

def _find_weixin_pids() -> List[Tuple[int, int]]:
    """通过 tasklist 查找所有运行中的 Weixin.exe 进程，按内存占用降序返回 [(pid, mem_kb)]。"""
    pids: List[Tuple[int, int]] = []
    for exe_name in ("Weixin.exe", "WeChat.exe"):
        try:
            r = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/FO", "CSV", "/NH"],
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out_text = (r.stdout or b"").decode("gbk", errors="replace")
            for line in out_text.splitlines():
                line = line.strip()
                if not line or exe_name.lower() not in line.lower():
                    continue
                parts = [p.strip().strip('"') for p in line.split('","')]
                if len(parts) >= 5 and parts[1].isdigit():
                    pid = int(parts[1])
                    mem_digits = re.sub(r"[^\d]", "", parts[4])
                    mem_kb = int(mem_digits) if mem_digits else 0
                    pids.append((pid, mem_kb))
        except Exception as e:
            logger.debug("查询进程 %s 失败: %s", exe_name, e)
    pids.sort(key=lambda x: x[1], reverse=True)
    return pids


def _scan_v2_aes_key_macos(samples: Sequence[bytes]) -> Optional[bytes]:
    """从运行中的 macOS WeChat 进程只读扫描并校验 V2 图片 AES-128 密钥（需 sudo 与重签名）。"""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logger.warning(
            "macOS 提取图片 V2 AES 密钥需要 root 权限（只需执行一次）。"
            "请打开微信点开任意一张大图后执行：sudo python3 src/run_archive.py --refresh-image-key"
        )
        return None

    pids: List[int] = []
    for proc_name in ("WeChat", "Weixin"):
        try:
            r = subprocess.run(["pgrep", "-x", proc_name], capture_output=True, text=True, timeout=5)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
        except Exception:
            continue
    if not pids:
        logger.warning("未找到运行中的 macOS WeChat 进程，无法提取图片 V2 AES 密钥")
        return None

    KERN_SUCCESS = 0
    VM_REGION_BASIC_INFO_64 = 9
    VM_REGION_BASIC_INFO_COUNT_64 = 9
    VM_PROT_READ = 0x01

    class _VmRegionBasicInfo64(ctypes.Structure):
        _fields_ = [
            ("protection", ctypes.c_int32),
            ("max_protection", ctypes.c_int32),
            ("inheritance", ctypes.c_uint32),
            ("shared", ctypes.c_uint32),
            ("reserved", ctypes.c_uint32),
            ("offset", ctypes.c_uint64),
            ("behavior", ctypes.c_int32),
            ("user_wired_count", ctypes.c_uint16),
        ]

    tested: set[bytes] = set()
    first_sample = samples[0]
    out_buf = ctypes.create_string_buffer(32)
    out_len = ctypes.c_size_t(0)

    def _quick_test_key(k16: bytes) -> bool:
        if k16 in tested:
            return False
        tested.add(k16)
        st = _libSystem.CCCrypt(
            _kCCDecrypt, _kCCAlgorithmAES, _kCCOptionECBMode,
            k16, 16, None, first_sample, 16, out_buf, 32, ctypes.byref(out_len),
        )
        if st != 0 or not _is_valid_first_block(out_buf.raw[:16]):
            return False
        for s_blk in samples[1:]:
            st2 = _libSystem.CCCrypt(
                _kCCDecrypt, _kCCAlgorithmAES, _kCCOptionECBMode,
                k16, 16, None, s_blk, 16, out_buf, 32, ctypes.byref(out_len),
            )
            if st2 != 0 or not _is_valid_first_block(out_buf.raw[:16]):
                return False
        return True

    for pid in pids:
        task = ctypes.c_uint32(0)
        kr = _libSystem.task_for_pid(_libSystem.mach_task_self(), ctypes.c_int(pid), ctypes.byref(task))
        if kr != KERN_SUCCESS:
            logger.warning(
                "task_for_pid 失败 (PID=%d, kr=%d)，请确认已对 WeChat.app 执行重签名并重启微信",
                pid, kr,
            )
            continue

        logger.info("正在扫描 macOS WeChat (PID=%d) 内存以提取图片 V2 AES 密钥...", pid)
        address = ctypes.c_uint64(0)
        size = ctypes.c_uint64(0)
        info = _VmRegionBasicInfo64()
        info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
        object_name = ctypes.c_uint32(0)

        while True:
            kr = _libSystem.mach_vm_region(
                ctypes.c_uint32(task.value),
                ctypes.byref(address),
                ctypes.byref(size),
                ctypes.c_int(VM_REGION_BASIC_INFO_64),
                ctypes.byref(info),
                ctypes.byref(info_count),
                ctypes.byref(object_name),
            )
            if kr != KERN_SUCCESS:
                break

            reg_addr = address.value
            reg_size = size.value
            next_addr = reg_addr + reg_size
            if next_addr <= reg_addr:
                break
            address.value = next_addr

            if not (info.protection & VM_PROT_READ) or reg_size == 0 or reg_size > 256 * 1024 * 1024:
                continue

            data_ptr = ctypes.c_uint64(0)
            data_size = ctypes.c_uint64(0)
            kr_r = _libSystem.mach_vm_read(
                ctypes.c_uint32(task.value),
                ctypes.c_uint64(reg_addr),
                ctypes.c_uint64(reg_size),
                ctypes.byref(data_ptr),
                ctypes.byref(data_size),
            )
            if kr_r != KERN_SUCCESS or data_size.value == 0:
                continue
            try:
                raw = ctypes.string_at(data_ptr.value, data_size.value)
            finally:
                _libSystem.mach_vm_deallocate(_libSystem.mach_task_self(), data_ptr, data_size)

            for m in MEM_HEX16_RE.finditer(raw):
                k16 = m.group(0)
                if _quick_test_key(k16):
                    logger.info("成功提取并校验图片 V2 AES 密钥 (macOS 16位hex ASCII，共测试 %d 个候选)", len(tested))
                    return k16
            for m in MEM_HEX32_RE.finditer(raw):
                cand32 = m.group(0)
                if _quick_test_key(cand32[:16]):
                    logger.info("成功提取并校验图片 V2 AES 密钥 (macOS 32位hex前16，共测试 %d 个候选)", len(tested))
                    return cand32[:16]
                try:
                    k_raw = bytes.fromhex(cand32.decode("ascii"))
                    if _quick_test_key(k_raw):
                        logger.info("成功提取并校验图片 V2 AES 密钥 (macOS 32位hex raw，共测试 %d 个候选)", len(tested))
                        return k_raw
                except ValueError:
                    pass
            for pat in (MEM_ALNUM16_RE, MEM_ALNUM32_RE):
                for m in pat.finditer(raw):
                    k_ascii = m.group(0)[:16]
                    if _quick_test_key(k_ascii):
                        logger.info("成功提取并校验图片 V2 AES 密钥 (macOS alnum ASCII，共测试 %d 个候选)", len(tested))
                        return k_ascii

    logger.warning("扫描了 %d 个候选密钥，但未在 macOS WeChat 内存中命中图片 V2 AES 密钥（请先点开任意一张大图后重试）", len(tested))
    return None


def scan_v2_aes_key_from_memory(attach_dir: str) -> Optional[bytes]:
    """从当前运行中的微信进程只读扫描并校验 V2 图片 AES-128 密钥（16 字节）。"""
    samples = _collect_v2_samples(attach_dir, limit=4)
    if not samples:
        logger.warning("未在 %s 找到 V2 .dat 样本文件，无法校验图片密钥", attach_dir)
        return None

    if sys.platform == "darwin":
        return _scan_v2_aes_key_macos(samples)
    if sys.platform != "win32":
        logger.warning("当前平台 %s 暂不支持自动扫描图片 V2 AES 密钥", sys.platform)
        return None

    pids = _find_weixin_pids()
    if not pids:
        logger.warning("未找到运行中的 Weixin.exe 进程，无法提取图片 AES 密钥")
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("PartitionId", wt.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.VirtualQueryEx.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wt.BOOL
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    READABLE_PROTECTS = {0x02, 0x04, 0x20, 0x40}  # PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
    CHUNK_SIZE = 8 * 1024 * 1024

    tested: set[bytes] = set()
    first_sample = samples[0]

    # 预创建 CNG algorithm provider 加速批量测试
    h_alg = wt.HANDLE()
    if _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0) != 0:
        return None
    mode = "ChainingModeECB\x00".encode("utf-16-le")
    _bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, len(mode), 0)
    out_buf = ctypes.create_string_buffer(16)
    out_len = wt.ULONG(0)

    def _quick_test_key(k16: bytes) -> bool:
        if k16 in tested:
            return False
        tested.add(k16)
        h_key = wt.HANDLE()
        if _bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0, k16, 16, 0) != 0:
            return False
        try:
            st = _bcrypt.BCryptDecrypt(
                h_key, first_sample, 16, None, None, 0, out_buf, 16, ctypes.byref(out_len), 0
            )
            if st != 0 or not _is_valid_first_block(out_buf.raw[:16]):
                return False
            # 首样本命中，用全部样本二次确认
            for s_blk in samples[1:]:
                st2 = _bcrypt.BCryptDecrypt(
                    h_key, s_blk, 16, None, None, 0, out_buf, 16, ctypes.byref(out_len), 0
                )
                if st2 != 0 or not _is_valid_first_block(out_buf.raw[:16]):
                    return False
            return True
        finally:
            _bcrypt.BCryptDestroyKey(h_key)

    try:
        for pid, _threads in pids:
            h_proc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not h_proc:
                continue
            logger.info("正在扫描 Weixin.exe (PID=%d) 内存以提取图片 AES 密钥...", pid)
            try:
                mbi = MEMORY_BASIC_INFORMATION()
                addr = 0x10000
                max_addr = 0x7FFFFFFFFFFF
                while addr < max_addr:
                    res = kernel32.VirtualQueryEx(
                        h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if res == 0:
                        break
                    region_size = mbi.RegionSize
                    next_addr = (mbi.BaseAddress or addr) + region_size
                    if next_addr <= addr:
                        break
                    addr = next_addr

                    if mbi.State != MEM_COMMIT or mbi.Type not in (MEM_PRIVATE, MEM_MAPPED):
                        continue
                    if (mbi.Protect & 0xFF) not in READABLE_PROTECTS or (mbi.Protect & 0x100):
                        continue
                    if region_size == 0 or region_size > 256 * 1024 * 1024:
                        continue

                    base_addr = mbi.BaseAddress or 0
                    offset = 0
                    while offset < region_size:
                        to_read = min(CHUNK_SIZE, region_size - offset)
                        buf = ctypes.create_string_buffer(to_read)
                        bytes_read = ctypes.c_size_t(0)
                        ok_read = kernel32.ReadProcessMemory(
                            h_proc,
                            ctypes.c_void_p(base_addr + offset),
                            buf,
                            to_read,
                            ctypes.byref(bytes_read),
                        )
                        offset += to_read
                        if not ok_read or bytes_read.value == 0:
                            continue
                        raw = buf.raw[: bytes_read.value]

                        # 1. 优先测 16 位 hex（微信 4.x V2 图片 AES key 最常见形式：16 字节 ASCII）
                        for m in MEM_HEX16_RE.finditer(raw):
                            k16 = m.group(0)
                            if _quick_test_key(k16):
                                logger.info("成功提取并校验图片 V2 AES 密钥 (16位hex ASCII，共测试 %d 个候选)", len(tested))
                                return k16

                        # 2. 测 32 位 hex（前 16 字节 ASCII 及 16 字节 raw bytes）
                        for m in MEM_HEX32_RE.finditer(raw):
                            cand32 = m.group(0)
                            k_ascii = cand32[:16]
                            if _quick_test_key(k_ascii):
                                logger.info("成功提取并校验图片 V2 AES 密钥 (32位hex前16 ASCII，共测试 %d 个候选)", len(tested))
                                return k_ascii
                            try:
                                k_raw = bytes.fromhex(cand32.decode("ascii"))
                                if _quick_test_key(k_raw):
                                    logger.info("成功提取并校验图片 V2 AES 密钥 (32位hex raw，共测试 %d 个候选)", len(tested))
                                    return k_raw
                            except ValueError:
                                pass

                        # 3. 测 16/32 位小写字母数字 ASCII
                        for pat in (MEM_ALNUM16_RE, MEM_ALNUM32_RE):
                            for m in pat.finditer(raw):
                                k_ascii = m.group(0)[:16]
                                if _quick_test_key(k_ascii):
                                    logger.info("成功提取并校验图片 V2 AES 密钥 (alnum ASCII，共测试 %d 个候选)", len(tested))
                                    return k_ascii
            finally:
                kernel32.CloseHandle(h_proc)
    finally:
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)

    logger.warning("扫描了 %d 个候选密钥，但未在 Weixin.exe 内存中命中图片 V2 AES 密钥（请先在微信中点开查看任意一张大图后再重试）", len(tested))
    return None


# ============================================================
# 密钥缓存读写 & 统一图片解密服务
# ============================================================

def load_or_refresh_image_keys(
    keys_file: str,
    attach_dir: str,
    force_refresh: bool = False,
) -> Tuple[Optional[bytes], Optional[int]]:
    """读取缓存的图片 V2 AES 密钥和 XOR 密钥；缺失或强制刷新时自动反推/扫描并持久化保存。"""
    raw_json: dict = {}
    if os.path.exists(keys_file):
        try:
            with open(keys_file, "r", encoding="utf-8") as f:
                raw_json = json.load(f)
        except Exception:
            raw_json = {}

    img_meta = raw_json.get("_image_keys") if isinstance(raw_json.get("_image_keys"), dict) else {}
    aes_key: Optional[bytes] = None
    xor_key: Optional[int] = None

    if not force_refresh:
        aes_hex = img_meta.get("aes_key_hex")
        if isinstance(aes_hex, str) and len(aes_hex) == 32:
            try:
                aes_key = bytes.fromhex(aes_hex)
            except ValueError:
                aes_key = None
        if isinstance(img_meta.get("xor_key"), int):
            xor_key = int(img_meta["xor_key"]) & 0xFF

    updated = False
    if xor_key is None:
        xor_key = detect_xor_key_from_attach_dir(attach_dir)
        if xor_key is not None:
            updated = True

    if aes_key is None:
        # 先验证本地是否有 V2 样本；如果没有 V2 文件则不需要扫内存
        v2_samples = _collect_v2_samples(attach_dir, limit=2)
        if v2_samples:
            aes_key = scan_v2_aes_key_from_memory(attach_dir)
            if aes_key is not None:
                updated = True

    if updated and (aes_key is not None or xor_key is not None):
        raw_json["_image_keys"] = {
            "aes_key_hex": aes_key.hex() if aes_key else img_meta.get("aes_key_hex", ""),
            "xor_key": xor_key if xor_key is not None else img_meta.get("xor_key", 0),
        }
        try:
            os.makedirs(os.path.dirname(os.path.abspath(keys_file)), exist_ok=True)
            with open(keys_file, "w", encoding="utf-8", newline="\n") as f:
                json.dump(raw_json, f, ensure_ascii=False, indent=2)
            logger.info("已将图片密钥持久化保存到 %s", keys_file)
        except Exception as e:
            logger.warning("保存图片密钥到 %s 失败: %s", keys_file, e)

    return aes_key, xor_key


class WeChatImageExporter:
    """本地微信 .dat 图片索引 + 批量解密导出器。"""

    def __init__(
        self,
        attach_dir: str,
        aes_key: Optional[bytes],
        xor_key: Optional[int],
    ) -> None:
        self.attach_dir = attach_dir
        self.aes_key = aes_key
        self.xor_key = xor_key if xor_key is not None else 0
        self._v2_dec: Optional[AesEcbDecryptor] = AesEcbDecryptor(aes_key) if aes_key else None
        self._v1_dec: Optional[AesEcbDecryptor] = AesEcbDecryptor(V1_AES_KEY)

        # (chat_md5, base_stem) -> [dat_paths]
        self._by_chat_stem: Dict[Tuple[str, str], List[str]] = {}
        # base_stem -> [dat_paths]
        self._by_stem: Dict[str, List[str]] = {}
        self._indexed = False

    def close(self) -> None:
        if self._v2_dec:
            self._v2_dec.close()
            self._v2_dec = None
        if self._v1_dec:
            self._v1_dec.close()
            self._v1_dec = None

    def __enter__(self) -> "WeChatImageExporter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def build_index(self) -> int:
        """扫描 msg/attach 目录，建立快速内存索引。"""
        if self._indexed:
            return len(self._by_stem)
        total_files = 0
        if os.path.isdir(self.attach_dir):
            for dp, _dn, fn in os.walk(self.attach_dir):
                rel_dp = os.path.relpath(dp, self.attach_dir)
                chat_md5 = rel_dp.split(os.sep)[0].lower() if rel_dp and rel_dp != "." else ""
                for f in fn:
                    if not f.lower().endswith(".dat"):
                        continue
                    total_files += 1
                    stem = f[:-4].lower()
                    base_stem = stem
                    for suf in ("_t", "_h", "_b", "_c"):
                        if base_stem.endswith(suf):
                            base_stem = base_stem[: -len(suf)]
                            break
                    full = os.path.join(dp, f)
                    self._by_chat_stem.setdefault((chat_md5, base_stem), []).append(full)
                    self._by_stem.setdefault(base_stem, []).append(full)
        self._indexed = True
        logger.info("图片附件索引完成: %d 个 .dat 文件, %d 组唯一图片", total_files, len(self._by_stem))
        return total_files

    @staticmethod
    def extract_stems_from_message(
        packed_info,
        xml_md5: str = "",
        local_id: int = 0,
        create_time: int = 0,
    ) -> List[str]:
        """从单条图片消息的 packed_info_data / XML md5 / local_id 提取候选文件基底名。"""
        stems: List[str] = []
        if isinstance(packed_info, memoryview):
            packed_info = packed_info.tobytes()
        if isinstance(packed_info, (bytes, bytearray)):
            for m in HEX32_RE.findall(bytes(packed_info)):
                s = m.decode("ascii").lower()
                if s not in stems:
                    stems.append(s)
        if xml_md5:
            m_low = xml_md5.lower()
            if m_low not in stems:
                stems.append(m_low)
        if local_id and create_time:
            lid_s = f"{local_id}_{create_time}"
            if lid_s not in stems:
                stems.append(lid_s)
        return stems

    def find_candidates(self, chat_md5: str, stems: Sequence[str]) -> List[str]:
        """按优先级返回候选 .dat 文件路径（优先高清/原图，其次缩略图 _t.dat）。"""
        if not self._indexed:
            self.build_index()
        chat_low = chat_md5.lower()
        found: List[str] = []
        for st in stems:
            paths = self._by_chat_stem.get((chat_low, st)) or self._by_stem.get(st)
            if paths:
                for p in paths:
                    if p not in found:
                        found.append(p)
                break

        def _priority(path: str) -> Tuple[int, int]:
            name = os.path.basename(path).lower()
            if name.endswith("_h.dat"):
                return (0, 0)
            if not name.endswith(("_t.dat", "_b.dat", "_c.dat")):
                return (1, 0)
            if name.endswith("_t.dat"):
                return (2, 0)
            return (3, 0)

        found.sort(key=_priority)
        return found

    def decrypt_dat_bytes(self, raw: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """解密单个 .dat 字节流，返回 (明文图片字节, 扩展名)。"""
        if len(raw) < 16:
            return None, None

        magic = raw[:6]
        if magic in (V1_MAGIC, V2_MAGIC):
            dec = self._v2_dec if magic == V2_MAGIC else self._v1_dec
            if dec is None:
                return None, None
            aes_size, xor_size = struct.unpack("<II", raw[6:14])
            # PKCS7 填充后的密文长度：aes_size + (16 - aes_size % 16)
            aes_enc_len = aes_size + (16 - (aes_size % 16)) if aes_size > 0 else 0
            header_len = 15
            if header_len + aes_enc_len > len(raw):
                return None, None

            parts: List[bytes] = []
            if aes_enc_len > 0:
                enc_head = raw[header_len : header_len + aes_enc_len]
                dec_head = dec.decrypt(enc_head)
                parts.append(_unpad_pkcs7(dec_head, aes_size))

            mid_start = header_len + aes_enc_len
            xor_start = max(mid_start, len(raw) - xor_size) if xor_size > 0 else len(raw)
            if xor_start > mid_start:
                parts.append(raw[mid_start:xor_start])
            if xor_start < len(raw):
                parts.append(_xor_bytes(raw[xor_start:], self.xor_key))

            plain = b"".join(parts)
            ext = detect_image_ext(plain)
            return (plain, ext) if ext else (None, None)

        # 旧版纯单字节 XOR .dat 兼容
        for sig, ext in (
            (b"\xff\xd8\xff", ".jpg"),
            (b"\x89PNG", ".png"),
            (b"GIF8", ".gif"),
            (b"RIFF", ".webp"),
        ):
            k = raw[0] ^ sig[0]
            if all((raw[i] ^ k) == sig[i] for i in range(len(sig))):
                plain = _xor_bytes(raw, k)
                if detect_image_ext(plain):
                    return plain, ext
        return None, None

    def export_image(
        self,
        chat_md5: str,
        stems: Sequence[str],
        out_dir: str,
        file_stem: str,
    ) -> Optional[str]:
        """定位并解密单张图片到 out_dir，返回最终生成的文件名（不含目录），失败返回 None。

        如果目标图片已存在则直接复用，跳过重复解密。
        若原图为微信专有 .wxgf（Markdown 无法直接渲染），自动回退优先导出标准格式的缩略图。
        """
        # 增量复用：若已导出过则直接返回
        for ext in (".jpg", ".png", ".gif", ".webp", ".bmp"):
            existing = os.path.join(out_dir, f"{file_stem}{ext}")
            if os.path.exists(existing) and os.path.getsize(existing) > 0:
                return f"{file_stem}{ext}"

        candidates = self.find_candidates(chat_md5, stems)
        if not candidates:
            return None

        fallback_wxgf: Optional[bytes] = None
        for dat_path in candidates:
            try:
                with open(dat_path, "rb") as fp:
                    raw = fp.read()
            except OSError:
                continue
            plain, ext = self.decrypt_dat_bytes(raw)
            if not plain or not ext:
                continue
            if ext == ".wxgf":
                # wxgf 无法在通用 Markdown 中直接预览，先记录并继续尝试缩略图 _t.dat
                if fallback_wxgf is None:
                    fallback_wxgf = plain
                continue
            os.makedirs(out_dir, exist_ok=True)
            out_name = f"{file_stem}{ext}"
            out_path = os.path.join(out_dir, out_name)
            with open(out_path, "wb") as fp:
                fp.write(plain)
            return out_name

        return None
