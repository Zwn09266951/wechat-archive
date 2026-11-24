r"""微信个人聊天记录自动归档主入口。

用法示例：
  py D:\wechat-archive\src\run_archive.py                  # 增量归档（推荐用于定时任务）
  py D:\wechat-archive\src\run_archive.py --full           # 全量重建所有日期的归档
  py D:\wechat-archive\src\run_archive.py --days 7         # 重建最近 7 天的归档
  py D:\wechat-archive\src\run_archive.py --since 2026-11-01
  py D:\wechat-archive\src\run_archive.py --refresh-keys   # 强制重新从微信进程刷新密钥
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from decryptor import DecryptedWorkspace, auto_detect_db_storage_dir
from exporter import run_incremental_export
from image_decryptor import WeChatImageExporter, load_or_refresh_image_keys


def _resolve_path(raw_path: str, base_dir: Path) -> str:
    """支持 ~ 展开与相对于配置文件目录的相对路径解析。"""
    expanded = os.path.expanduser(raw_path)
    p = Path(expanded)
    if not p.is_absolute():
        p = (base_dir / p).resolve()
    return str(p)


def _find_attach_dir(cfg: dict, db_storage_dir: str, base_dir: Path) -> str:
    if cfg.get("attach_dir"):
        return _resolve_path(str(cfg["attach_dir"]), base_dir)
    account_root = os.path.dirname(os.path.abspath(db_storage_dir))
    candidates = [
        os.path.join(account_root, "msg", "attach"),
        os.path.join(account_root, "Message", "MessageTemp"),
    ]
    for cand in candidates:
        if os.path.isdir(cand):
            return cand
    return candidates[0]


def setup_logging(logs_dir: str, verbose: bool = False) -> None:
    os.makedirs(logs_dir, exist_ok=True)
    log_file = os.path.join(logs_dir, "archive.log")
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="个人微信 4.x 聊天记录只读增量归档工具（Windows / macOS）")
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "config.json"),
        help="配置文件路径（默认项目根目录下的 config.json）",
    )
    parser.add_argument("--full", action="store_true", help="全量重建全部归档")
    parser.add_argument("--days", type=int, help="仅重导最近 N 天（从今天往前推 N 天）")
    parser.add_argument("--since", help="仅重导指定日期（含）之后的记录，格式 YYYY-MM-DD")
    parser.add_argument("--refresh-keys", action="store_true", help="强制重新提取数据库与图片密钥")
    parser.add_argument("--refresh-image-key", action="store_true", help="强制重新提取图片 V2 AES 密钥")
    parser.add_argument("--no-images", action="store_true", help="本次归档跳过图片解密导出，仅保留 [图片] 占位符")
    parser.add_argument("--verbose", "-v", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    config_path = Path(os.path.expanduser(args.config)).resolve()
    base_dir = config_path.parent
    cfg = load_config(str(config_path))

    logs_dir = _resolve_path(cfg.get("logs_dir", "./logs"), base_dir)
    keys_file = _resolve_path(cfg.get("keys_file", "./secrets/all_keys.json"), base_dir)
    state_file = _resolve_path(cfg.get("state_file", "./state/archive_state.json"), base_dir)
    notes_dir = _resolve_path(cfg.get("notes_dir", "./notes"), base_dir)
    wcdb_tool_dir = _resolve_path(cfg.get("wcdb_tool_dir", "./vendor/wcdb-key-tool"), base_dir)

    setup_logging(logs_dir, verbose=args.verbose)
    logger = logging.getLogger("wechat_archive")

    raw_db_dir = str(cfg.get("db_storage_dir") or "").strip()
    if not raw_db_dir or raw_db_dir.lower() == "auto":
        detected = auto_detect_db_storage_dir(wcdb_tool_dir)
        if not detected:
            logger.error("未能自动检测微信 db_storage 目录，请在 config.json 中手动配置 db_storage_dir")
            return 1
        db_storage_dir = detected
        logger.info("已自动检测到微信 db_storage 目录: %s", db_storage_dir)
    else:
        db_storage_dir = _resolve_path(raw_db_dir, base_dir)

    since_ts = None
    if args.since:
        since_ts = int(datetime.datetime.strptime(args.since, "%Y-%m-%d").timestamp())
    elif args.days is not None and args.days > 0:
        start_day = datetime.date.today() - datetime.timedelta(days=args.days - 1)
        since_ts = int(datetime.datetime.combine(start_day, datetime.time.min).timestamp())

    run_hint = "py src\\run_archive.py" if sys.platform == "win32" else "sudo python3 src/run_archive.py"

    logger.info("========== 开始执行微信聊天记录归档 (%s) ==========", sys.platform)
    try:
        export_images = bool(cfg.get("export_images", True)) and not args.no_images
        attach_dir = _find_attach_dir(cfg, db_storage_dir, base_dir)
        image_exporter = None
        if export_images and os.path.isdir(attach_dir):
            aes_key, xor_key = load_or_refresh_image_keys(
                keys_file=keys_file,
                attach_dir=attach_dir,
                force_refresh=(args.refresh_keys or args.refresh_image_key),
            )
            if aes_key is None:
                logger.warning(
                    "尚未获取到图片 V2 AES 密钥（V2 图片将暂时显示为 [图片]）。"
                    "请打开并登录微信客户端、在聊天中点开任意一张大图后，执行：%s --refresh-image-key --full",
                    run_hint,
                )
            image_exporter = WeChatImageExporter(
                attach_dir=attach_dir,
                aes_key=aes_key,
                xor_key=xor_key,
            )
        elif export_images:
            logger.warning("未找到微信图片附件目录: %s，本次将跳过图片导出", attach_dir)

        try:
            with DecryptedWorkspace(
                db_storage_dir=db_storage_dir,
                keys_file=keys_file,
                wcdb_tool_dir=wcdb_tool_dir,
                include_biz=bool(cfg.get("include_biz_messages", False)),
                force_refresh_keys=args.refresh_keys,
            ) as decrypted_dbs:
                summary = run_incremental_export(
                    decrypted_dbs=decrypted_dbs,
                    notes_dir=notes_dir,
                    state_file=state_file,
                    self_wxid=cfg.get("self_wxid", ""),
                    include_system_chats=bool(cfg.get("include_system_chats", False)),
                    full_rebuild=args.full,
                    since_ts=since_ts,
                    split_threshold_messages=int(cfg.get("split_threshold_messages", 3000)),
                    chunk_max_messages=int(cfg.get("chunk_max_messages", 2000)),
                    image_exporter=image_exporter,
                )
        finally:
            if image_exporter is not None:
                image_exporter.close()

        logger.info(
            "归档完成: 扫描会话 %d 个, 新增/处理消息 %d 条, 更新会话 Markdown %d 个, 关联/导出图片 %d 张",
            summary.total_chats_scanned,
            summary.new_messages,
            summary.updated_files,
            summary.exported_images,
        )
        return 0
    except Exception as e:
        logger.exception("归档执行失败: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
