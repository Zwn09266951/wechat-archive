"""微信聊天记录增量导出与按会话 Markdown 归档引擎。

输出目录结构（自动分卷，避免超大文件无法预览）：
notes/
  index.md                        # 全部会话总览索引（按最近活跃时间倒序）
  好友_<名称>.md                   # 普通会话：单文件（内部按 ## YYYY-MM-DD 分节）
  群聊_<名称>.md                   # 普通群聊：单文件
  群聊_<超大群>/                   # 超过阈值的超大历史会话：自动建子目录按月/日期分卷
    index.md                      # 该会话分卷导航索引（最新在前）
    2026-11.md                    # 单月消息量适中 -> 按月单文件
    2025-07_01~03.md              # 单月消息量极大 -> 按完整日期自动分卷（每卷约 100~200KB，秒开预览）
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

from parser import (
    ContactInfo,
    extract_image_md5,
    format_message,
    load_contacts,
    should_archive_chat,
)

if TYPE_CHECKING:
    from image_decryptor import WeChatImageExporter

logger = logging.getLogger("wechat_archive.exporter")

_INVALID_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


@dataclass
class ArchiveSummary:
    new_messages: int
    updated_files: int
    updated_chats: List[str]
    total_chats_scanned: int
    exported_images: int = 0


def sanitize_filename(name: str, fallback_id: str) -> str:
    cleaned = _INVALID_FS_CHARS.sub("_", name).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        cleaned = fallback_id
    if len(cleaned) > 50:
        cleaned = cleaned[:50].rstrip(" .")
    return cleaned


def build_chat_stem(
    username: str,
    contact: ContactInfo,
    used_stems_map: Dict[str, str],
) -> str:
    """为会话生成稳定、无冲突的基底名称（不含 .md 后缀）。"""
    prefix = "群聊" if contact.is_group else "好友"
    base = f"{prefix}_{sanitize_filename(contact.display_name, username)}"
    existing_owner = used_stems_map.get(base.lower())
    if existing_owner is None or existing_owner == username:
        used_stems_map[base.lower()] = username
        return base
    short_hash = hashlib.md5(username.encode("utf-8")).hexdigest()[:6]
    candidate = f"{base}_{short_hash}"
    used_stems_map[candidate.lower()] = username
    return candidate


def _atomic_write(path: str, content: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".md", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _load_state(state_file: str) -> dict:
    if not os.path.exists(state_file):
        return {"layout": "by_chat_v2", "watermarks": {}, "chat_stats": {}}
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("layout") != "by_chat_v2":
            return {"layout": "by_chat_v2", "watermarks": {}, "chat_stats": {}}
        data.setdefault("watermarks", {})
        data.setdefault("chat_stats", {})
        return data
    except Exception as e:
        logger.warning("读取状态文件失败，将重新初始化: %s", e)
        return {"layout": "by_chat_v2", "watermarks": {}, "chat_stats": {}}


def _save_state(state_file: str, state: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(state_file)), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp_state_", suffix=".json", dir=os.path.dirname(os.path.abspath(state_file))
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, state_file)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _resolve_sender_name(
    sender_username: Optional[str],
    prefix_sender: Optional[str],
    chat_username: str,
    is_group: bool,
    self_wxid: str,
    contacts: Dict[str, ContactInfo],
) -> str:
    uid = prefix_sender or sender_username
    if not uid:
        return "对方" if not is_group else "群成员"
    if self_wxid and uid == self_wxid:
        return "我"
    if not is_group and uid == chat_username:
        info = contacts.get(chat_username)
        return info.display_name if info else chat_username
    info = contacts.get(uid)
    return info.display_name if info else uid


def _render_messages_markdown(
    contact: ContactInfo,
    messages_by_date: Dict[str, List[Tuple[int, str, str]]],
    back_link: str,
    back_label: str,
    subtitle: str = "",
) -> str:
    """渲染单文件或单个分卷的 Markdown（内部按 ## YYYY-MM-DD 日期分节）。"""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chat_type = "group" if contact.is_group else "direct"
    type_label = "群聊" if contact.is_group else "好友"
    sorted_dates = sorted(messages_by_date.keys())
    total_msgs = sum(len(messages_by_date[d]) for d in sorted_dates)
    first_date = sorted_dates[0]
    last_date = sorted_dates[-1]
    date_span = first_date if first_date == last_date else f"{first_date} ~ {last_date}"
    title_suffix = f"（{subtitle}）" if subtitle else ""

    lines: List[str] = [
        "---",
        f"chat_name: {json.dumps(contact.display_name, ensure_ascii=False)}",
        f"chat_type: {chat_type}",
        f"chat_id: {contact.username}",
        f"message_count: {total_msgs}",
        f"active_days: {len(sorted_dates)}",
        f"first_date: {first_date}",
        f"last_date: {last_date}",
        f"updated_at: {now_str}",
        "---",
        "",
        f"# {type_label}：{contact.display_name}{title_suffix}",
        "",
        f"> 共 {total_msgs} 条消息 · 活跃 {len(sorted_dates)} 天（{date_span}） · [{back_label}]({back_link})",
        "",
    ]

    for date_str in sorted_dates:
        day_msgs = messages_by_date[date_str]
        lines.append(f"## {date_str}")
        lines.append("")
        for ts, sender, body in day_msgs:
            t_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            if "\n" in body:
                body_lines = body.splitlines()
                first = body_lines[0]
                rest = "\n".join(f"  {ln}" if ln.strip() else "" for ln in body_lines[1:])
                lines.append(f"- **{t_str}** **{sender}**: {first}\n{rest}")
            else:
                lines.append(f"- **{t_str}** **{sender}**: {body}")
        lines.append("")

    return "\n".join(lines)


def _split_month_into_chunks(
    month_str: str,
    month_dates: List[str],
    messages_by_date: Dict[str, List[Tuple[int, str, str]]],
    chunk_max_messages: int,
) -> List[Tuple[str, str, Dict[str, List[Tuple[int, str, str]]]]]:
    """将一个月的消息按完整日期切分为若干预览友好的小文件。

    返回列表元素：(filename, label, {date_str: msgs})
    """
    total_month_msgs = sum(len(messages_by_date[d]) for d in month_dates)
    if total_month_msgs <= chunk_max_messages:
        sub = {d: messages_by_date[d] for d in month_dates}
        return [(f"{month_str}.md", month_str, sub)]

    chunks: List[List[str]] = []
    cur_days: List[str] = []
    cur_count = 0
    for d in month_dates:
        cnt = len(messages_by_date[d])
        if cur_days and cur_count + cnt > chunk_max_messages:
            chunks.append(cur_days)
            cur_days = [d]
            cur_count = cnt
        else:
            cur_days.append(d)
            cur_count += cnt
    if cur_days:
        chunks.append(cur_days)

    result: List[Tuple[str, str, Dict[str, List[Tuple[int, str, str]]]]] = []
    for days in chunks:
        d1 = days[0][-2:]
        d2 = days[-1][-2:]
        if d1 == d2:
            fname = f"{month_str}-{d1}.md"
            label = f"{month_str}-{d1}"
        else:
            fname = f"{month_str}_{d1}~{d2}.md"
            label = f"{month_str}-{d1} ~ {month_str}-{d2}"
        sub = {d: messages_by_date[d] for d in days}
        result.append((fname, label, sub))
    return result


def _render_split_chat_index(contact: ContactInfo, chunks_meta: List[dict]) -> str:
    """渲染超大历史会话的分卷目录索引 notes/<会话名>/index.md（最新分卷在前）。"""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    type_label = "群聊" if contact.is_group else "好友"
    sorted_chunks = sorted(chunks_meta, key=lambda x: x["last_date"], reverse=True)
    total_msgs = sum(x["message_count"] for x in sorted_chunks)
    total_days = sum(x["active_days"] for x in sorted_chunks)

    lines: List[str] = [
        "---",
        f"chat_name: {json.dumps(contact.display_name, ensure_ascii=False)}",
        f"chat_type: {'group' if contact.is_group else 'direct'}",
        f"chat_id: {contact.username}",
        f"chunk_count: {len(sorted_chunks)}",
        f"message_count: {total_msgs}",
        f"updated_at: {now_str}",
        "---",
        "",
        f"# {type_label}：{contact.display_name}（分卷目录）",
        "",
        f"- 累计消息：**{total_msgs}** 条 · 活跃 **{total_days}** 天 · 已自动拆分为 **{len(sorted_chunks)}** 个轻量化分卷",
        f"- [返回全部会话总览](../index.md)",
        "",
        "| 日期范围 | 消息数 | 活跃天数 | 分卷文件 |",
        "| --- | ---: | ---: | --- |",
    ]

    for c in sorted_chunks:
        link = f"[{c['filename']}](./{quote(c['filename'])})"
        lines.append(
            f"| {c['label']} | {c['message_count']} | {c['active_days']} | {link} |"
        )

    lines.append("")
    return "\n".join(lines)


def _render_chat_index(chat_stats: Dict[str, dict]) -> str:
    """渲染全部会话总览索引 notes/index.md（按最近活跃时间倒序）。"""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    items = list(chat_stats.values())
    items.sort(key=lambda x: (-x["last_ts"], -x["message_count"], x["display_name"]))

    total_msgs = sum(x["message_count"] for x in items)
    group_cnt = sum(1 for x in items if x["is_group"])
    direct_cnt = len(items) - group_cnt

    lines: List[str] = [
        "---",
        "layout: by_chat_v2",
        f"chat_count: {len(items)}",
        f"message_count: {total_msgs}",
        f"updated_at: {now_str}",
        "---",
        "",
        "# 微信聊天归档总览（按会话）",
        "",
        f"- 归档会话：**{len(items)}** 个（好友 {direct_cnt} / 群聊 {group_cnt}）",
        f"- 累计消息：**{total_msgs}** 条",
        f"- 最近更新：{now_str}",
        "",
        "## 会话清单",
        "",
        "| 类型 | 会话名称 | 消息数 | 活跃天数 | 最近活跃时间 | 归档入口 |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]

    for item in items:
        t_label = "群聊" if item["is_group"] else "好友"
        safe_title = item["display_name"].replace("|", "\\|")
        last_t = datetime.datetime.fromtimestamp(item["last_ts"]).strftime("%Y-%m-%d %H:%M")
        entry_rel = item["entry_rel"]
        entry_label = item.get("entry_label") or entry_rel
        # 对路径每段分别 URL 编码，保留斜杠
        encoded_rel = "/".join(quote(part) for part in entry_rel.split("/"))
        link = f"[{entry_label}](./{encoded_rel})"
        lines.append(
            f"| {t_label} | {safe_title} | {item['message_count']} | {item['active_days']} | {last_t} | {link} |"
        )

    lines.append("")
    return "\n".join(lines)


def _encode_rel_url(rel_path: str) -> str:
    return "/".join(quote(part) for part in rel_path.replace("\\", "/").split("/"))


def run_incremental_export(
    decrypted_dbs: Dict[str, str],
    notes_dir: str,
    state_file: str,
    self_wxid: str = "",
    include_system_chats: bool = False,
    full_rebuild: bool = False,
    since_ts: Optional[int] = None,
    split_threshold_messages: int = 3000,
    chunk_max_messages: int = 2000,
    image_exporter: Optional["WeChatImageExporter"] = None,
) -> ArchiveSummary:
    """执行增量（或全量/指定起始时间）按会话归档导出，超大群自动按月/日分卷。"""
    contacts = load_contacts(decrypted_dbs.get("contact/contact.db"))
    state = (
        {"layout": "by_chat_v2", "watermarks": {}, "chat_stats": {}}
        if full_rebuild
        else _load_state(state_file)
    )
    watermarks: Dict[str, dict] = state["watermarks"]
    chat_stats: Dict[str, dict] = state["chat_stats"]

    used_stems_map: Dict[str, str] = {}
    for uname, info in chat_stats.items():
        stem = info.get("stem")
        if stem:
            used_stems_map[stem.lower()] = uname

    # 1. 扫描所有消息分库，找出新增消息以及受影响的会话
    msg_db_items = [
        (rel, path)
        for rel, path in sorted(decrypted_dbs.items())
        if rel.startswith("message/message_") or rel.startswith("message/biz_message_")
    ]

    dirty_chats: Set[str] = set()
    chat_sources: Dict[str, List[Tuple[str, str]]] = {}
    new_msg_total = 0
    total_chats_scanned = 0

    for db_rel, db_path in msg_db_items:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            name2id = dict(conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall())
            md5_to_user = {
                hashlib.md5(u.encode("utf-8")).hexdigest(): u
                for u in name2id.values()
                if u
            }
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                ).fetchall()
            ]
            for tbl in tables:
                chat_user = md5_to_user.get(tbl[4:])
                if not chat_user or not should_archive_chat(chat_user, include_system_chats):
                    continue
                total_chats_scanned += 1
                chat_sources.setdefault(chat_user, []).append((db_path, tbl))

                wm_key = f"{db_rel}::{tbl}"
                wm = watermarks.get(wm_key, {})
                last_seq = int(wm.get("last_sort_seq", 0))
                last_ct = int(wm.get("last_create_time", 0))
                last_id = int(wm.get("last_local_id", 0))

                if full_rebuild:
                    query = f"SELECT create_time, sort_seq, local_id FROM [{tbl}] WHERE create_time > 0"
                    params: tuple = ()
                elif since_ts is not None:
                    query = (
                        f"SELECT create_time, sort_seq, local_id FROM [{tbl}] "
                        f"WHERE create_time >= ?"
                    )
                    params = (since_ts,)
                else:
                    query = (
                        f"SELECT create_time, sort_seq, local_id FROM [{tbl}] "
                        f"WHERE create_time > 0 AND ("
                        f"  sort_seq > ? OR (sort_seq = ? AND (create_time > ? OR (create_time = ? AND local_id > ?)))"
                        f")"
                    )
                    params = (last_seq, last_seq, last_ct, last_ct, last_id)

                rows = conn.execute(query, params).fetchall()
                if not rows:
                    continue

                new_msg_total += len(rows)
                dirty_chats.add(chat_user)
                max_seq, max_ct, max_id = last_seq, last_ct, last_id
                for ct, seq, lid in rows:
                    s_val = int(seq or 0)
                    c_val = int(ct or 0)
                    l_val = int(lid or 0)
                    if (s_val, c_val, l_val) > (max_seq, max_ct, max_id):
                        max_seq, max_ct, max_id = s_val, c_val, l_val

                watermarks[wm_key] = {
                    "last_sort_seq": max_seq,
                    "last_create_time": max_ct,
                    "last_local_id": max_id,
                }
        finally:
            conn.close()

    if not dirty_chats:
        _save_state(state_file, state)
        return ArchiveSummary(
            new_messages=0,
            updated_files=0,
            updated_chats=[],
            total_chats_scanned=total_chats_scanned,
        )

    # 2. 针对每个有新增消息的会话导出 Markdown（超阈值自动分卷）
    conns: Dict[str, sqlite3.Connection] = {}
    name2ids: Dict[str, Dict[int, str]] = {}
    updated_files = 0
    updated_chat_names: List[str] = []
    exported_images = 0

    try:
        for chat_user in sorted(dirty_chats):
            contact = contacts.get(
                chat_user,
                ContactInfo(
                    username=chat_user,
                    display_name=chat_user,
                    is_group=chat_user.endswith("@chatroom"),
                ),
            )
            stem = build_chat_stem(chat_user, contact, used_stems_map)
            chat_md5 = hashlib.md5(chat_user.encode("utf-8")).hexdigest()

            # (ct, seq, lid, sender_name, formatted, img_asset_rel_or_None)
            records: List[Tuple[int, int, int, str, str, Optional[str]]] = []
            for db_path, tbl in chat_sources.get(chat_user, []):
                if db_path not in conns:
                    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    conns[db_path] = c
                    name2ids[db_path] = dict(c.execute("SELECT rowid, user_name FROM Name2Id").fetchall())

                c = conns[db_path]
                n2i = name2ids[db_path]
                if since_ts is not None:
                    rows = c.execute(
                        f"""
                        SELECT create_time, sort_seq, local_id, local_type,
                               real_sender_id, message_content, WCDB_CT_message_content,
                               packed_info_data
                        FROM [{tbl}]
                        WHERE create_time >= ?
                        ORDER BY create_time ASC, sort_seq ASC, local_id ASC
                        """,
                        (since_ts,),
                    ).fetchall()
                else:
                    rows = c.execute(
                        f"""
                        SELECT create_time, sort_seq, local_id, local_type,
                               real_sender_id, message_content, WCDB_CT_message_content,
                               packed_info_data
                        FROM [{tbl}]
                        WHERE create_time > 0
                        ORDER BY create_time ASC, sort_seq ASC, local_id ASC
                        """
                    ).fetchall()

                for ct, seq, lid, ltype, rsid, content, ct_flag, packed_info in rows:
                    ltype_int = int(ltype or 0)
                    base_type = ltype_int & 0xFFFFFFFF
                    prefix_sender, formatted = format_message(
                        local_type=ltype_int,
                        raw_content=content,
                        ct_flag=ct_flag,
                        is_group=contact.is_group,
                    )
                    if not formatted:
                        continue

                    img_asset_rel: Optional[str] = None
                    if base_type == 3 and image_exporter is not None:
                        xml_md5 = extract_image_md5(content, ct_flag, contact.is_group)
                        stems = image_exporter.extract_stems_from_message(
                            packed_info=packed_info,
                            xml_md5=xml_md5,
                            local_id=int(lid or 0),
                            create_time=int(ct or 0),
                        )
                        if stems:
                            month_str = datetime.datetime.fromtimestamp(int(ct)).strftime("%Y-%m")
                            img_out_dir = os.path.join(notes_dir, "assets", stem, month_str)
                            out_name = image_exporter.export_image(
                                chat_md5=chat_md5,
                                stems=stems,
                                out_dir=img_out_dir,
                                file_stem=stems[0],
                            )
                            if out_name:
                                img_asset_rel = f"assets/{stem}/{month_str}/{out_name}"
                                exported_images += 1

                    sender_uid = n2i.get(int(rsid)) if rsid is not None else None
                    sender_name = _resolve_sender_name(
                        sender_username=sender_uid,
                        prefix_sender=prefix_sender,
                        chat_username=chat_user,
                        is_group=contact.is_group,
                        self_wxid=self_wxid,
                        contacts=contacts,
                    )
                    records.append(
                        (int(ct), int(seq or 0), int(lid or 0), sender_name, formatted, img_asset_rel)
                    )

            if not records:
                continue

            records.sort(key=lambda x: (x[0], x[1], x[2]))
            is_split = len(records) > split_threshold_messages
            asset_prefix = "../" if is_split else "./"

            messages_by_date: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
            for ct, _seq, _lid, sender_name, formatted, img_asset_rel in records:
                d_str = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d")
                if img_asset_rel:
                    body_text = f"![图片]({asset_prefix}{_encode_rel_url(img_asset_rel)})"
                else:
                    body_text = formatted
                messages_by_date[d_str].append((ct, sender_name, body_text))

            single_md_path = os.path.join(notes_dir, f"{stem}.md")
            split_dir_path = os.path.join(notes_dir, stem)

            if not is_split:
                # 普通会话：单文件
                md_text = _render_messages_markdown(
                    contact=contact,
                    messages_by_date=messages_by_date,
                    back_link="./index.md",
                    back_label="返回会话总览",
                )
                _atomic_write(single_md_path, md_text)
                updated_files += 1
                entry_rel = f"{stem}.md"
                entry_label = f"{stem}.md"
            else:
                # 超大会话：自动建子目录并按月/日分卷
                if os.path.exists(single_md_path):
                    os.remove(single_md_path)
                os.makedirs(split_dir_path, exist_ok=True)

                dates_by_month: Dict[str, List[str]] = defaultdict(list)
                for d_str in sorted(messages_by_date.keys()):
                    dates_by_month[d_str[:7]].append(d_str)

                chunks_meta: List[dict] = []
                written_chunk_files: Set[str] = set()

                for month_str in sorted(dates_by_month.keys()):
                    month_chunks = _split_month_into_chunks(
                        month_str=month_str,
                        month_dates=dates_by_month[month_str],
                        messages_by_date=messages_by_date,
                        chunk_max_messages=chunk_max_messages,
                    )
                    for fname, label, sub_map in month_chunks:
                        chunk_path = os.path.join(split_dir_path, fname)
                        md_text = _render_messages_markdown(
                            contact=contact,
                            messages_by_date=sub_map,
                            back_link="./index.md",
                            back_label="返回分卷目录",
                            subtitle=label,
                        )
                        _atomic_write(chunk_path, md_text)
                        written_chunk_files.add(fname)
                        updated_files += 1
                        sub_dates = sorted(sub_map.keys())
                        chunks_meta.append(
                            {
                                "filename": fname,
                                "label": label,
                                "message_count": sum(len(v) for v in sub_map.values()),
                                "active_days": len(sub_dates),
                                "first_date": sub_dates[0],
                                "last_date": sub_dates[-1],
                            }
                        )

                # 清理该分卷目录下已过时的旧分卷文件
                for existing in os.listdir(split_dir_path):
                    if existing.endswith(".md") and existing != "index.md" and existing not in written_chunk_files:
                        os.remove(os.path.join(split_dir_path, existing))

                sub_index = _render_split_chat_index(contact, chunks_meta)
                _atomic_write(os.path.join(split_dir_path, "index.md"), sub_index)
                updated_files += 1

                entry_rel = f"{stem}/index.md"
                entry_label = f"{stem}/ (共 {len(chunks_meta)} 卷)"

            updated_chat_names.append(contact.display_name)
            chat_stats[chat_user] = {
                "stem": stem,
                "display_name": contact.display_name,
                "is_group": contact.is_group,
                "entry_rel": entry_rel,
                "entry_label": entry_label,
                "message_count": len(records),
                "active_days": len(messages_by_date),
                "first_ts": records[0][0],
                "last_ts": records[-1][0],
            }
    finally:
        for c in conns.values():
            c.close()

    # 3. 更新总索引 notes/index.md
    idx_path = os.path.join(notes_dir, "index.md")
    idx_text = _render_chat_index(chat_stats)
    _atomic_write(idx_path, idx_text)

    _save_state(state_file, state)

    return ArchiveSummary(
        new_messages=new_msg_total,
        updated_files=updated_files,
        updated_chats=updated_chat_names,
        total_chats_scanned=total_chats_scanned,
        exported_images=exported_images,
    )
