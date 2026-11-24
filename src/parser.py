"""微信 4.x 联系人、消息内容（含 zstd 解压与 XML 富文本）解析模块。"""
from __future__ import annotations

import html
import re
import sqlite3
import xml.etree.ElementTree as ET
from compression import zstd
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

SYSTEM_IGNORED_USERS = {
    "weixin",
    "fmessage",
    "newsapp",
    "medianote",
    "notifymessage",
    "qmessage",
    "qqmail",
    "tmessage",
    "weibo",
    "floatbottle",
    "shakeapp",
    "lbsapp",
    "brandsessionholder",
    "brandservicesessionholder",
    "opencustomerservicemsg",
    "service_officialaccounts",
}

SPECIAL_DISPLAY_NAMES = {
    "filehelper": "文件传输助手",
    "weixin": "微信团队",
}

_XML_TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class ContactInfo:
    username: str
    display_name: str
    is_group: bool


def load_contacts(contact_db_path: Optional[str]) -> Dict[str, ContactInfo]:
    """从 contact.db 加载联系人与群聊名称映射。"""
    contacts: Dict[str, ContactInfo] = {}
    for uname, dname in SPECIAL_DISPLAY_NAMES.items():
        contacts[uname] = ContactInfo(username=uname, display_name=dname, is_group=False)

    if not contact_db_path:
        return contacts

    conn = sqlite3.connect(f"file:{contact_db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT username, remark, nick_name, alias FROM contact WHERE username IS NOT NULL"
        ).fetchall()
        for username, remark, nick_name, alias in rows:
            if not username:
                continue
            name = (remark or "").strip() or (nick_name or "").strip() or (alias or "").strip()
            if not name:
                name = SPECIAL_DISPLAY_NAMES.get(username, username)
            contacts[username] = ContactInfo(
                username=username,
                display_name=name,
                is_group=username.endswith("@chatroom"),
            )
    finally:
        conn.close()
    return contacts


def should_archive_chat(username: str, include_system_chats: bool = False) -> bool:
    if not username:
        return False
    if username == "filehelper":
        return True
    if include_system_chats:
        return True
    if username in SYSTEM_IGNORED_USERS:
        return False
    if username.startswith("gh_"):
        return False
    return True


def decompress_content(raw_content, ct_flag: Optional[int]) -> str:
    """解压 WCDB zstd 字段并统一转换为 str。"""
    if raw_content is None:
        return ""
    if isinstance(raw_content, memoryview):
        raw_content = raw_content.tobytes()
    if isinstance(raw_content, bytes):
        if ct_flag == 4:
            try:
                raw_content = zstd.decompress(raw_content)
            except Exception:
                pass
        return raw_content.decode("utf-8", errors="replace")
    return str(raw_content)


def _strip_group_prefix(text: str, is_group: bool) -> Tuple[Optional[str], str]:
    """群聊消息正文通常以 `wxid_xxx:\\n` 开头，剥离后返回 (prefix_sender, body)。"""
    if not is_group or not text:
        return None, text
    idx = text.find(":\n")
    if 0 < idx <= 64:
        cand = text[:idx]
        if " " not in cand and "\n" not in cand and "<" not in cand:
            return cand, text[idx + 2 :]
    return None, text


def _clean_xml_text(text: str) -> str:
    cleaned = _XML_TAG_RE.sub("", text)
    return html.unescape(cleaned).strip()


def _parse_appmsg_xml(xml_text: str, sub_type: int) -> str:
    """解析 local_type 基础类型为 49 的 XML 应用消息。"""
    xml_body = xml_text.strip()
    xml_start = xml_body.find("<")
    if xml_start > 0:
        xml_body = xml_body[xml_start:]
    try:
        root = ET.fromstring(xml_body)
    except Exception:
        snippet = _clean_xml_text(xml_body)[:120]
        return f"[应用消息] {snippet}" if snippet else "[应用消息]"

    appmsg = root.find("appmsg")
    if appmsg is None:
        appmsg = root

    title = (appmsg.findtext("title") or "").strip()
    des = (appmsg.findtext("des") or "").strip()
    url = (appmsg.findtext("url") or "").strip()
    xml_type_str = (appmsg.findtext("type") or "").strip()
    msg_sub = sub_type or (int(xml_type_str) if xml_type_str.isdigit() else 0)

    # 57: 引用回复消息
    if msg_sub == 57:
        refer = appmsg.find("refermsg")
        if refer is not None:
            ref_name = (refer.findtext("displayname") or "").strip()
            ref_content = (refer.findtext("content") or "").strip()
            ref_type = (refer.findtext("type") or "").strip()
            if ref_type == "1":
                ref_preview = ref_content.replace("\n", " ")[:60]
            elif ref_type == "3":
                ref_preview = "[图片]"
            elif ref_type == "49":
                ref_preview = "[引用内容]"
            else:
                ref_preview = _clean_xml_text(ref_content).replace("\n", " ")[:60] or "[消息]"
            if ref_name:
                return f"{title}\n  > 引用 {ref_name}: {ref_preview}"
            return f"{title}\n  > 引用: {ref_preview}"
        return title or "[引用回复]"

    # 6: 文件
    if msg_sub == 6:
        return f"[文件] {title}" if title else "[文件]"

    # 5: 链接/文章
    if msg_sub in (4, 5):
        if title and url:
            return f"[链接] [{title}]({url})"
        if title:
            return f"[链接] {title}"
        return f"[链接] {url}" if url else "[链接]"

    # 19: 合并转发聊天记录
    if msg_sub == 19:
        return f"[合并转发] {title}" if title else "[合并转发]"

    # 33 / 36: 小程序
    if msg_sub in (33, 36):
        return f"[小程序] {title}" if title else "[小程序]"

    # 51: 视频号
    if msg_sub == 51:
        desc = (appmsg.findtext(".//finderFeed/desc") or title or des).strip()
        return f"[视频号] {desc[:80]}" if desc else "[视频号]"

    # 2000 / 2001: 转账 / 红包
    if msg_sub == 2000:
        return f"[转账] {des or title}" if (des or title) else "[转账]"
    if msg_sub == 2001:
        return f"[红包] {title or des}" if (title or des) else "[红包]"

    if title and url:
        return f"[应用消息] [{title}]({url})"
    if title:
        return f"[应用消息] {title}"
    return f"[应用消息 type={msg_sub}]"


def _parse_location_xml(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text.strip())
        loc = root.find("location")
        if loc is not None:
            poiname = (loc.attrib.get("poiname") or "").strip()
            label = (loc.attrib.get("label") or "").strip()
            desc = " - ".join(x for x in (poiname, label) if x)
            if desc:
                return f"[位置] {desc}"
    except Exception:
        pass
    return "[位置]"


def extract_image_md5(raw_content, ct_flag: Optional[int], is_group: bool) -> str:
    """从图片消息（base_type == 3）的 XML 中提取 md5 属性作为辅助定位凭据。"""
    text = decompress_content(raw_content, ct_flag)
    _prefix, body = _strip_group_prefix(text, is_group)
    xml_start = body.find("<")
    if xml_start < 0:
        return ""
    try:
        root = ET.fromstring(body[xml_start:].strip())
        img_el = root.find("img")
        if img_el is not None:
            return (img_el.attrib.get("md5") or "").strip().lower()
    except Exception:
        pass
    return ""


def format_message(
    local_type: int,
    raw_content,
    ct_flag: Optional[int],
    is_group: bool,
) -> Tuple[Optional[str], str]:
    """解析单条消息，返回 (从正文剥离的发送者wxid_or_None, 格式化后的可读文本)。"""
    base_type = local_type & 0xFFFFFFFF
    sub_type = local_type >> 32

    text = decompress_content(raw_content, ct_flag)
    prefix_sender, body = _strip_group_prefix(text, is_group)

    if base_type == 1:
        return prefix_sender, body.strip()
    if base_type == 3:
        return prefix_sender, "[图片]"
    if base_type == 34:
        return prefix_sender, "[语音]"
    if base_type == 43:
        return prefix_sender, "[视频]"
    if base_type == 47:
        return prefix_sender, "[表情]"
    if base_type == 48:
        return prefix_sender, _parse_location_xml(body)
    if base_type == 49:
        return prefix_sender, _parse_appmsg_xml(body, sub_type)
    if base_type == 50:
        return prefix_sender, "[语音/视频通话]"
    if base_type == 10000:
        cleaned = _clean_xml_text(body)
        return None, f"[系统消息] {cleaned}" if cleaned else "[系统消息]"
    if base_type == 10002:
        cleaned = _clean_xml_text(body)
        if "revokemsg" in body:
            return prefix_sender, "[撤回了一条消息]"
        return None, f"[系统通知] {cleaned[:100]}" if cleaned else "[系统通知]"

    return prefix_sender, f"[消息类型 {base_type}]"
