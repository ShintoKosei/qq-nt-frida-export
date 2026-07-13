#!/usr/bin/env python3
"""从 QQ NT 明文数据库中提取“本人发送”的文本消息。

QQ NT 消息表大量使用数字列名，消息元素通常保存在 protobuf-like BLOB 中。
本脚本会保留原始消息元数据 JSONL，同时生成较保守的纯文本语料，
方便后续备份、检索或自我蒸馏。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


MESSAGE_TABLES = {
    "c2c": "c2c_msg_table",
    "group": "group_msg_table",
    "dataline": "dataline_msg_table",
}

TEXTISH_TYPES = {1, 129}

NOISE_STRINGS = {
    "g",
    "ҕ",
    "Ҕјi",
    "ÅҔјi",
    "ǅҔјi",
    "Т",
    "У",
    "Ş{",
    "ң\tȣ",
}


def read_varint(buf: bytes, offset: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    pos = offset
    while pos < len(buf) and shift < 70:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, offset


def looks_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch == "\n" or ch == "\t" or ch == " " or ch.isprintable())
    return printable / max(len(text), 1) > 0.92


def is_noise(text: str) -> bool:
    text = text.strip("\x00\r\n\t ")
    if not text or text in NOISE_STRINGS:
        return True
    if len(text) == 1 and not ("\u4e00" <= text <= "\u9fff") and not text.isalnum():
        return True
    if re.fullmatch(r"nt_[0-9]+", text):
        return True
    if "我们已成功添加为好友" in text and "可以开始聊天" in text:
        return True
    if re.fullmatch(r"[$]?[0-9A-Fa-f]{16,}\.(jpg|jpeg|png|gif|mp4|amr)", text):
        return True
    if "NTOSFull::" in text or "/storage/emulated/" in text:
        return True
    return False


def text_score(text: str) -> int:
    score = 0
    if any("\u4e00" <= ch <= "\u9fff" for ch in text):
        score += 8
    if any(ch.isalpha() or ch.isdigit() for ch in text):
        score += 3
    if any(ord(ch) > 0xFFFF for ch in text):
        score += 2
    if text.startswith(("http://", "https://")):
        score += 1
    if len(text) >= 4:
        score += 2
    if re.search(r"[\u0400-\u04ff]", text):
        score -= 5
    if re.fullmatch(r"[A-Za-z0-9_+\-/=]{20,}", text):
        score -= 6
    if text.startswith("{") and len(text) > 200:
        score -= 2
    return score


def decode_utf8_chunk(chunk: bytes) -> str | None:
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch == " " or ch.isprintable())
    text = text.strip("\x00\r\n\t ")
    if not looks_printable(text) or is_noise(text):
        return None
    return text


def protobuf_strings(buf: bytes, depth: int = 0) -> list[str]:
    if not buf or depth > 4:
        return []
    out: list[str] = []
    pos = 0
    while pos < len(buf):
        tag, next_pos = read_varint(buf, pos)
        if tag is None or tag == 0:
            pos += 1
            continue
        wire_type = tag & 0x7
        pos = next_pos
        if wire_type == 0:
            _, pos = read_varint(buf, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        elif wire_type == 2:
            length, pos2 = read_varint(buf, pos)
            if length is None:
                pos += 1
                continue
            end = pos2 + length
            if length < 0 or end > len(buf):
                pos += 1
                continue
            chunk = buf[pos2:end]
            text = decode_utf8_chunk(chunk)
            if text is not None:
                out.append(text)
            if length >= 3:
                out.extend(protobuf_strings(chunk, depth + 1))
            pos = end
        else:
            pos += 1
    return out


def byte_run_strings(buf: bytes) -> list[str]:
    if not buf:
        return []
    out: list[str] = []
    current = bytearray()

    def flush() -> None:
        nonlocal current
        if not current:
            return
        chunk = bytes(current)
        current = bytearray()
        text = chunk.decode("utf-8", "ignore")
        text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch == " " or ch.isprintable())
        text = text.strip("\x00\r\n\t ")
        if text and not is_noise(text) and looks_printable(text):
            out.append(text)

    for byte in buf:
        if byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 0x80:
            current.append(byte)
        else:
            flush()
    flush()
    return out


def unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_candidates(blob: bytes | None) -> list[str]:
    if blob is None:
        return []
    return unique(protobuf_strings(blob) + byte_run_strings(blob))


def choose_content(blob: bytes | None, msg_type: int | None) -> tuple[str, list[str]]:
    candidates = extract_candidates(blob)
    ranked = sorted(candidates, key=lambda s: (text_score(s), len(s)), reverse=True)
    if msg_type not in TEXTISH_TYPES:
        return "", ranked[:8]
    for candidate in ranked:
        if text_score(candidate) >= 5:
            return candidate, ranked[:8]
    return "", ranked[:8]


def iso_from_timestamp(value: int | None) -> str:
    if not value:
        return ""
    return dt.datetime.fromtimestamp(value, tz=dt.timezone(dt.timedelta(hours=8))).isoformat()


def iter_own_messages(con: sqlite3.Connection, account: int):
    fields = (
        "[40001],[40002],[40003],[40010],[40011],[40012],[40013],[40020],"
        "[40021],[40027],[40050],[40052],[40090],[40093],[40800],[40030],[40033]"
    )
    for conv_kind, table in MESSAGE_TABLES.items():
        query = f"SELECT {fields} FROM {table} WHERE [40033]=? ORDER BY [40050], [40001]"
        for row in con.execute(query, (account,)):
            (
                msg_id,
                random_id,
                seq,
                chat_type,
                sub_chat_type,
                msg_type,
                direction,
                sender_uid,
                peer_uid,
                peer_uin,
                timestamp,
                sub_type,
                display_name,
                text_col,
                blob_40800,
                field_40030,
                sender_uin,
            ) = row
            content, candidates = choose_content(blob_40800, msg_type)
            yield {
                "source_table": table,
                "conversation_kind": conv_kind,
                "msg_id": msg_id,
                "random_id": random_id,
                "seq": seq,
                "timestamp": timestamp,
                "time_iso": iso_from_timestamp(timestamp),
                "chat_type": chat_type,
                "sub_chat_type": sub_chat_type,
                "msg_type": msg_type,
                "sub_type": sub_type,
                "direction": direction,
                "sender_uid": sender_uid,
                "sender_uin": sender_uin,
                "peer_uid": peer_uid,
                "peer_uin": peer_uin,
                "field_40030": field_40030,
                "display_name": display_name or "",
                "text_col": text_col or "",
                "content": content,
                "candidates": candidates,
            }


def main() -> int:
    parser = argparse.ArgumentParser(description="从 QQ NT 明文数据库提取本人发送的消息。")
    parser.add_argument("--db", required=True, help="明文 nt_msg.db 路径")
    parser.add_argument("--account", required=True, type=int, help="本人 QQ 号")
    parser.add_argument("--outdir", default="RE/qq_export", help="输出目录")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    db_path = Path(args.db)
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)

    all_path = outdir / "qq_own_messages.jsonl"
    text_path = outdir / "qq_own_text_messages.jsonl"
    corpus_path = outdir / "qq_own_corpus.txt"
    summary_path = outdir / "summary.json"

    stats = Counter()
    by_table = Counter()
    by_type = Counter()
    by_month = Counter()
    by_conversation = Counter()
    examples: list[dict] = []

    with all_path.open("w", encoding="utf-8", newline="\n") as all_f, text_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as text_f, corpus_path.open("w", encoding="utf-8", newline="\n") as corpus_f:
        for msg in iter_own_messages(con, args.account):
            stats["own_messages"] += 1
            by_table[msg["source_table"]] += 1
            by_type[str(msg["msg_type"])] += 1
            if msg["time_iso"]:
                by_month[msg["time_iso"][:7]] += 1
            conv_key = f"{msg['conversation_kind']}:{msg['peer_uin'] or msg['peer_uid']}"
            by_conversation[conv_key] += 1
            all_f.write(json.dumps(msg, ensure_ascii=False) + "\n")
            content = msg["content"].strip()
            if content:
                stats["messages_with_content"] += 1
                content_msg = {k: v for k, v in msg.items() if k != "candidates"}
                text_f.write(json.dumps(content_msg, ensure_ascii=False) + "\n")
                corpus_f.write(content.replace("\r", "").replace("\n", " / ") + "\n")
                if len(examples) < 20:
                    examples.append(
                        {
                            "time_iso": msg["time_iso"],
                            "conversation_kind": msg["conversation_kind"],
                            "msg_type": msg["msg_type"],
                            "content": content,
                        }
                    )

    summary = {
        "account": args.account,
        "db": str(db_path),
        "outputs": {
            "all_messages": str(all_path),
            "text_messages": str(text_path),
            "corpus": str(corpus_path),
        },
        "stats": dict(stats),
        "by_table": dict(by_table),
        "by_type": dict(by_type),
        "by_month": dict(sorted(by_month.items())),
        "top_conversations": by_conversation.most_common(30),
        "examples": examples,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
