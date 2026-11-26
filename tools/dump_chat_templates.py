"""Dump MLBB draft/chat templates (`data/chat_templates.json`) from Document.unity3d.

Purely read-only extraction using stdlib only:
- Pulls `Document.unity3d` from a connected rooted Android device (`--adb <serial>`)
  or reads a local copy (`--document <path>`).
- Parses `AllLanguageEN.bytes`, `Hero.bytes`, `ShowMessage.bytes`,
  `BattleAniEmoji.bytes`, `Emoji.bytes`, and `BattleFastChatMessage.bytes`
  using MLBB's `$mulonggame_table_1` format and 32-bit base-31 `PKHash`.
- Scans `.pcap` files in `--captures-dir` (when present) so every template ID
  referenced by captured matches is included automatically without dumping all
  114,000+ unrelated locale strings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import struct
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.chat_viewer.ingest import find_adb  # noqa: E402
from tools.chat_viewer.pcap_reader import IncrementalPcapReader, InvalidPcapMagicError  # noqa: E402
from tools.chat_viewer.session import MatchStore, SessionRouter  # noqa: E402
from tools.chat_viewer.templates import DEFAULT_TEMPLATES_PATH, TemplateResolver  # noqa: E402

DEVICE_DOCUMENT_PATH = (
    "/sdcard/Android/data/com.mobile.legends/files/dragon2017/assets/Document/android/Document.unity3d"
)

ROLE_NAMES = {
    1: "Tank",
    2: "Fighter",
    3: "Assassin",
    4: "Mage",
    5: "Marksman",
    6: "Support",
}

CURATED_STRING_IDS = {11010, 11011, 11012, 12154}
CURATED_SHOWMESSAGE_IDS = {
    10498,
    11010,
    11011,
    11012,
    12154,
    12282,
    12283,
    12569,
    15336,
    15337,
    15338,
    15339,
    15340,
    15561,
    17254,
    19878,
    *range(21951, 21958),
    *range(21965, 21970),
    21971,
    *range(31469, 31472),
    *range(31684, 31687),
    33187,
    33188,
    *range(36415, 36423),
    *range(36427, 36430),
    48272,
    48273,
    48281,
    48282,
    *range(154829, 154836),
}

_BBCODE_RE = re.compile(r"\[(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{8}|-)\]")


def pk_hash(key: str) -> int:
    """Compute MLBB's 32-bit unsigned base-31 `PKHash` for `<Table>_<Column>_<ID>`."""
    h = 0
    for ch in key:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h


def clean_text(text: str) -> str:
    """Strip NGUI color tags and collapse escaped newlines."""
    out = _BBCODE_RE.sub("", text)
    out = out.replace("\\n", " ").replace("\n", " ").replace("####", " ")
    return re.sub(r" {2,}", " ", out).strip()


def _read_7bit(buf: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7


def _read_str(buf: bytes, pos: int) -> tuple[str, int]:
    ln, pos = _read_7bit(buf, pos)
    return buf[pos : pos + ln].decode("utf-8", "replace"), pos + ln


def parse_mlbb_archive(blob: bytes) -> dict[str, bytes]:
    """Parse an uncompressed `MLBB` Document.unity3d archive into `{filename: bytes}`."""
    if blob[:4] != b"MLBB":
        raise ValueError(f"Expected MLBB archive header, got {blob[:4]!r}")
    count = struct.unpack_from("<I", blob, 4)[0]
    pos = 8
    entries: list[tuple[str, int, int]] = []
    for _ in range(count):
        nlen = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
        name = blob[pos : pos + nlen].decode("utf-8", "replace")
        pos += nlen
        size, offset = struct.unpack_from("<2I", blob, pos)
        pos += 8
        entries.append((name, size, offset))
    data_base = pos
    return {name: blob[data_base + off : data_base + off + size] for name, size, off in entries}


def parse_table_index(tbl: bytes) -> dict[int, int]:
    """Parse `$mulonggame_table_1` header and return `{int_key: row_offset}`."""
    magic = b"$mulonggame_table_1\x00"
    if not tbl.startswith(magic):
        raise ValueError(f"Unexpected table magic: {tbl[:20]!r}")
    _nrows, _ncols, dic_off, _end_off = struct.unpack_from("<4I", tbl, 21)
    _dic_bytes, dic_cnt = struct.unpack_from("<2I", tbl, dic_off)
    out: dict[int, int] = {}
    p = dic_off + 8
    for _ in range(dic_cnt):
        k, off = struct.unpack_from("<2I", tbl, p)
        p += 8
        out[k] = off
    return out


def parse_language_table(tbl: bytes) -> dict[int, str]:
    """Parse `AllLanguageEN.bytes` into `{pk_hash: utf8_string}`."""
    idx = parse_table_index(tbl)
    out: dict[int, str] = {}
    for k, off in idx.items():
        s, _ = _read_str(tbl, off)
        out[k] = s
    return out


def parse_hero_roles(hero_tbl: bytes) -> dict[int, list[int]]:
    """Parse `Hero.bytes` binary rows to extract `m_Sort` (`int32[]`) per hero ID."""
    idx = parse_table_index(hero_tbl)
    roles: dict[int, list[int]] = {}
    for hid, off in idx.items():
        p = off + 16  # m_SkinId, m_PreLoadID, m_PreLoadConfId, m_ReadExtraType
        _, p = _read_str(hero_tbl, p)  # m_Prefabs
        p += 8 + 16  # m_Size (float), m_GuideType (int32), 4 string hash refs
        n_skill_groups, p = _read_7bit(hero_tbl, p)
        for _ in range(n_skill_groups):
            n_skills, p = _read_7bit(hero_tbl, p)
            p += 4 * n_skills
        n_ind, p = _read_7bit(hero_tbl, p)
        p += 4 * n_ind
        n_sort, p = _read_7bit(hero_tbl, p)
        sorts = list(struct.unpack_from(f"<{n_sort}i", hero_tbl, p))
        roles[hid] = sorts
    return roles


def scan_capture_ids(captures_dir: Path | None) -> dict[str, set[int]]:
    """Scan local `.pcap` files to discover all referenced template & hero IDs."""
    refs: dict[str, set[int]] = {
        "strings": set(),
        "showmessage": set(),
        "heroes": set(),
        "emots": set(),
        "emojis": set(),
    }
    if captures_dir is None or not captures_dir.is_dir():
        return refs

    empty_tmpl = TemplateResolver(captures_dir / "__missing__.json")
    for p in sorted(captures_dir.glob("*.pcap")):
        if not p.is_file() or p.stat().st_size < 100:
            continue
        store = MatchStore()
        router = SessionRouter(store=store, templates=empty_tmpl)
        reader = IncrementalPcapReader()
        try:
            with p.open("rb") as fh:
                while True:
                    chunk = fh.read(131072)
                    if not chunk:
                        break
                    for pkt in reader.feed(chunk):
                        router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
        except (OSError, InvalidPcapMagicError):
            continue

        for sess in store.get_matches():
            for ev in sess.events:
                if not ev.is_template:
                    continue
                primary = ev.raw_text.split("|", 1)[0]
                parts = primary.split("/")
                if len(parts) < 2 or not parts[0].isdigit():
                    continue
                pref = parts[0]
                if pref == "3" and len(parts) >= 3:
                    if parts[1].strip().isdigit():
                        refs["strings"].add(int(parts[1].strip()))
                    if parts[2].strip().isdigit():
                        refs["heroes"].add(int(parts[2].strip()))
                elif pref in ("7", "8"):
                    if parts[1].strip().isdigit():
                        refs["showmessage"].add(int(parts[1].strip()))
                elif pref == "12":
                    if parts[1].strip().isdigit():
                        refs["emots"].add(int(parts[1].strip()))
                elif pref == "2":
                    if parts[1].strip().isdigit():
                        refs["emojis"].add(int(parts[1].strip()))
                elif pref == "5" and len(parts) >= 3:
                    if parts[-1].strip().isdigit():
                        refs["heroes"].add(int(parts[-1].strip()))
    return refs


def build_templates_dict(archive_bytes: bytes, captures_dir: Path | None = None) -> dict[str, Any]:
    """Build the `chat_templates.json` payload from `Document.unity3d` bytes."""
    files = parse_mlbb_archive(archive_bytes)
    lang = parse_language_table(files["AllLanguageEN.bytes"])

    def lookup(table: str, col: str, row_id: int) -> str | None:
        return lang.get(pk_hash(f"{table}_{col}_{row_id}"))

    refs = scan_capture_ids(captures_dir)

    # 1. Heroes: id -> {"name": ..., "role": ...}
    hero_roles = parse_hero_roles(files["Hero.bytes"])
    heroes_out: dict[str, dict[str, str]] = {}
    for hid, sort_ids in sorted(hero_roles.items()):
        if hid > 200 and hid not in refs["heroes"]:
            continue
        name = lookup("Hero", "mName", hid)
        if not name:
            continue
        role_str = "/".join(ROLE_NAMES.get(r, str(r)) for r in sort_ids if r in ROLE_NAMES)
        heroes_out[str(hid)] = {"name": clean_text(name), "role": role_str}

    # 2. Strings for 3/<str_id>/<hero_id>
    string_ids = sorted(CURATED_STRING_IDS | refs["strings"])
    strings_out: dict[str, str] = {}
    for sid in string_ids:
        raw_val = lookup("ShowMessage", "mMessage", sid)
        if raw_val:
            txt = clean_text(raw_val)
            txt = txt.replace("{0}", "{hero}").replace("{1}", "{role}")
            strings_out[str(sid)] = txt

    # 3. Messages: ShowMessage (7/, 8/, 5/*), BattleAniEmoji (12/), Emoji (2/)
    messages_out: dict[str, str] = {}
    sm_idx = parse_table_index(files["ShowMessage.bytes"])
    wanted_sm = sorted((CURATED_SHOWMESSAGE_IDS | refs["showmessage"]) & set(sm_idx.keys()))
    for sid in wanted_sm:
        raw_val = lookup("ShowMessage", "mMessage", sid)
        if raw_val:
            cleaned = clean_text(raw_val)
            messages_out[str(sid)] = cleaned
            messages_out[f"7/{sid}"] = cleaned
            messages_out[f"8/{sid}"] = cleaned

    # 5/* templates sourced directly from ShowMessage rows
    sm_17254 = lookup("ShowMessage", "mMessage", 17254)
    if sm_17254:
        messages_out["5/6"] = clean_text(sm_17254).replace("{0}", "{hero}")
    sm_10498 = lookup("ShowMessage", "mMessage", 10498)
    if sm_10498:
        messages_out["5/5"] = clean_text(sm_10498).replace("{0}", "{hero}")
    sm_33187 = lookup("ShowMessage", "mMessage", 33187)
    if sm_33187:
        messages_out["5/7"] = clean_text(sm_33187)
    sm_15338 = lookup("ShowMessage", "mMessage", 15338)
    if sm_15338:
        messages_out["5/3"] = clean_text(sm_15338)
    sm_15339 = lookup("ShowMessage", "mMessage", 15339)
    if sm_15339:
        messages_out["5/3_notitle"] = clean_text(sm_15339)

    # 12/<id> BattleAniEmoji
    ani_idx = parse_table_index(files["BattleAniEmoji.bytes"])
    for eid in sorted(ani_idx):
        nm = lookup("BattleAniEmoji", "mName", eid)
        if nm:
            messages_out[f"12/{eid}"] = f"[Emote] {clean_text(nm)}"

    # 2/<id> Emoji
    emoji_idx = parse_table_index(files["Emoji.bytes"])
    for eid in sorted(emoji_idx):
        nm = lookup("Emoji", "mEmojiName", eid)
        if nm:
            messages_out[f"2/{eid}"] = f"[Emoji] {clean_text(nm)}"

    # BattleFastChatMessage quick-chats (kept under separate key + fastchat/* prefix)
    fc_idx = parse_table_index(files["BattleFastChatMessage.bytes"])
    fastchat_out: dict[str, str] = {}
    for fid in sorted(fc_idx):
        txt = lookup("BattleFastChatMessage", "mMessage", fid)
        if txt:
            cleaned = clean_text(txt)
            fastchat_out[str(fid)] = cleaned
            messages_out[f"fastchat/{fid}"] = cleaned

    return {
        "messages": messages_out,
        "heroes": heroes_out,
        "strings": strings_out,
        "fastchat": fastchat_out,
    }


def read_document_from_adb(serial: str, adb_path: Path | str | None = None) -> bytes:
    """Read `Document.unity3d` from a rooted Android device over `adb exec-out`."""
    adb = find_adb(adb_path)
    if adb is None:
        raise FileNotFoundError("adb executable not found")
    cmd = [str(adb), "-s", serial, "exec-out", f"su -c 'cat {DEVICE_DOCUMENT_PATH}'"]
    return subprocess.check_output(cmd)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Dump MLBB chat templates to data/chat_templates.json")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--adb", metavar="SERIAL", help="ADB device serial to read Document.unity3d from")
    src.add_argument("--document", type=Path, help="Local Document.unity3d file path")
    ap.add_argument("--adb-path", type=Path, default=None, help="Override path to adb executable")
    ap.add_argument(
        "--captures-dir",
        type=Path,
        default=REPO_ROOT / "captures",
        help="Scan .pcap files here for referenced template IDs",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_TEMPLATES_PATH,
        help="Output JSON path (default: data/chat_templates.json)",
    )
    args = ap.parse_args(argv)

    if args.document is not None:
        archive_bytes = args.document.read_bytes()
    else:
        archive_bytes = read_document_from_adb(args.adb, args.adb_path)

    payload = build_templates_dict(archive_bytes, captures_dir=args.captures_dir)
    atomic_write_json(args.out, payload)
    print(
        f"Wrote {args.out} ("
        f"messages={len(payload['messages'])}, "
        f"heroes={len(payload['heroes'])}, "
        f"strings={len(payload['strings'])}, "
        f"fastchat={len(payload['fastchat'])})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
