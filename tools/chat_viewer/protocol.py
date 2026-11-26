"""Low-level MLBB wire decoders: varint, pure-Python raw LZ4, and TLV structs."""

from __future__ import annotations

import re

_MSG_UID_RE = re.compile(r"^(\d+)-(\d+)-\d+$")


def read_varint(buf: bytes | bytearray | memoryview, pos: int) -> tuple[int, int]:
    """Decode an unsigned base-128 varint from *buf* starting at *pos*."""
    val = 0
    shift = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
    raise ValueError("truncated varint")


def lz4_decompress_raw(src: bytes | bytearray | memoryview, expected_len: int | None = None) -> bytes:
    """Decompress a pure raw LZ4 block without frame headers.

    Handles extended literal/match lengths (0xFF bytes) and overlapping
    backward copies where offset < match_len.
    """
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        tok = src[i]
        i += 1

        lit_len = tok >> 4
        if lit_len == 15:
            while i < n:
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
            else:
                raise ValueError("truncated lz4 literal length")

        if i + lit_len > n:
            raise ValueError(f"truncated lz4 literals: {i + lit_len} > {n}")
        if lit_len:
            out.extend(src[i : i + lit_len])
            i += lit_len

        # LZ4 blocks always end with a literal sequence (no offset/match after last literals).
        if i >= n:
            break
        if i + 2 > n:
            raise ValueError("truncated lz4 match offset")

        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
            raise ValueError(f"invalid lz4 offset {offset} at output size {len(out)}")

        match_len = (tok & 0x0F) + 4
        if (tok & 0x0F) == 15:
            while i < n:
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
            else:
                raise ValueError("truncated lz4 match length")

        if offset >= match_len:
            start = len(out) - offset
            out.extend(out[start : start + match_len])
        elif offset == 1:
            out.extend(bytes([out[-1]]) * match_len)
        else:
            rem = match_len
            while rem > 0:
                take = min(rem, offset)
                start = len(out) - offset
                out.extend(out[start : start + take])
                rem -= take

    if expected_len is not None and len(out) != expected_len:
        raise ValueError(f"lz4 ulen mismatch: got {len(out)}, expected {expected_len}")
    return bytes(out)


def _parse_collection_item(
    buf: bytes | bytearray | memoryview,
    pos: int,
    elem_tag: int,
    max_depth: int,
    *,
    require_terminator: bool = False,
) -> tuple[object, int]:
    ew = elem_tag >> 4
    if ew in (0, 1, 2, 3):
        return read_varint(buf, pos)
    if ew == 4:
        ln, pos = read_varint(buf, pos)
        if pos + ln > len(buf):
            raise ValueError("truncated list/map bytes")
        return bytes(buf[pos : pos + ln]), pos + ln
    if ew == 7:
        return parse_mlbb_struct(buf, pos, max_depth - 1, require_terminator=require_terminator)
    raise ValueError(f"unsupported collection element tag {elem_tag:#x}")


def parse_mlbb_struct(
    buf: bytes | bytearray | memoryview,
    pos: int,
    max_depth: int = 16,
    *,
    require_terminator: bool = False,
) -> tuple[dict[tuple[str, int], object], int]:
    """Parse an MLBB TLV struct body starting immediately after the 0x70 tag."""
    if max_depth <= 0:
        raise ValueError("max struct nesting depth exceeded")
    fields: dict[tuple[str, int], object] = {}
    n = len(buf)
    while pos < n:
        tag = buf[pos]
        pos += 1
        if tag == 0x80:
            return fields, pos
        wire = tag >> 4
        fnum = tag & 0x0F
        if fnum == 0x0F:
            fnum, pos = read_varint(buf, pos)

        if wire in (0, 1, 2, 3):
            val, pos = read_varint(buf, pos)
            fields[("v", fnum)] = val
        elif wire == 4:
            ln, pos = read_varint(buf, pos)
            if pos + ln > n:
                raise ValueError("truncated bytes field")
            fields[("b", fnum)] = bytes(buf[pos : pos + ln])
            pos += ln
        elif wire == 5:
            cnt, pos = read_varint(buf, pos)
            items: list[object] = []
            for _ in range(cnt):
                if pos >= n:
                    raise ValueError("truncated list element tag")
                et = buf[pos]
                pos += 1
                item, pos = _parse_collection_item(
                    buf, pos, et, max_depth, require_terminator=require_terminator
                )
                items.append(item)
            fields[("l", fnum)] = items
        elif wire == 6:
            cnt, pos = read_varint(buf, pos)
            pairs: list[tuple[object, object]] = []
            for _ in range(cnt):
                if pos >= n:
                    raise ValueError("truncated map key tag")
                kt = buf[pos]
                pos += 1
                k, pos = _parse_collection_item(
                    buf, pos, kt, max_depth, require_terminator=require_terminator
                )
                if pos >= n:
                    raise ValueError("truncated map value tag")
                vt = buf[pos]
                pos += 1
                v, pos = _parse_collection_item(
                    buf, pos, vt, max_depth, require_terminator=require_terminator
                )
                pairs.append((k, v))
            fields[("m", fnum)] = pairs
        elif wire == 7:
            sub, pos = parse_mlbb_struct(buf, pos, max_depth - 1, require_terminator=require_terminator)
            fields[("s", fnum)] = sub
        else:
            raise ValueError(f"unknown wire type {wire:#x} at pos {pos - 1}")
    if require_terminator:
        raise ValueError("missing struct terminator 0x80")
    return fields, pos


def global_pos_to_camp_seat(pos: int) -> tuple[int, int] | None:
    """Convert 1-based global draft seat (`1..5` Camp 1, `6..10` Camp 2) to `(camp, seat)`."""
    if 1 <= pos <= 5:
        return 1, pos - 1
    if 6 <= pos <= 10:
        return 2, pos - 6
    return None


def parse_help_select_body(body: bytes, *, sender_uid: int | None = None) -> dict[str, object] | None:
    """Decode an `ev=0x45` (`OperType_Battle_HelpSelectHero`) seat/hero swap sub-event."""
    if len(body) < 3 or body[0] != 0x70:
        return None
    try:
        fields, _ = parse_mlbb_struct(body, 1, require_terminator=True)
    except ValueError:
        return None

    req_uid = fields.get(("v", 0))
    hero_id = fields.get(("v", 1))
    req_pos = fields.get(("v", 2))
    ack_uid = fields.get(("v", 3))
    if not isinstance(ack_uid, int) and isinstance(sender_uid, int) and sender_uid > 0xFF:
        ack_uid = sender_uid
    ack_pos = fields.get(("v", 4))
    req_skin = fields.get(("v", 5))
    battle_skill = fields.get(("v", 6))

    if not isinstance(req_uid, int) or not isinstance(ack_uid, int) or req_uid <= 0 or ack_uid <= 0:
        return None
    if req_uid == ack_uid:
        return None

    req_cs = global_pos_to_camp_seat(req_pos) if isinstance(req_pos, int) else None
    ack_cs = global_pos_to_camp_seat(ack_pos) if isinstance(ack_pos, int) else None
    return {
        "ev_type": 0x45,
        "req_uid": req_uid,
        "ack_uid": ack_uid,
        "hero_id": hero_id if isinstance(hero_id, int) else None,
        "req_pos": req_pos if isinstance(req_pos, int) else None,
        "ack_pos": ack_pos if isinstance(ack_pos, int) else None,
        "req_slot": ((req_cs[0] << 4) | req_cs[1]) if req_cs else None,
        "ack_slot": ((ack_cs[0] << 4) | ack_cs[1]) if ack_cs else None,
        "req_skin": req_skin if isinstance(req_skin, int) else None,
        "battle_skill": battle_skill if isinstance(battle_skill, int) else None,
    }


def parse_ready_select_body(body: bytes, *, outer_slot: int) -> dict[str, object]:
    """Decode `ev=0x36` (`OperTypeId_Battle_ReadySelect`) binding `uid <-> (camp, seat)`."""
    out: dict[str, object] = {"ev_type": 0x36, "slot": outer_slot, "body": body}
    if len(body) >= 3 and body[0] == 0x70:
        try:
            fields, _ = parse_mlbb_struct(body, 1, require_terminator=True)
        except ValueError:
            return out
        camp = fields.get(("v", 3))
        seat = fields.get(("v", 2), 0)
        if camp in (1, 2) and outer_slot > 0xFF and isinstance(seat, int) and 0 <= seat <= 4:
            out["uid"] = outer_slot
            out["camp"] = camp
            out["seat"] = seat
            out["slot"] = (camp << 4) | seat
    return out


def parse_confirm_hero_body(body: bytes, *, outer_slot: int) -> dict[str, object] | None:
    """Decode `ev=0x34` hero lock-in confirmation payload (`70 00 <hero_id> ... 80`)."""
    if outer_slot <= 0xFF or len(body) < 3 or body[0] != 0x70:
        return None
    try:
        fields, _ = parse_mlbb_struct(body, 1, require_terminator=True)
    except ValueError:
        return None
    hero_id = fields.get(("v", 0))
    if not isinstance(hero_id, int) or hero_id <= 0:
        return None
    return {"ev_type": 0x34, "uid": outer_slot, "hero_id": hero_id}


def parse_chat_body(body: bytes) -> dict[str, object] | None:
    """Decode an ev=0x06 chat sub-event payload (`70 00 <ch> 41 <text> ...`)."""
    if len(body) < 3 or body[0] != 0x70:
        return None
    try:
        fields, _ = parse_mlbb_struct(body, 1)
    except ValueError:
        return None

    raw_bytes = fields.get(("b", 1))
    if not isinstance(raw_bytes, bytes):
        return None

    channel = fields.get(("v", 0))
    if not isinstance(channel, int):
        channel = 0

    raw_text = raw_bytes.decode("utf-8", "replace")
    msg_uid_raw = fields.get(("b", 11))
    msg_uid = msg_uid_raw.decode("utf-8", "replace") if isinstance(msg_uid_raw, bytes) else ""

    battle_id: str | None = None
    uid: int | None = None
    if msg_uid:
        match = _MSG_UID_RE.match(msg_uid)
        if match:
            battle_id = match.group(1)
            uid = int(match.group(2))

    return {
        "channel": channel,
        "raw_text": raw_text,
        "msg_uid": msg_uid,
        "battle_id": battle_id,
        "uid": uid,
    }


def extract_events_from_struct_list(items: list[object]) -> list[dict[str, object]]:
    """Extract normalized sub-events (0x06 chat, 0x34 hero lock-in, 0x36/0x0b slot hints, 0x45 swaps) from a `70 51` list."""
    out: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ev_type = item.get(("v", 1))
        slot = item.get(("v", 0))
        body = item.get(("b", 3))
        if not isinstance(ev_type, int) or not isinstance(slot, int) or not isinstance(body, bytes):
            continue
        if ev_type == 0x06:
            chat = parse_chat_body(body)
            if chat is not None:
                chat["ev_type"] = 0x06
                chat["slot"] = slot
                out.append(chat)
        elif ev_type == 0x34:
            pick = parse_confirm_hero_body(body, outer_slot=slot)
            if pick is not None:
                out.append(pick)
        elif ev_type == 0x45:
            swap = parse_help_select_body(body, sender_uid=slot)
            if swap is not None:
                out.append(swap)
        elif ev_type == 0x36:
            out.append(parse_ready_select_body(body, outer_slot=slot))
        elif ev_type == 0x0B:
            out.append({"ev_type": ev_type, "slot": slot, "body": body})
    return out


def _scan_defensive_subevents(data: bytes) -> list[dict[str, object]]:
    """Defensively scan a partial post-clear LZW suffix for complete `01 <ev> 43 <len> 70 ...`."""
    out: list[dict[str, object]] = []
    i = 0
    n = len(data)
    while i + 5 <= n:
        if data[i] == 0x01 and data[i + 1] in (0x06, 0x36, 0x0B, 0x45) and data[i + 2] == 0x43:
            ev_type = data[i + 1]
            try:
                elen, k = read_varint(data, i + 3)
            except ValueError:
                i += 1
                continue
            if elen > 0 and k + elen <= n and data[k] == 0x70:
                body = data[k : k + elen]
                slot: int | None = None
                # Look backwards locally for enclosing `70 00 <slot_varint>`.
                if i >= 3 and data[i - 3 : i - 1] == b"\x70\x00":
                    slot = data[i - 1]
                elif i >= 4 and data[i - 4 : i - 2] == b"\x70\x00":
                    try:
                        val, end_pos = read_varint(data, i - 2)
                        if end_pos == i:
                            slot = val
                    except ValueError:
                        slot = None

                if ev_type == 0x06:
                    chat = parse_chat_body(body)
                    if chat is not None:
                        chat["ev_type"] = 0x06
                        chat["slot"] = slot
                        out.append(chat)
                        i = k + elen
                        continue
                elif ev_type == 0x45:
                    swap = parse_help_select_body(body, sender_uid=slot)
                    if swap is not None:
                        out.append(swap)
                        i = k + elen
                        continue
                elif ev_type == 0x36 and slot is not None:
                    out.append(parse_ready_select_body(body, outer_slot=slot))
                    i = k + elen
                    continue
                else:
                    out.append({"ev_type": ev_type, "slot": slot, "body": body})
                    i = k + elen
                    continue
        i += 1
    return out


def extract_events_from_tick_bytes(data: bytes, partial_suffix: bool = False) -> list[dict[str, object]]:
    """Extract sub-events from a decoded tick payload (`70 51 ...` or partial clear suffix)."""
    if not data:
        return []
    if not partial_suffix and data[0] == 0x70:
        try:
            st, _ = parse_mlbb_struct(data, 1)
            for key in (("l", 1), ("l", 2)):
                items = st.get(key)
                if isinstance(items, list):
                    return extract_events_from_struct_list(items)
        except ValueError:
            pass
    return _scan_defensive_subevents(data)
