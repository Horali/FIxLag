"""Optional JSON template expansion for MLBB slash-coded chat messages."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_TEMPLATES_PATH = Path(__file__).resolve().parents[2] / "data" / "chat_templates.json"

_BBCODE_COLOR_RE = re.compile(r"\[(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{8}|-)\]")


def _clean_mlbb_text(text: str) -> str:
    """Strip NGUI color tags and normalize embedded newlines for display."""
    cleaned = _BBCODE_COLOR_RE.sub("", text)
    cleaned = cleaned.replace("\\n", " ").replace("\n", " ").replace("####", " ")
    return re.sub(r" {2,}", " ", cleaned).strip()


def _format_win_rate(wins_raw: str, matches_raw: str) -> str:
    try:
        wins = int(wins_raw.strip())
        matches = int(matches_raw.strip())
    except ValueError:
        return ""
    if matches <= 0:
        return "0%"
    return f"{(wins / matches) * 100:.1f}%"


class TemplateResolver:
    """Expand MLBB quick-chat/draft slash templates with clean raw fallback."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else DEFAULT_TEMPLATES_PATH
        self.messages: dict[str, str] = {}
        self.heroes: dict[str, str] = {}
        self.hero_roles: dict[str, str] = {}
        self.strings: dict[str, str] = {}
        self.lanes: dict[str, str] = {}
        self._scoped_prefixes: set[str] = set()
        self.loaded = False
        self.reload()

    def reload(self) -> None:
        """Load template tables from JSON if present on disk."""
        self.messages.clear()
        self.heroes.clear()
        self.hero_roles.clear()
        self.strings.clear()
        self.lanes.clear()
        self._scoped_prefixes.clear()
        self.loaded = False
        if not self.path or not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return

        if any(k in data for k in ("messages", "heroes", "strings", "lanes")):
            msgs = data.get("messages") or {}
            heroes = data.get("heroes") or {}
            strings = data.get("strings") or {}
            lanes = data.get("lanes") or {}
            if isinstance(msgs, dict):
                self.messages = {str(k): str(v) for k, v in msgs.items()}
            if isinstance(heroes, dict):
                for k, v in heroes.items():
                    sk = str(k)
                    if isinstance(v, dict):
                        name = str(v.get("name") or "").strip()
                        role = str(v.get("role") or "").strip()
                        if name:
                            self.heroes[sk] = name
                        if role:
                            self.hero_roles[sk] = role
                    else:
                        self.heroes[sk] = str(v)
            if isinstance(strings, dict):
                self.strings = {str(k): str(v) for k, v in strings.items()}
            if isinstance(lanes, dict):
                self.lanes = {str(k): str(v) for k, v in lanes.items()}
        else:
            self.messages = {str(k): str(v) for k, v in data.items()}

        for key in self.messages:
            if "/" in key:
                self._scoped_prefixes.add(key.split("/", 1)[0])
        self.loaded = True

    def _apply_hero_placeholders(self, tmpl: str, hero: str, role: str) -> str:
        out = _clean_mlbb_text(tmpl)
        if "{hero}" in out or "{role}" in out:
            out = out.replace("{hero}", hero).replace("{role}", role)
        elif "{0}" in out or "{1}" in out:
            out = out.replace("{0}", hero).replace("{1}", role)
        elif "%s" in out:
            out = out.replace("%s", hero, 1)
        else:
            out = f"{out} {hero}"
        out = out.replace(" ()", "")
        return re.sub(r" {2,}", " ", out).strip()

    def _format_prefixed_5(self, raw_text: str) -> tuple[str, bool]:
        primary = raw_text.split("|", 1)[0]
        parts = primary.split("/")
        sub_id = parts[1].strip() if len(parts) >= 2 else ""

        if sub_id == "6" and len(parts) == 3:
            hero_id = parts[2].strip()
            hero = self.heroes.get(hero_id)
            if not hero:
                return raw_text, True
            role = self.hero_roles.get(hero_id, "")
            tmpl = self.messages.get("5/6") or self.messages.get("6")
            if tmpl:
                return self._apply_hero_placeholders(tmpl, hero, role), True
            return f"Suggest {hero}", True

        if sub_id == "5" and len(parts) == 5:
            wins, matches, hero_id = parts[2].strip(), parts[3].strip(), parts[4].strip()
            hero = self.heroes.get(hero_id)
            if not hero:
                return raw_text, True
            role = self.hero_roles.get(hero_id, "")
            win_rate = _format_win_rate(wins, matches)
            tmpl = self.messages.get("5/5")
            if tmpl:
                out = _clean_mlbb_text(tmpl)
                out = (
                    out.replace("{hero}", hero)
                    .replace("{role}", role)
                    .replace("{matches}", matches)
                    .replace("{wins}", wins)
                    .replace("{win_rate}", win_rate)
                    .replace("{0}", hero)
                    .replace("{1}", f"Matches: {matches}")
                    .replace("{2}", f"Win Rate: {win_rate}")
                )
                return re.sub(r" {2,}", " ", out).strip(), True
            return f"I want to use {hero}. Matches: {matches}, Win Rate: {win_rate}", True

        if sub_id == "7" and len(parts) == 7:
            medal, kills, deaths, assists, hero_id = (
                parts[2].strip(),
                parts[3].strip(),
                parts[4].strip(),
                parts[5].strip(),
                parts[6].strip(),
            )
            hero = self.heroes.get(hero_id)
            if not hero:
                return raw_text, True
            role = self.hero_roles.get(hero_id, "")
            tmpl = self.messages.get("5/7")
            if tmpl:
                out = _clean_mlbb_text(tmpl)
                out = (
                    out.replace("{hero}", hero)
                    .replace("{role}", role)
                    .replace("{medal}", medal)
                    .replace("{kills}", kills)
                    .replace("{deaths}", deaths)
                    .replace("{assists}", assists)
                    .replace("{0}", hero)
                    .replace("{1}", kills)
                    .replace("{2}", deaths)
                    .replace("{3}", assists)
                )
                return re.sub(r" {2,}", " ", out).strip(), True
            return f"Got MVP using {hero} in the last match, with a score of {kills}/{deaths}/{assists}.", True

        if sub_id == "3" and len(parts) == 6:
            title, power, rank, hero_id = (
                parts[2].strip(),
                parts[3].strip(),
                parts[4].strip(),
                parts[5].strip(),
            )
            hero = self.heroes.get(hero_id)
            if not hero:
                return raw_text, True
            role = self.hero_roles.get(hero_id, "")
            key = "5/3" if title else "5/3_notitle"
            tmpl = self.messages.get(key) or self.messages.get("5/3")
            if tmpl:
                out = _clean_mlbb_text(tmpl)
                out = (
                    out.replace("{title}", title)
                    .replace("{power}", power)
                    .replace("{rank}", rank)
                    .replace("{hero}", hero)
                    .replace("{role}", role)
                )
                if key == "5/3":
                    out = out.replace("{0}", title).replace("{1}", hero)
                else:
                    out = out.replace("{0}", hero).replace("{1}", power).replace("{2}", hero)
                return re.sub(r" {2,}", " ", out).strip(), True
            if title:
                return f"I'm {title} and I want to use {hero}.", True
            return f"I want to use {hero}. Hero Power: {power}", True

        if len(parts) == 2:
            return raw_text, True

        hero_id = parts[-1].strip()
        hero = self.heroes.get(hero_id)
        if not hero:
            return raw_text, True
        role = self.hero_roles.get(hero_id, "")
        tmpl = self.messages.get(f"5/{sub_id}") or self.messages.get(sub_id)
        if tmpl:
            return self._apply_hero_placeholders(tmpl, hero, role), True
        return f"Suggest {hero}", True

    def _format_prefixed_4(self, raw_text: str) -> tuple[str, bool]:
        primary = raw_text.split("|", 1)[0]
        p4 = primary.split("/")
        if len(p4) == 2:
            lane_id = p4[1].strip()
            tmpl = self.messages.get(f"4/{lane_id}")
            if tmpl:
                return _clean_mlbb_text(tmpl), True
            lane = self.lanes.get(lane_id)
            if lane:
                base_tmpl = _clean_mlbb_text(self.messages.get("4") or "I want to go {lane}")
                out = base_tmpl.replace("{lane}", lane).replace("{0}", lane)
                return re.sub(r" {2,}", " ", out).strip(), True
            return raw_text, True

        if len(p4) >= 3:
            lane_id = p4[1].strip()
            hero_id = p4[2].strip()
            lane = self.lanes.get(lane_id)
            hero = self.heroes.get(hero_id)
            if lane and hero:
                tmpl = _clean_mlbb_text(
                    self.messages.get("4_hero") or "I want to use {hero} to go to {lane}."
                )
                out = (
                    tmpl.replace("{hero}", hero)
                    .replace("{0}", hero)
                    .replace("{lane}", lane)
                    .replace("{1}", lane)
                )
                return re.sub(r" {2,}", " ", out).strip(), True
        return raw_text, True

    def format_text(self, raw_text: str, *, channel: int | None = None) -> tuple[str, bool]:
        """Return `(display_text, is_template)` for *raw_text*.

        - `1/<text>` -> `(<text>, False)`
        - Structured slash templates (`2/...`, `3/...`, `4/...`, `5/...`, `7/...`, `8/...`, `12/...`):
          expand using loaded JSON tables if available, otherwise return `raw_text` verbatim.
        - `ch=10` (`2/0` post-match state) is left raw so it never mis-expands as draft quick-chat.
        - Plain text -> `(raw_text, False)`
        """
        if not raw_text:
            return "", False

        if raw_text.startswith("1/"):
            return raw_text[2:], False

        parts = raw_text.split("/")
        if len(parts) < 2 or not parts[0].isdigit():
            return raw_text, False

        prefix = parts[0]
        if prefix == "2" and channel == 10:
            return raw_text, True

        if prefix == "4":
            return self._format_prefixed_4(raw_text)

        if prefix == "3" and len(parts) >= 3:
            str_id = parts[1].strip()
            hero_id = parts[2].strip()
            tmpl = self.strings.get(str_id) or self.messages.get(f"3/{str_id}") or self.messages.get(str_id)
            hero = self.heroes.get(hero_id)
            role = self.hero_roles.get(hero_id, "")
            if tmpl and hero:
                return self._apply_hero_placeholders(tmpl, hero, role), True
            return raw_text, True

        if prefix in ("2", "7", "8", "12"):
            msg_id = parts[1].strip()
            arg = parts[2].strip() if len(parts) >= 3 else ""
            tmpl = self.messages.get(f"{prefix}/{msg_id}")
            if tmpl is None and (prefix in ("7", "8") or prefix not in self._scoped_prefixes):
                tmpl = self.messages.get(msg_id)
            if tmpl:
                clean_tmpl = _clean_mlbb_text(tmpl)
                if "{arg}" in clean_tmpl:
                    return clean_tmpl.replace("{arg}", arg).strip(), True
                if "{0}" in clean_tmpl:
                    return clean_tmpl.replace("{0}", arg).strip(), True
                if "{hero}" in clean_tmpl and arg in self.heroes:
                    return clean_tmpl.replace("{hero}", self.heroes[arg]).strip(), True
                if arg and arg != "0":
                    hero = self.heroes.get(arg)
                    return f"{clean_tmpl} ({hero or arg})", True
                return clean_tmpl, True
            return raw_text, True

        if prefix == "5":
            return self._format_prefixed_5(raw_text)

        return raw_text, True
