"""Optional JSON template expansion for MLBB slash-coded chat messages."""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_TEMPLATES_PATH = Path(__file__).resolve().parents[2] / "data" / "chat_templates.json"


class TemplateResolver:
    """Expand MLBB quick-chat/draft slash templates with clean raw fallback."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else DEFAULT_TEMPLATES_PATH
        self.messages: dict[str, str] = {}
        self.heroes: dict[str, str] = {}
        self.strings: dict[str, str] = {}
        self.loaded = False
        self.reload()

    def reload(self) -> None:
        """Load template tables from JSON if present on disk."""
        self.messages.clear()
        self.heroes.clear()
        self.strings.clear()
        self.loaded = False
        if not self.path or not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return

        if any(k in data for k in ("messages", "heroes", "strings")):
            msgs = data.get("messages") or {}
            heroes = data.get("heroes") or {}
            strings = data.get("strings") or {}
            if isinstance(msgs, dict):
                self.messages = {str(k): str(v) for k, v in msgs.items()}
            if isinstance(heroes, dict):
                self.heroes = {str(k): str(v) for k, v in heroes.items()}
            if isinstance(strings, dict):
                self.strings = {str(k): str(v) for k, v in strings.items()}
        else:
            self.messages = {str(k): str(v) for k, v in data.items()}
        self.loaded = True

    def format_text(self, raw_text: str) -> tuple[str, bool]:
        """Return `(display_text, is_template)` for *raw_text*.

        - `1/<text>` -> `(<text>, False)`
        - Structured slash templates (`2/...`, `3/...`, `5/...`, `7/...`, `8/...`, `12/...`):
          expand using loaded JSON tables if available, otherwise return `raw_text` verbatim.
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
        if prefix == "3" and len(parts) >= 3:
            str_id = parts[1].strip()
            hero_id = parts[2].strip()
            tmpl = self.strings.get(str_id) or self.messages.get(str_id)
            hero = self.heroes.get(hero_id)
            if tmpl and hero:
                if "{hero}" in tmpl:
                    return tmpl.replace("{hero}", hero), True
                if "%s" in tmpl:
                    return tmpl.replace("%s", hero, 1), True
                return f"{tmpl} {hero}", True
            if hero and str_id in self.messages:
                return f"{self.messages[str_id]} {hero}", True
            return raw_text, True

        if prefix in ("2", "7", "8", "12"):
            msg_id = parts[1].strip()
            arg = parts[2].strip() if len(parts) >= 3 else ""
            tmpl = self.messages.get(msg_id)
            if tmpl:
                if "{arg}" in tmpl:
                    return tmpl.replace("{arg}", arg), True
                if "{hero}" in tmpl and arg in self.heroes:
                    return tmpl.replace("{hero}", self.heroes[arg]), True
                if arg and arg != "0":
                    hero = self.heroes.get(arg)
                    return f"{tmpl} ({hero or arg})", True
                return tmpl, True
            return raw_text, True

        if prefix == "5":
            # Examples: 5/6/<hero_id> or 5/5/<...>/<hero_id>
            hero_id = parts[-1].strip()
            sub_id = parts[1].strip() if len(parts) >= 2 else ""
            tmpl = self.messages.get(f"5/{sub_id}") or self.messages.get(sub_id)
            hero = self.heroes.get(hero_id)
            if tmpl and hero:
                if "{hero}" in tmpl:
                    return tmpl.replace("{hero}", hero), True
                return f"{tmpl} {hero}", True
            if hero:
                return f"Suggest {hero}", True
            return raw_text, True

        return raw_text, True
