#!/usr/bin/env python3
"""Synchronise la table TRELLO_SYNC.md à partir du JSON Trello ou de l'API."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import certifi  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    certifi = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "TRELLO_SYNC.md"
DEFAULT_ENV = REPO_ROOT / ".env.trello"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mettre à jour TRELLO_SYNC.md")
    parser.add_argument("--board-id", help="ID du board Trello")
    parser.add_argument("--api-key", help="Trello API key (override)")
    parser.add_argument("--token", help="Trello token (override)")
    parser.add_argument("--input", type=Path, help="Fichier JSON déjà exporté")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Fichier Markdown à écrire",
    )
    parser.add_argument(
        "--ticket-prefix",
        default="CHG",
        help="Préfixe (Ticket ID)",
    )
    parser.add_argument(
        "--max-cards",
        type=int,
        default=200,
        help="Max cards à inclure (0 = illimité)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Ne rien écrire mais échouer si la sortie diffère du fichier cible",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV,
        help="Fichier .env avec TRELLO_KEY= & TRELLO_TOKEN=",
    )
    return parser.parse_args()


def load_env(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    data: Dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def fetch_board_json(board_id: str, api_key: str, token: str) -> Dict[str, Any]:
    params = {
        "cards": "open",
        "card_fields": "name,desc,due,dueComplete,idList,shortUrl,idShort,closed,idMembers",
        "card_attachments": "true",
        "card_attachment_fields": "url,name",
        "card_labels": "all",
        "lists": "all",
        "members": "all",
        "fields": "name,url",
        "key": api_key,
        "token": token,
    }
    url = f"https://api.trello.com/1/boards/{board_id}?{urllib.parse.urlencode(params)}"
    context = ssl.create_default_context()
    if certifi is not None:
        context.load_verify_locations(certifi.where())
    with urllib.request.urlopen(url, context=context) as response:  # nosec - Trello official endpoint
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def load_board(args: argparse.Namespace) -> Dict[str, Any]:
    if args.input:
        return json.loads(args.input.read_text())
    env = load_env(args.env_file)
    api_key = args.api_key or env.get("TRELLO_KEY") or os.getenv("TRELLO_KEY")
    token = args.token or env.get("TRELLO_TOKEN") or os.getenv("TRELLO_TOKEN")
    board_id = args.board_id or env.get("TRELLO_BOARD_ID") or os.getenv("TRELLO_BOARD_ID")
    if not (api_key and token and board_id):
        raise SystemExit("[trello_update] Manque API key/token/board id.")
    return fetch_board_json(board_id, api_key, token)


def pick_github_link(card: Dict[str, Any]) -> str:
    attachments = card.get("attachments", [])
    for attachment in attachments:
        url = attachment.get("url", "")
        if "github.com" in url:
            return url
    desc = card.get("desc", "")
    for word in desc.split():
        if "github.com" in word:
            return word
    return ""


def render_groups(board: Dict[str, Any], ticket_prefix: str, max_cards: int) -> Tuple[List[str], Dict[str, List[str]]]:
    lists = board.get("lists", [])
    list_lookup = {list_["id"]: list_["name"] for list_ in lists}
    ordered_names = [list_["name"] for list_ in lists]
    member_lookup = {m["id"]: m.get("username") or m.get("fullName") for m in board.get("members", [])}
    groups: Dict[str, List[str]] = {name: [] for name in ordered_names}
    cards = board.get("cards", [])
    cards = [card for card in cards if not card.get("closed")]
    cards.sort(key=lambda c: (c.get("due") or "", c.get("name")))
    if max_cards > 0:
        cards = cards[:max_cards]
    for card in cards:
        ticket_id = f"{ticket_prefix}-{card.get('idShort') or card.get('shortLink')}"
        task = card.get("name", "(sans titre)")
        list_name = list_lookup.get(card.get("idList"), "?")
        assignees = card.get("idMembers", [])
        assignee_text = ", ".join(filter(None, (member_lookup.get(mid) for mid in assignees))) or "Unassigned"
        due = card.get("due") or "-"
        status = derive_status(card)
        gh_link = pick_github_link(card) or "-"
        notes = ", ".join(label.get("name") for label in card.get("labels", [])) or "-"
        row = f"| {ticket_id} | {task} | {assignee_text} | {due} | {status} | {gh_link} | {notes} |"
        groups.setdefault(list_name, []).append(row)
    full_order = ordered_names[:]
    for name in groups.keys():
        if name not in full_order:
            full_order.append(name)
    return full_order, groups


def derive_status(card: Dict[str, Any]) -> str:
    if card.get("closed"):
        return "🔴"
    due = card.get("due")
    if card.get("dueComplete"):
        return "🟢"
    if due:
        due_dt = dt.datetime.fromisoformat(due.replace("Z", "+00:00"))
        if due_dt < dt.datetime.now(dt.timezone.utc):
            return "🟠"
        return "🟡"
    return "⚪️"


def build_markdown(list_order: List[str], groups: Dict[str, List[str]]) -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    total = sum(len(rows) for rows in groups.values())
    lines = [
        "# TRELLO_SYNC",
        "",
        f"> Généré automatiquement le {timestamp} via `scripts/trello_update.py`.",
        "",
        "## Résumé rapide",
        "| Liste | Tickets |",
        "| --- | --- |",
    ]
    for name in list_order:
        lines.append(f"| {name} | {len(groups.get(name, []))} |")
    lines.append(f"| Total | {total} |")
    lines.append("")
    for name in list_order:
        lines.append(f"## {name}")
        lines.append("")
        lines.append("| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        rows = groups.get(name) or []
        lines.extend(rows or ["| - | Aucun ticket | - | - | - | - | - |"])
        lines.append("")
    lines.append("## Procédure")
    lines.append("1. Exporter le board en JSON (ou utiliser l'API avec `--board-id`).")
    lines.append("2. `python scripts/trello_update.py --input board.json`.")
    lines.append("3. Commit + push pour déclencher la sync GitHub Actions.")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    board = load_board(args)
    list_order, groups = render_groups(board, args.ticket_prefix, args.max_cards)
    markdown = build_markdown(list_order, groups)
    if args.check:
        existing = args.output.read_text() if args.output.exists() else ""
        if existing.strip() != markdown.strip():
            print("[trello_update] Le fichier n'est pas à jour. Relancez le script.")
            return 1
        print("[trello_update] ✅ TRELLO_SYNC.md est déjà aligné.")
        return 0
    args.output.write_text(markdown)
    print(f"[trello_update] ✍️  Mise à jour de {args.output} ({sum(len(v) for v in groups.values())} tickets).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
