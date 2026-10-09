#!/usr/bin/env python3
"""WikiTCG booster opener — pure HTTP via curl_cffi (Chrome impersonation).

Flow (reverse-engineered from a browser HAR capture):
  1. Firebase auth (signInWithPassword or refresh token) -> idToken
  2. POST /api/auth/session {idToken, locale} -> wikitcg_session cookie (JWT, 30 days)
  3. GET /fr/boosters -> wikitcg_entree cookie (waiting-room gate, 20 min) + list of JS chunks
  4. POST /fr/boosters  (Next.js Server Action "openPack", next-action header)
     body: ["fr", <sorte|null>]  -> {"ok", "cards", "packsLeft", "dustGained", "speciaux", ...}

Mechanics: 1 booster every 15 min, up to 10 stored. No need to hit the site every
15 min: daemon mode drains the reserve, then sleeps until it is almost full again.

Config (environment variables, or a .env file next to the script):
  WIKITCG_EMAIL / WIKITCG_PASSWORD   only needed for the first login (refresh token afterwards)
  WIKITCG_STATE                      state file (default: ./.wikitcg_state.json)
  WIKITCG_PULLS                      JSONL pull log (default: ./pulls.jsonl)

Usage:
  python wikitcg_bot.py --dry-run     # login + read reserve + discover action, opens NOTHING
  python wikitcg_bot.py --once        # drain the reserve once and exit (for cron/launchd)
  python wikitcg_bot.py               # daemon
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import random
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

from curl_cffi import requests


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE pairs from .env (next to the script) without overriding the existing environment."""
    path = path or Path(__file__).with_name(".env")
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_dotenv()

BASE = "https://wiki-tcg.com"
LOCALE = "fr"
BOOSTERS_URL = f"{BASE}/{LOCALE}/boosters"

# Public Firebase Web API key (shipped in the site's frontend bundle).
FIREBASE_API_KEY = os.environ.get("WIKITCG_FIREBASE_KEY", "AIzaSyDuhgt5fULV4c1-fBca7cJLtDwWurEQxRc")
FIREBASE_SIGNIN = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
FIREBASE_REFRESH = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"

PACK_INTERVAL_S = 15 * 60
PACK_MAX_STORED = 10
# Known value at capture time; rediscovered automatically when it stops working.
DEFAULT_ACTION_ID = "602e59276c30a4400fa06ff5dfacc4a1cf794377db"

ROUTER_STATE_TREE = quote(json.dumps(
    ["", {"children": [["locale", LOCALE, "d", None], {"children": ["packs", {"children": [
        "__PAGE__", {}, None, None, 4096]}, None, None, 4100]}, None, None, 4120]}, None, None, 4120],
    separators=(",", ":"),
), safe="")

STATE_PATH = Path(os.environ.get("WIKITCG_STATE", ".wikitcg_state.json"))
PULLS_PATH = Path(os.environ.get("WIKITCG_PULLS", "pulls.jsonl"))
DEBUG_PATH = Path("last_action_response.txt")

log = logging.getLogger("wikitcg")


class QueueError(Exception):
    """The site sent us to its waiting room (/attente)."""


class AuthError(Exception):
    pass


class ActionNotFound(Exception):
    """The Server Action ID is no longer valid (new deployment)."""


class UnexpectedResponse(Exception):
    """Unrecognized action response (dumped to DEBUG_PATH)."""


# --------------------------------------------------------------------------- state

def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2))
    os.chmod(STATE_PATH, 0o600)


def jwt_exp(token: str) -> int:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return 0


# --------------------------------------------------------------------------- client

class WikiTCG:
    def __init__(self, state: dict, impersonate: str = "chrome"):
        self.state = state
        self.s = requests.Session(impersonate=impersonate)
        self.s.headers.update({"accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"})
        if sess := state.get("session_cookie"):
            self.s.cookies.set("wikitcg_session", sess, domain="wiki-tcg.com")
        self.s.cookies.set("wikitcg_connu", "1", domain="wiki-tcg.com")

    # ---- auth

    def _firebase_id_token(self) -> str:
        headers = {
            "origin": BASE,
            "referer": f"{BASE}/",
            "x-client-version": "Chrome/JsCore/12.18.0/FirebaseCore-web",
            "x-firebase-gmpid": "1:312622153166:web:481027366ad0ca8402ff9f",
        }
        if rt := self.state.get("refresh_token"):
            r = self.s.post(FIREBASE_REFRESH, headers=headers,
                            data={"grant_type": "refresh_token", "refresh_token": rt})
            if r.status_code == 200:
                j = r.json()
                self.state["refresh_token"] = j["refresh_token"]
                return j["id_token"]
            log.warning("refresh token rejected (%s), falling back to password login", r.status_code)

        email, password = os.environ.get("WIKITCG_EMAIL"), os.environ.get("WIKITCG_PASSWORD")
        if not (email and password):
            raise AuthError("Session expired and WIKITCG_EMAIL / WIKITCG_PASSWORD are not set")
        r = self.s.post(FIREBASE_SIGNIN, headers=headers, json={
            "returnSecureToken": True, "email": email, "password": password,
            "clientType": "CLIENT_TYPE_WEB",
        })
        if r.status_code != 200:
            raise AuthError(f"Firebase signIn {r.status_code}: {r.text[:200]}")
        j = r.json()
        self.state["refresh_token"] = j["refreshToken"]
        return j["idToken"]

    def login(self) -> None:
        id_token = self._firebase_id_token()
        r = self.s.post(f"{BASE}/api/auth/session", json={"idToken": id_token, "locale": LOCALE},
                        headers={"origin": BASE, "referer": f"{BASE}/{LOCALE}/connexion"})
        if r.status_code != 200 or not r.json().get("ok"):
            raise AuthError(f"/api/auth/session {r.status_code}: {r.text[:200]}")
        cookie = self.s.cookies.get("wikitcg_session", domain="wiki-tcg.com")
        if not cookie:
            raise AuthError("no wikitcg_session cookie received")
        self.state["session_cookie"] = cookie
        save_state(self.state)
        log.info("session opened (valid until %s)", time.strftime("%Y-%m-%d", time.localtime(jwt_exp(cookie))))

    def ensure_session(self) -> None:
        cookie = self.state.get("session_cookie")
        if not cookie or jwt_exp(cookie) < time.time() + 86400:
            self.login()

    # ---- read

    def account(self) -> dict:
        r = self.s.get(f"{BASE}/api/v1/battement", params={"parts": "compte"},
                       headers={"referer": BOOSTERS_URL})
        part = r.json().get("parts", {}).get("compte", {})
        if part.get("statut") != 200:
            raise AuthError(f"battement compte statut={part.get('statut')}")
        return part["corps"]["player"]

    def load_boosters_page(self) -> tuple[str, int | None]:
        """GET /fr/boosters: sets wikitcg_entree, returns (html, nextPackInMs)."""
        r = self.s.get(BOOSTERS_URL, headers={"referer": f"{BASE}/{LOCALE}"})
        if "/attente" in r.url:
            raise QueueError("waiting room active")
        r.raise_for_status()
        m = re.search(r'nextPackInMs\\?"\s*:\s*(\d+)', r.text)
        return r.text, int(m.group(1)) if m else None

    # ---- action id

    def discover_action_id(self, html: str) -> str:
        chunks = list(dict.fromkeys(re.findall(r'/_next/static/chunks/[\w\-.~]+\.js', html)))
        log.info("looking for the openPack action in %d chunks…", len(chunks))
        pat = re.compile(r'createServerReference\)?\("([0-9a-f]{40,})",[^)]*?"openPack"\)')
        for path in chunks:
            r = self.s.get(BASE + path, headers={"referer": BOOSTERS_URL})
            if r.status_code == 200 and (m := pat.search(r.text)):
                log.info("openPack action = %s", m.group(1))
                self.state["action_id"] = m.group(1)
                save_state(self.state)
                return m.group(1)
        raise ActionNotFound("openPack not found in JS chunks")

    @property
    def action_id(self) -> str:
        return self.state.get("action_id", DEFAULT_ACTION_ID)

    # ---- open

    def open_pack(self, sorte: str | None = None) -> dict:
        r = self.s.post(
            BOOSTERS_URL,
            data=json.dumps([LOCALE, sorte], separators=(",", ":")),
            headers={
                "next-action": self.action_id,
                "next-router-state-tree": ROUTER_STATE_TREE,
                "accept": "text/x-component",
                "content-type": "text/plain;charset=UTF-8",
                "origin": BASE,
                "referer": BOOSTERS_URL,
            },
        )
        if "/attente" in r.url:
            raise QueueError("waiting room active")
        if r.status_code == 404 or "text/x-component" not in r.headers.get("content-type", ""):
            raise ActionNotFound(f"status={r.status_code} ct={r.headers.get('content-type')}")
        r.raise_for_status()
        try:
            return parse_action_result(r.content)
        except UnexpectedResponse:
            DEBUG_PATH.write_text(f"status={r.status_code}\nurl={r.url}\nheaders={dict(r.headers)}\n\n{r.text}")
            raise


def parse_rsc_rows(data: bytes) -> dict[str, str]:
    """Split an RSC stream into `id:payload` rows.

    Text rows `id:T<hex len>,<text>` are <len> bytes long and do NOT end with a
    newline: the next row follows immediately. All other rows end with `\\n`."""
    rows: dict[str, str] = {}
    i, n = 0, len(data)
    while i < n:
        colon = data.find(b":", i)
        if colon < 0:
            break
        key = data[i:colon].decode("ascii", "replace")
        j = colon + 1
        if data[j:j + 1] == b"T" and (comma := data.find(b",", j)) > 0:
            try:
                length = int(data[j + 1:comma], 16)
            except ValueError:
                length = -1
            if length >= 0:
                rows.setdefault(key, data[comma + 1:comma + 1 + length].decode("utf-8", "replace"))
                i = comma + 1 + length
                continue
        end = data.find(b"\n", j)
        end = n if end < 0 else end
        rows.setdefault(key, data[j:end].decode("utf-8", "replace"))
        i = end + 1
    return rows


def parse_action_result(rsc: bytes) -> dict:
    """Row 0 of the RSC stream holds the action result in "a": either inline
    (small result, e.g. an error) or a "$@N" reference to row N."""
    rows = parse_rsc_rows(rsc)
    try:
        a = json.loads(rows["0"])["a"]
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        raise UnexpectedResponse(f"row 0 / field 'a' missing ({e!r})") from None
    if isinstance(a, str) and a.startswith("$@"):
        if a[2:] not in rows:
            raise UnexpectedResponse(f"row {a[2:]} missing")
        a = json.loads(rows[a[2:]])
    if not isinstance(a, dict):
        raise UnexpectedResponse(f"unexpected result: {str(a)[:200]}")
    return a


# --------------------------------------------------------------------------- run

def record_pull(res: dict, sorte: str | None) -> None:
    with PULLS_PATH.open("a") as f:
        f.write(json.dumps({
            "ts": int(time.time()), "seed": res.get("seed"), "sorte": sorte,
            "dustGained": res.get("dustGained"),
            "cards": [{"qid": c["card"]["qid"], "name": c["card"]["name"], "rarity": c["card"]["rarity"],
                       "foil": c.get("foil"), "isNew": c.get("isNew"), "dust": c.get("dust"),
                       "power": c["card"].get("power")} for c in res.get("cards", [])],
        }, ensure_ascii=False) + "\n")


def drain(bot: WikiTCG, open_specials: bool, dry_run: bool) -> int | None:
    """Empty the reserve. Returns nextPackInMs (or None if unknown)."""
    bot.ensure_session()
    try:
        player = bot.account()
    except AuthError:
        log.info("session rejected, logging in again")
        bot.login()
        player = bot.account()

    html, next_ms = bot.load_boosters_page()
    stock, specials = player.get("packsStored", 0), player.get("speciaux") or []
    log.info("%s: %d booster(s) in reserve, specials=%s, next in %ss",
             player.get("handle"), stock, specials, next_ms and next_ms // 1000)

    if dry_run:
        bot.discover_action_id(html)
        log.info("dry-run: nothing opened")
        return next_ms

    queue: list[str | None] = [None] * stock
    if open_specials:
        for sp in specials:
            queue += [sp["sorte"]] * int(sp.get("nombre", 0))

    rediscovered = False
    while queue:
        sorte = queue[0]
        try:
            res = bot.open_pack(sorte)
        except ActionNotFound as e:
            if rediscovered:
                raise
            log.warning("invalid action (%s), rediscovering", e)
            bot.discover_action_id(html)
            rediscovered = True
            continue
        if not res.get("ok"):
            log.warning("opening refused: %s", res.get("error"))
            break
        queue.pop(0)
        record_pull(res, sorte)
        cards = ", ".join(f"{c['card']['rarity']}{'*' if c.get('foil') else ''} {c['card']['name']}"
                          for c in res["cards"])
        log.info("[%s] %s | +%s dust | %s left", sorte or "normal", cards, res.get("dustGained"),
                 res.get("packsLeft"))
        time.sleep(random.uniform(2.5, 6.0))

    _, next_ms = bot.load_boosters_page()
    return next_ms


def sleep_seconds(next_ms: int | None, target: int) -> float:
    """Time for an empty reserve to refill up to `target` boosters, plus jitter."""
    first = (next_ms / 1000) if next_ms else PACK_INTERVAL_S
    return first + (target - 1) * PACK_INTERVAL_S + random.uniform(60, 300)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="drain the reserve once and exit")
    ap.add_argument("--dry-run", action="store_true", help="login + read reserve, open nothing")
    ap.add_argument("--specials", action="store_true", help="also open owned special boosters")
    ap.add_argument("--target", type=int, default=8,
                    help=f"daemon: wake up when the reserve reaches N (max {PACK_MAX_STORED}, default 8)")
    ap.add_argument("--impersonate", default="chrome", help="curl_cffi profile (default: chrome = latest)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    target = max(1, min(args.target, PACK_MAX_STORED))

    bot = WikiTCG(load_state(), impersonate=args.impersonate)

    if args.once or args.dry_run:
        try:
            drain(bot, args.specials, args.dry_run)
        except QueueError as e:
            log.warning("%s — try again later", e)
            sys.exit(2)
        return

    while True:
        try:
            delay = sleep_seconds(drain(bot, args.specials, False), target)
        except QueueError as e:
            delay = random.uniform(300, 600)
            log.warning("%s — retrying in %d min", e, delay // 60)
        except Exception:
            log.exception("error, retrying in 10 min")
            delay = 600
        log.info("next run at %s", time.strftime("%H:%M", time.localtime(time.time() + delay)))
        time.sleep(delay)


if __name__ == "__main__":
    main()
