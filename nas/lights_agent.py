#!/usr/bin/env python3
"""
Lighting agent — Hue + IKEA Tradfri, bridged to R2.

Both hubs are LAN-only, so the Cloudflare Worker cannot reach either one. This
runs on the NAS: it reads state and pushes it to R2 for the dashboard, and it
polls R2 for commands the dashboard has queued and executes them locally.

Secrets never pass through the repo:
  /cfg-r2/vaillant.env   R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY   (shared)
  /cfg/lights.env        DIRIGERA_HOST (TRADFRI_HOST accepted as an alias)
  /cfg/hue_key.json      written by this script on first pairing
  /cfg/dirigera_token.json  written by this script on first pairing

The Hue key is minted here rather than pasted in, so it never travels through a
chat log or a config file anyone has to copy by hand.
"""

import asyncio
import calendar
import json
import math
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3
from botocore.config import Config

STATE_OBJ = os.environ.get("R2_LIGHTS_OBJECT", "lights.json")
CMD_OBJ = os.environ.get("R2_LIGHTS_CMD", "lightcmd.json")
BUCKET = os.environ.get("R2_BUCKET", "powerwall-data")
ACCOUNT = os.environ["R2_ACCOUNT_ID"]
POLL = float(os.environ.get("POLL_SECONDS", "4"))
PUSH_EVERY = float(os.environ.get("PUSH_SECONDS", "20"))
HUE_HOST = os.environ.get("HUE_HOST", "")
CFG = "/cfg"


def load_env(path):
    """Read KEY=value lines literally. No shell, so an @ or # in a value is safe."""
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass


def jread(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def jwrite(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def http(url, method="GET", body=None, timeout=8):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "null")


# ---------------------------------------------------------------- hue

def hue_pair(host):
    """Mint an application key. Needs the round link button pressed."""
    print(f"[hue] no key yet — press the link button on the bridge at {host}", flush=True)
    deadline = time.time() + 300
    while time.time() < deadline:
        try:
            r = http(f"http://{host}/api", "POST",
                     {"devicetype": "powerwall-dashboard#nas", "generateclientkey": True})
            first = r[0] if isinstance(r, list) else r
            if first.get("success", {}).get("username"):
                key = first["success"]["username"]
                jwrite(f"{CFG}/hue_key.json", {"username": key,
                                               "clientkey": first["success"].get("clientkey")})
                print("[hue] paired, key saved", flush=True)
                return key
        except Exception as exc:
            print(f"[hue] pairing attempt failed: {exc}", flush=True)
        time.sleep(3)
    raise SystemExit("[hue] link button never pressed — restart the container to retry")


def hue_key(host):
    saved = jread(f"{CFG}/hue_key.json")
    if saved and saved.get("username"):
        return saved["username"]
    return hue_pair(host)


def hue_state(host, key):
    lights = http(f"http://{host}/api/{key}/lights")
    groups = http(f"http://{host}/api/{key}/groups")
    scenes = http(f"http://{host}/api/{key}/scenes")
    if isinstance(lights, list):  # an error payload, not a dict of lights
        raise RuntimeError(f"hue error: {lights}")
    out_l = {}
    for lid, l in lights.items():
        s = l.get("state", {})
        out_l[lid] = {"name": l.get("name"), "type": l.get("type"),
                      "on": s.get("on"), "bri": s.get("bri"),
                      "ct": s.get("ct"), "xy": s.get("xy"),
                      "reachable": s.get("reachable")}
    out_g = {}
    for gid, g in groups.items():
        out_g[gid] = {"name": g.get("name"), "type": g.get("type"),
                      "class": g.get("class"), "lights": g.get("lights", []),
                      "any_on": g.get("state", {}).get("any_on"),
                      "all_on": g.get("state", {}).get("all_on")}
    out_s = {sid: {"name": s.get("name"), "group": s.get("group")}
             for sid, s in (scenes or {}).items() if s.get("group")}
    return {"lights": out_l, "groups": out_g, "scenes": out_s}


def hue_apply(host, key, cmd):
    """cmd: {target: 'light'|'group', id: '3', on: bool, bri: 0-254, scene: id}"""
    tgt = cmd.get("target", "light")
    cid = str(cmd.get("id"))
    body = {}
    if "on" in cmd:
        body["on"] = bool(cmd["on"])
    if "bri" in cmd and cmd["bri"] is not None:
        body["bri"] = max(1, min(254, int(cmd["bri"])))
        body["on"] = True
    if "ct" in cmd and cmd["ct"] is not None:
        body["ct"] = int(cmd["ct"])
    if cmd.get("scene"):
        body = {"scene": cmd["scene"]}
    if tgt == "group":
        return http(f"http://{host}/api/{key}/groups/{cid}/action", "PUT", body)
    return http(f"http://{host}/api/{key}/lights/{cid}/state", "PUT", body)


# ------------------------------------------------------- ikea dirigera

DIRIGERA_PORT = 8443


def _dctx():
    """The hub serves a self-signed cert on its own LAN address, so verification
    would fail by design. We are pinned to a fixed private IP either way."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def dhttp(host, path, method="GET", token=None, body=None, form=None, timeout=10):
    url = f"https://{host}:{DIRIGERA_PORT}/v1{path}"
    headers, data = {}, None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=_dctx()) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else None


def dirigera_pair(host):
    """DIRIGERA replaced Tradfri's CoAP with HTTPS and an OAuth-style handshake.
    There is no security code on this generation - you press the action button
    on the underside of the hub while the token exchange is retrying.

    A fresh authorisation code is fetched every round. The hub expires them in
    well under a minute, so one code cannot span a long wait - holding a single
    code is what produced "Pairing request timed out" then "Invalid
    authorization code" on the first attempt.
    """
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "_-"
    print("[dirigera] PRESS THE ACTION BUTTON on the underside of the hub", flush=True)
    last = None
    deadline = time.time() + 300
    while time.time() < deadline:
        verifier = "".join(secrets.choice(alphabet) for _ in range(128))
        q = urllib.parse.urlencode({"audience": "homesmart.local",
                                    "response_type": "code",
                                    "code_challenge": verifier,
                                    "code_challenge_method": "S256"})
        try:
            code = dhttp(host, "/oauth/authorize?" + q)["code"]
        except Exception as exc:
            print(f"[dirigera] authorize failed: {exc}", flush=True)
            time.sleep(3)
            continue
        # keep each round short: the code dies in seconds, so the useful
        # pattern is fresh-code-then-immediately-exchange, repeated quickly
        for _ in range(2):
            if time.time() > deadline:
                break
            try:
                tok = dhttp(host, "/oauth/token", "POST", form={
                    "code": code, "name": "powerwall-dashboard",
                    "grant_type": "authorization_code", "code_verifier": verifier})
                if tok and tok.get("access_token"):
                    jwrite(f"{CFG}/dirigera_token.json", {"token": tok["access_token"]})
                    print("[dirigera] paired, token saved", flush=True)
                    return tok["access_token"]
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode()[:160]
                except Exception:
                    pass
                msg = f"HTTP {exc.code} {body}"
                if msg != last:
                    print(f"[dirigera] waiting: {msg}", flush=True)
                    last = msg
                if exc.code == 401:
                    break  # this code is dead, go round and get a fresh one
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"
                if msg != last:
                    print(f"[dirigera] waiting: {msg}", flush=True)
                    last = msg
            time.sleep(2)
    raise RuntimeError(f"pairing timed out. Last reply from hub: {last}")


def dirigera_token(host):
    saved = jread(f"{CFG}/dirigera_token.json")
    if saved and saved.get("token"):
        return saved["token"]
    return dirigera_pair(host)


def dirigera_state(host, token):
    out = {}
    seen = {}
    for d in dhttp(host, "/devices", token=token) or []:
        if d.get("deviceType") != "light" and d.get("type") != "light":
            continue
        a = d.get("attributes", {})
        room = (d.get("room") or {}).get("name")
        # Most of these bulbs were never named in the IKEA app, so customName
        # is empty and all 34 of them would render as an identical
        # "TRADFRI bulb GU10 WW 400lm". Number them within their room so they
        # can actually be told apart on the dashboard.
        seen[room] = seen.get(room, 0) + 1
        model = (a.get("model") or "light").replace("TRADFRI bulb ", "")
        out[d.get("id")] = {"name": a.get("customName") or (model + " " + str(seen[room])),
                            "on": a.get("isOn"), "bri": a.get("lightLevel"),
                            "reachable": bool(d.get("isReachable", True)),
                            "room": room}
    return out


def dirigera_apply(host, token, cmd):
    attrs = {}
    if "on" in cmd:
        attrs["isOn"] = bool(cmd["on"])
    if cmd.get("bri") is not None:
        attrs["lightLevel"] = max(1, min(100, int(cmd["bri"])))
        attrs["isOn"] = True
    return dhttp(host, f"/devices/{cmd['id']}", "PATCH", token=token,
                 body=[{"attributes": attrs}])


# ------------------------------------------------------------- holiday mode

LAT = float(os.environ.get("HOME_LAT", "53.4"))
LON = float(os.environ.get("HOME_LON", "-2.6"))
HOL_FILE = f"{CFG}/holiday.json"
DUSK_LEAD = 1200  # switch on 20 min before sunset, as a real household does

_hol = {"on": False, "cur": None, "until": 0.0, "bedtime": 0.0,
        "day": None, "lit": [], "recent": [], "why": "idle"}


def sun_epoch(lat, lon, ts):
    """Sunrise/sunset as epoch seconds for the UTC day containing ts.

    Epoch-based on purpose: comparing darkness in epoch seconds sidesteps the
    local-versus-UTC confusion that has caused real bugs in this project.
    """
    g = time.gmtime(ts)
    gamma = 2 * math.pi / 365.0 * (g.tm_yday - 1 + (g.tm_hour - 12) / 24.0)
    eqtime = 229.18 * (0.000075 + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma)
                       - 0.014615 * math.cos(2 * gamma) - 0.040849 * math.sin(2 * gamma))
    decl = (0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
            - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)
            - 0.002697 * math.cos(3 * gamma) + 0.00148 * math.sin(3 * gamma))
    latr = math.radians(lat)
    cosha = (math.cos(math.radians(90.833)) / (math.cos(latr) * math.cos(decl))
             - math.tan(latr) * math.tan(decl))
    if cosha > 1 or cosha < -1:
        return None, None
    ha = math.degrees(math.acos(cosha))
    midnight = calendar.timegm((g.tm_year, g.tm_mon, g.tm_mday, 0, 0, 0, 0, 0, 0))
    return (midnight + (720 - 4 * (lon + ha) - eqtime) * 60,
            midnight + (720 - 4 * (lon - ha) - eqtime) * 60)


def is_dark(ts):
    rise, sett = sun_epoch(LAT, LON, ts)
    if rise is None:
        return True
    return ts > (sett - DUSK_LEAD) or ts < rise


def evening_window(ts):
    """Dusk-to-bedtime only.

    Darkness alone is not enough: at 00:30 it is pitch dark and technically
    before tonight's bedtime, which would light the whole house at half
    midnight. Anything before midday belongs to the previous night's session,
    which has already finished.
    """
    return is_dark(ts) and time.localtime(ts).tm_hour >= 12


WEIGHTS = [
    (("kitchen", "lounge", "living", "dining", "dinning", "snug", "family"), 5),
    (("hall", "landing", "stair", "study", "extension", "games", "den"), 2),
    (("toilet", "bath", "shower", "wc", "utility"), 1),
    (("bedroom", "bed"), 1),
]


def weight_for(name):
    n = (name or "").lower()
    for words, w in WEIGHTS:
        if any(x in n for x in words):
            return w
    return 2


def pick_next(rooms, current, rnd, recent=()):
    """Weighted pick, avoiding the current room and damping recent ones.

    Without the recent damping the chain ping-pongs between the two heaviest
    rooms - lounge, kitchen, lounge, kitchen - which reads as machine generated
    rather than as somebody moving around a house.
    """
    pool = [r for r in rooms if r != current] or list(rooms)
    weights = []
    for r in pool:
        w = float(weight_for(r[2]))
        if r in recent:
            w /= (3.0 - list(recent).index(r) * 0.7)
        weights.append(max(w, 0.15))
    return rnd.choices(pool, weights=weights, k=1)[0]


def bedtime_for(ts, rnd):
    """Randomised lights-out between 22:30 and 23:45 local."""
    lt = time.localtime(ts)
    mins = 22 * 60 + 30 + rnd.randrange(0, 76)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                        mins // 60, mins % 60, 0, 0, 0, -1))


def rooms_from(state):
    """Every room across both hubs, as (hub, id, name)."""
    out = []
    for gid, g in ((state.get("hue") or {}).get("groups") or {}).items():
        if g.get("type") == "Room" and (g.get("lights") or []):
            out.append(("hue", gid, g.get("name") or ("Room " + gid)))
    seen = set()
    for d in (state.get("ikea") or {}).values():
        r = d.get("room")
        if r and r not in seen:
            seen.add(r)
            out.append(("ikea", r, r))
    return out


def hol_load():
    _hol["on"] = bool((jread(HOL_FILE) or {}).get("on"))


def hol_save():
    jwrite(HOL_FILE, {"on": _hol["on"]})


def hol_apply(room, on, ctx):
    kind, ident, _ = room
    if kind == "hue":
        hue_apply(ctx["host"], ctx["key"], {"target": "group", "id": ident, "on": on})
    elif ctx["dst"].get("token"):
        for did, d in (ctx["ikea"] or {}).items():
            if d.get("room") == ident:
                dirigera_apply(ctx["dhost"], ctx["dst"]["token"], {"id": did, "on": on})


def hol_all_off(ctx):
    for room in list(_hol["lit"]):
        try:
            hol_apply(room, False, ctx)
        except Exception as exc:
            print(f"[holiday] could not switch off {room[2]}: {exc}", flush=True)
    _hol["lit"] = []
    _hol["cur"] = None


def hol_tick(state, ctx):
    now = time.time()
    if not _hol["on"]:
        if _hol["lit"]:
            hol_all_off(ctx)
            _hol["why"] = "switched off"
        else:
            _hol["why"] = "off"
        return
    rooms = rooms_from(state)
    if not rooms:
        _hol["why"] = "no rooms visible"
        return

    today = time.strftime("%Y-%m-%d", time.localtime(now))
    if _hol["day"] != today:
        _hol["day"] = today
        _hol["bedtime"] = bedtime_for(now, random)

    if not evening_window(now):
        if _hol["lit"]:
            hol_all_off(ctx)
        _hol["why"] = "waiting for dusk"
        return
    if now >= _hol["bedtime"]:
        if _hol["lit"]:
            hol_all_off(ctx)
            print("[holiday] bedtime - all off", flush=True)
        _hol["why"] = "after bedtime"
        return
    if now < _hol["until"]:
        _hol["why"] = "in " + (_hol["cur"][2] if _hol["cur"] else "?")
        return

    nxt = pick_next(rooms, _hol["cur"], random, tuple(_hol["recent"]))
    # Occasionally leave the previous room on so two overlap - a real house
    # often has the kitchen and lounge lit together, and strict
    # one-room-at-a-time is its own kind of tell.
    overlap = _hol["cur"] is not None and len(_hol["lit"]) < 2 and random.random() < 0.35
    if _hol["cur"] is not None and not overlap:
        hol_apply(_hol["cur"], False, ctx)
        if _hol["cur"] in _hol["lit"]:
            _hol["lit"].remove(_hol["cur"])
    hol_apply(nxt, True, ctx)
    if nxt not in _hol["lit"]:
        _hol["lit"].append(nxt)
    while len(_hol["lit"]) > 2:
        oldest = _hol["lit"].pop(0)
        if oldest != nxt:
            hol_apply(oldest, False, ctx)
    _hol["cur"] = nxt
    _hol["recent"].insert(0, nxt)
    del _hol["recent"][3:]
    _hol["until"] = now + random.randrange(8 * 60, 35 * 60)
    _hol["why"] = "in " + nxt[2]
    print(f"[holiday] {nxt[2]} for {int((_hol['until'] - now) / 60)} min", flush=True)


def hol_status():
    rise, sett = sun_epoch(LAT, LON, time.time())
    return {"on": _hol["on"], "why": _hol["why"],
            "room": _hol["cur"][2] if _hol["cur"] else None,
            "lit": [r[2] for r in _hol["lit"]],
            "bedtime": int(_hol["bedtime"]) if _hol["bedtime"] else None,
            "sunset": int(sett) if sett else None,
            "sunrise": int(rise) if rise else None}

# ----------------------------------------------------------------- r2

def r2():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{ACCOUNT}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def put(s3, key, obj):
    s3.put_object(Bucket=BUCKET, Key=key,
                  Body=json.dumps(obj).encode(), ContentType="application/json")


def take_command(s3):
    """Read and immediately clear the queue, so a command runs at most once."""
    try:
        o = s3.get_object(Bucket=BUCKET, Key=CMD_OBJ)
        body = json.loads(o["Body"].read().decode())
    except Exception:
        return None
    if not body or not body.get("cmds"):
        return None
    try:
        put(s3, CMD_OBJ, {"cmds": [], "t": int(time.time())})
    except Exception as exc:
        print(f"[cmd] could not clear queue, skipping to avoid a repeat: {exc}", flush=True)
        return None
    return body["cmds"]


def main():
    load_env("/cfg-r2/vaillant.env")
    load_env(f"{CFG}/lights.env")

    host = HUE_HOST or os.environ.get("HUE_HOST", "")
    if not host:
        raise SystemExit("HUE_HOST not set")
    key = hue_key(host)
    dhost = os.environ.get("DIRIGERA_HOST") or os.environ.get("TRADFRI_HOST", "")
    # Pairing must never gate the Hue loop. An unpaired hub once spun in
    # authorize retries for minutes before the loop even started, which starved
    # the state push and left the dashboard stale while Hue itself was
    # perfectly healthy. So: only ever adopt a token that already exists, and
    # run pairing off the hot path, in a daemon thread, and only when asked for
    # by dropping a pair_dirigera flag file next to the config.
    _saved = jread(f"{CFG}/dirigera_token.json") or {}
    dst = {"token": _saved.get("token")}
    _flag = f"{CFG}/pair_dirigera"
    if dhost and not dst["token"] and os.path.exists(_flag):
        def _pair():
            try:
                dst["token"] = dirigera_pair(dhost)
            except Exception as exc:
                print(f"[dirigera] pairing failed: {exc}", flush=True)
            finally:
                try:
                    os.remove(_flag)
                except OSError:
                    pass
        threading.Thread(target=_pair, daemon=True).start()
    elif dhost and not dst["token"]:
        print("[dirigera] not paired; skipping. Touch /cfg/pair_dirigera and "
              "restart to pair.", flush=True)

    hol_load()
    print(f"[holiday] mode is {'on' if _hol['on'] else 'off'} at start", flush=True)

    s3 = r2()
    last_push = 0.0
    while True:
        try:
            cmds = take_command(s3)
            if cmds:
                for c in cmds:
                    try:
                        if c.get("target") == "holiday":
                            _hol["on"] = bool(c.get("on"))
                            hol_save()
                            print(f"[holiday] switched {'on' if _hol['on'] else 'off'}", flush=True)
                        elif c.get("hub") == "ikea" and dst["token"]:
                            dirigera_apply(dhost, dst["token"], c)
                        else:
                            hue_apply(host, key, c)
                        print(f"[cmd] {c}", flush=True)
                    except Exception as exc:
                        print(f"[cmd] FAILED {c}: {exc}", flush=True)
                last_push = 0.0  # push new state straight away

            if time.time() - last_push >= PUSH_EVERY:
                state = {"t": int(time.time()), "hue": hue_state(host, key)}
                if dhost and dst["token"]:
                    try:
                        state["ikea"] = dirigera_state(dhost, dst["token"])
                    except Exception as exc:
                        state["ikea_error"] = str(exc)[:160]
                        # log it too - storing it only in the payload meant a
                        # failing hub leg looked like a healthy silent container
                        print(f"[ikea] {type(exc).__name__}: {exc}", flush=True)
                try:
                    hol_tick(state, {"host": host, "key": key, "dhost": dhost,
                                     "dst": dst, "ikea": state.get("ikea")})
                except Exception as exc:
                    print(f"[holiday] {type(exc).__name__}: {exc}", flush=True)
                state["holiday"] = hol_status()
                put(s3, STATE_OBJ, state)
                last_push = time.time()
        except Exception as exc:
            print(f"[loop] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
