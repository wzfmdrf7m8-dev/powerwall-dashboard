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
import json
import os
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
    for d in dhttp(host, "/devices", token=token) or []:
        if d.get("deviceType") != "light" and d.get("type") != "light":
            continue
        a = d.get("attributes", {})
        out[d.get("id")] = {"name": a.get("customName") or a.get("model"),
                            "on": a.get("isOn"), "bri": a.get("lightLevel"),
                            "reachable": bool(d.get("isReachable", True)),
                            "room": (d.get("room") or {}).get("name")}
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

    s3 = r2()
    last_push = 0.0
    while True:
        try:
            cmds = take_command(s3)
            if cmds:
                for c in cmds:
                    try:
                        if c.get("hub") == "ikea" and dst["token"]:
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
                put(s3, STATE_OBJ, state)
                last_push = time.time()
        except Exception as exc:
            print(f"[loop] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
