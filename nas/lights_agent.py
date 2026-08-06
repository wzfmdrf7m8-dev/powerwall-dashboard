#!/usr/bin/env python3
"""
Lighting agent — Hue + IKEA Tradfri, bridged to R2.

Both hubs are LAN-only, so the Cloudflare Worker cannot reach either one. This
runs on the NAS: it reads state and pushes it to R2 for the dashboard, and it
polls R2 for commands the dashboard has queued and executes them locally.

Secrets never pass through the repo:
  /cfg-r2/vaillant.env   R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY   (shared)
  /cfg/lights.env        TRADFRI_HOST, TRADFRI_CODE
  /cfg/hue_key.json      written by this script on first pairing
  /cfg/tradfri_psk.json  written by this script on first pairing

The Hue key is minted here rather than pasted in, so it never travels through a
chat log or a config file anyone has to copy by hand.
"""

import asyncio
import json
import os
import sys
import time
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


# ------------------------------------------------------------ tradfri

def tradfri_creds():
    """Config only. The connection itself is made per poll, inside asyncio."""
    host = os.environ.get("TRADFRI_HOST", "")
    code = os.environ.get("TRADFRI_CODE", "")
    if not host or not code:
        return None
    return {"host": host, "code": code, "saved": jread(f"{CFG}/tradfri_psk.json")}


async def _tradfri_async(creds):
    """aiocoap backend, deliberately not libcoap.

    libcoap shells out to a coap-client binary that Debian's slim image does not
    carry and that no obvious package provides on arm64. aiocoap is pure Python
    and installs cleanly, so there is nothing extra to build or find at runtime.
    """
    from pytradfri import Gateway
    from pytradfri.api.aiocoap_api import APIFactory

    host, saved = creds["host"], creds["saved"]
    if saved:
        factory = await APIFactory.init(host, psk_id=saved["identity"], psk=saved["psk"])
    else:
        ident = f"pwdash-{int(time.time())}"
        factory = await APIFactory.init(host, psk_id=ident)
        psk = await factory.generate_psk(creds["code"])
        jwrite(f"{CFG}/tradfri_psk.json", {"identity": ident, "psk": psk})
        creds["saved"] = {"identity": ident, "psk": psk}
        print("[tradfri] paired, psk saved", flush=True)
    try:
        api = factory.request
        gw = Gateway()
        devices = await api(await api(gw.get_devices()))
        out = {}
        for d in devices:
            if not getattr(d, "has_light_control", False):
                continue
            lc = d.light_control.lights[0]
            out[str(d.id)] = {"name": d.name, "on": lc.state,
                              "bri": lc.dimmer, "reachable": bool(d.reachable)}
        return out
    finally:
        await factory.shutdown()


def tradfri_state(creds):
    return asyncio.run(_tradfri_async(creds))


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
    creds = tradfri_creds()

    s3 = r2()
    last_push = 0.0
    while True:
        try:
            cmds = take_command(s3)
            if cmds:
                for c in cmds:
                    try:
                        hue_apply(host, key, c)
                        print(f"[cmd] {c}", flush=True)
                    except Exception as exc:
                        print(f"[cmd] FAILED {c}: {exc}", flush=True)
                last_push = 0.0  # push new state straight away

            if time.time() - last_push >= PUSH_EVERY:
                state = {"t": int(time.time()), "hue": hue_state(host, key)}
                if creds:
                    try:
                        state["tradfri"] = tradfri_state(creds)
                    except Exception as exc:
                        state["tradfri_error"] = str(exc)[:160]
                put(s3, STATE_OBJ, state)
                last_push = time.time()
        except Exception as exc:
            print(f"[loop] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
