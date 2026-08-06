#!/usr/bin/env python3
"""
Home Connect agent - oven monitoring and control, bridged to R2.

Why events and not polling
--------------------------
Home Connect allows 1000 API requests per client+user per DAY. A full state
read costs 7 calls for two ovens, so even a five minute poll would exhaust the
budget by mid afternoon and get the client blocked. The documentation is
explicit: "do not query for state information but use the monitoring function
instead".

So this opens one Server-Sent Events stream per oven. Opening a stream costs a
single request; every update delivered over it afterwards is free. A full state
snapshot is taken once at startup and then kept current from the event stream.

Publishing to R2 and reading the command queue are not Home Connect calls, so
those can run as often as we like.

Secrets never pass through the repo:
  /cfg-r2/vaillant.env   R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY   (shared)
  /cfg/hcauth.json       written by the device-flow pairing, refreshed here
"""

import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3
from botocore.config import Config

API = "https://api.home-connect.com"
CFG = "/cfg"
AUTH = f"{CFG}/hcauth.json"
STATE_OBJ = os.environ.get("R2_OVEN_OBJECT", "ovens.json")
CMD_OBJ = os.environ.get("R2_OVEN_CMD", "ovencmd.json")
BUCKET = os.environ.get("R2_BUCKET", "powerwall-data")
ACCOUNT = os.environ["R2_ACCOUNT_ID"]
CMD_POLL = float(os.environ.get("CMD_POLL_SECONDS", "4"))
# the stream sends keep-alives, so silence for this long means it is dead
SSE_IDLE = float(os.environ.get("SSE_IDLE_SECONDS", "180"))

_lock = threading.Lock()
_state = {"t": 0, "ovens": {}}
_auth_lock = threading.Lock()


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


def token(force=False):
    """Return a valid access token, refreshing when it is close to expiry.

    Refreshes are themselves rate limited (100/day), and the refresh token does
    not rotate on this client, so we only refresh when genuinely needed.
    """
    with _auth_lock:
        a = jread(AUTH)
        if not a:
            raise SystemExit("no /cfg/hcauth.json - run the device flow pairing first")
        if not force and a.get("access") and time.time() < a.get("exp", 0):
            return a["access"]
        form = {"grant_type": "refresh_token", "refresh_token": a["refresh"]}
        req = urllib.request.Request(
            API + "/security/oauth/token",
            data=urllib.parse.urlencode(form).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
        a["access"] = r["access_token"]
        a["refresh"] = r.get("refresh_token") or a["refresh"]
        a["exp"] = int(time.time()) + int(r.get("expires_in", 86400)) - 300
        a["t"] = int(time.time())
        jwrite(AUTH, a)
        print(f"[auth] refreshed, valid {int(r.get('expires_in', 0)) // 3600}h", flush=True)
        return a["access"]


def api(path, method="GET", body=None):
    data = json.dumps({"data": body}).encode() if body is not None else None
    headers = {"Authorization": "Bearer " + token(),
               "Accept": "application/vnd.bsh.sdk.v1+json"}
    if data:
        headers["Content-Type"] = "application/vnd.bsh.sdk.v1+json"
    req = urllib.request.Request(API + "/api" + path, data=data, method=method,
                                 headers=headers)
    try:
        raw = urllib.request.urlopen(req, timeout=30).read().decode()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        payload = ""
        try:
            payload = e.read().decode()[:200]
        except Exception:
            pass
        if e.code == 401:
            # token died early - refresh once and let the caller retry
            token(force=True)
        raise RuntimeError(f"HTTP {e.code} {payload}")


def short(key):
    return key.split(".")[-1]


def snapshot():
    """One full read at startup. Seven calls for two ovens - the only polling
    this agent ever does."""
    out = {}
    for ap in api("/homeappliances").get("data", {}).get("homeappliances", []):
        if ap.get("type") != "Oven":
            continue
        hid = ap["haId"]
        o = {"name": ap.get("name"), "model": ap.get("vib"), "brand": ap.get("brand"),
             "connected": bool(ap.get("connected")), "status": {}, "settings": {},
             "program": None, "progress": None, "remaining": None, "events": {}}
        for path, bucket in (("/status", "status"), ("/settings", "settings")):
            try:
                for s in api(f"/homeappliances/{hid}{path}").get("data", {}).get(path[1:], []):
                    o[bucket][short(s["key"])] = s.get("value")
            except Exception as exc:
                print(f"[snap] {hid} {path}: {exc}", flush=True)
        try:
            d = api(f"/homeappliances/{hid}/programs/active").get("data", {})
            o["program"] = d.get("key")
            for opt in d.get("options", []):
                k = short(opt["key"])
                if k == "ProgramProgress":
                    o["progress"] = opt.get("value")
                elif k == "RemainingProgramTime":
                    o["remaining"] = opt.get("value")
        except Exception:
            o["program"] = None  # nothing running is the normal case
        out[hid] = o
    return out


def apply_event(hid, items):
    with _lock:
        o = _state["ovens"].get(hid)
        if not o:
            return
        for it in items:
            key = it.get("key", "")
            k = short(key)
            val = it.get("value")
            if k == "ProgramProgress":
                o["progress"] = val
            elif k == "RemainingProgramTime":
                o["remaining"] = val
            elif ".Status." in key:
                o["status"][k] = val
            elif ".Setting." in key:
                o["settings"][k] = val
            elif ".Event." in key:
                o["events"][k] = val
            elif k in ("SelectedProgram", "ActiveProgram"):
                o["program"] = val
            else:
                o["status"][k] = val
        _state["t"] = int(time.time())


def parse_sse(lines):
    """Yield (event, data) pairs from an SSE byte stream.

    Kept separate from the network code so the framing can actually be tested:
    multi-line data has to be concatenated, KEEP-ALIVE frames carry no data and
    must not be mistaken for state, and a frame is only complete on a blank
    line.
    """
    ev, data = None, []
    for raw in lines:
        line = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        line = line.rstrip("\r\n")
        if line.startswith(":"):
            continue  # comment / heartbeat
        if line.startswith("event:"):
            ev = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].strip())
        elif line == "":
            if ev:
                yield ev, "".join(data)
            ev, data = None, []
    if ev:
        yield ev, "".join(data)


def sse(hid, s3):
    """One monitoring channel per oven. Reconnects with backoff; each reconnect
    costs one request against the daily budget, so we do not thrash."""
    backoff = 5
    while True:
        try:
            req = urllib.request.Request(
                f"{API}/api/homeappliances/{hid}/events",
                headers={"Authorization": "Bearer " + token(),
                         "Accept": "text/event-stream"})
            with urllib.request.urlopen(req, timeout=SSE_IDLE) as r:
                print(f"[sse] {hid[:12]} connected", flush=True)
                backoff = 5
                for ev, payload in parse_sse(r):
                    if ev in ("STATUS", "NOTIFY", "EVENT"):
                        try:
                            apply_event(hid, json.loads(payload).get("items", []))
                            publish(s3)
                        except Exception as exc:
                            print(f"[sse] {hid[:12]} parse: {exc}", flush=True)
                    elif ev in ("CONNECTED", "DISCONNECTED"):
                        with _lock:
                            if hid in _state["ovens"]:
                                _state["ovens"][hid]["connected"] = (ev == "CONNECTED")
                            _state["t"] = int(time.time())
                        publish(s3)
        except Exception as exc:
            print(f"[sse] {hid[:12]} dropped: {type(exc).__name__}: {str(exc)[:90]}"
                  f" - retry in {backoff}s", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 600)


def r2():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{ACCOUNT}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def publish(s3):
    with _lock:
        body = json.dumps(_state).encode()
    try:
        s3.put_object(Bucket=BUCKET, Key=STATE_OBJ, Body=body,
                      ContentType="application/json")
    except Exception as exc:
        print(f"[r2] publish failed: {exc}", flush=True)


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
        s3.put_object(Bucket=BUCKET, Key=CMD_OBJ,
                      Body=json.dumps({"cmds": [], "t": int(time.time())}).encode(),
                      ContentType="application/json")
    except Exception as exc:
        print(f"[cmd] could not clear queue, skipping to avoid a repeat: {exc}", flush=True)
        return None
    return body["cmds"]


def run_command(c):
    """cmd: {haId, action: power|setting|select|start|stop, key, value}"""
    hid = c.get("haId")
    act = c.get("action")
    if not hid or not act:
        raise ValueError("haId and action required")
    if act == "power":
        val = ("BSH.Common.EnumType.PowerState.On" if c.get("value")
               else "BSH.Common.EnumType.PowerState.Standby")
        return api(f"/homeappliances/{hid}/settings/BSH.Common.Setting.PowerState",
                   "PUT", {"key": "BSH.Common.Setting.PowerState", "value": val})
    if act == "setting":
        return api(f"/homeappliances/{hid}/settings/{c['key']}", "PUT",
                   {"key": c["key"], "value": c["value"]})
    if act == "stop":
        return api(f"/homeappliances/{hid}/programs/active", "DELETE")
    if act == "start":
        # Guarded deliberately: this is an oven. The appliance itself must have
        # remote start armed, and Home Connect will refuse otherwise - but fail
        # early here with a clear message rather than a raw 409.
        with _lock:
            o = _state["ovens"].get(hid, {})
            st = o.get("status", {})
        if not st.get("RemoteControlStartAllowed"):
            raise RuntimeError("remote start not armed on the appliance")
        body = {"key": c["key"], "options": c.get("options", [])}
        return api(f"/homeappliances/{hid}/programs/active", "PUT", body)
    raise ValueError(f"unknown action {act}")


def main():
    load_env("/cfg-r2/vaillant.env")
    load_env(f"{CFG}/hc.env")
    s3 = r2()
    token()  # fail fast if pairing is missing or the refresh token is dead

    with _lock:
        _state["ovens"] = snapshot()
        _state["t"] = int(time.time())
    print(f"[boot] {len(_state['ovens'])} oven(s) found", flush=True)
    publish(s3)

    for hid in list(_state["ovens"]):
        threading.Thread(target=sse, args=(hid, s3), daemon=True).start()

    last_beat = 0.0
    while True:
        try:
            cmds = take_command(s3)
            for c in cmds or []:
                try:
                    run_command(c)
                    print(f"[cmd] ok {json.dumps(c)[:90]}", flush=True)
                except Exception as exc:
                    print(f"[cmd] FAILED {json.dumps(c)[:70]}: {exc}", flush=True)
            if cmds:
                publish(s3)
            # refresh the timestamp periodically so the dashboard can tell the
            # difference between "nothing changed" and "agent died"
            if time.time() - last_beat >= 60:
                with _lock:
                    _state["t"] = int(time.time())
                publish(s3)
                last_beat = time.time()
        except Exception as exc:
            print(f"[loop] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(CMD_POLL)


if __name__ == "__main__":
    main()
