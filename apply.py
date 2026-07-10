#!/usr/bin/env python3
"""Powerwall poller + automation engine. Runs in GitHub Actions.

Env vars:
  TESLA_CLIENT_ID      app client id
  TESLA_REFRESH_TOKEN  bootstrap refresh token (repo secret; used if no state file)
  DASH_PASSWORD        passphrase for encrypting dashboard data + token state
  COMMAND, VALUE       optional manual command (reserve|mode|storm|poll)

Reads automations.json, applies rules, writes encrypted bundle to data/dashboard.enc
and rotated refresh token to state/refresh.enc.
"""
import base64
import datetime
import json
import os
import sys
import zoneinfo

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

API = "https://fleet-api.prd.eu.vn.cloud.tesla.com"
TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
CLIENT_ID = os.environ["TESLA_CLIENT_ID"]
PASSWORD = os.environ["DASH_PASSWORD"].encode()
COMMAND = os.environ.get("COMMAND", "").strip()
VALUE = os.environ.get("VALUE", "").strip()

ITERATIONS = 200_000


# ---------- crypto (format: b64(salt16 | iv16 | aes256cbc(pkcs7(data)))) ----------

def _key(salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS).derive(PASSWORD)


def encrypt(data: bytes) -> str:
    salt, iv = os.urandom(16), os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(_key(salt)), modes.CBC(iv)).encryptor()
    return base64.b64encode(salt + iv + enc.update(padded) + enc.finalize()).decode()


def decrypt(b64: str) -> bytes:
    raw = base64.b64decode(b64)
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    dec = Cipher(algorithms.AES(_key(salt)), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------- token rotation ----------

def get_tokens() -> dict:
    candidates = []
    if os.path.exists("state/refresh.enc"):
        try:
            candidates.append(decrypt(open("state/refresh.enc").read()).decode())
        except Exception as e:
            print(f"state decrypt failed: {e}", file=sys.stderr)
    if os.environ.get("TESLA_REFRESH_TOKEN"):
        candidates.append(os.environ["TESLA_REFRESH_TOKEN"])
    last_err = None
    for rt in candidates:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": rt})
        if r.ok and "access_token" in r.json():
            tokens = r.json()
            os.makedirs("state", exist_ok=True)
            open("state/refresh.enc", "w").write(encrypt(tokens["refresh_token"].encode()))
            return tokens
        last_err = r.text[:200]
    sys.exit(f"token refresh failed: {last_err}")


# ---------- api helpers ----------

def api(tok, method, path, **kw):
    r = requests.request(method, API + path,
                         headers={"Authorization": f"Bearer {tok}"}, **kw)
    r.raise_for_status()
    return r.json().get("response")


def fetch_octopus(key: str, acct: str, now) -> dict:
    """Pull meter points, half-hourly consumption and unit rates from Octopus."""
    s = requests.Session()
    s.auth = (key, "")
    base = "https://api.octopus.energy/v1"
    account = s.get(f"{base}/accounts/{acct}/", timeout=30).json()
    start = (now - datetime.timedelta(days=3)).isoformat()
    out = {}
    for prop in account.get("properties", []):
        for mp in prop.get("electricity_meter_points", []):
            kind = "export" if mp.get("is_export") else "import"
            mpan = mp.get("mpan")
            serial = None
            for m in mp.get("meters", []):
                if m.get("serial_number"):
                    serial = m["serial_number"]
            tariff = None
            for ag in mp.get("agreements", []):
                vt = ag.get("valid_to")
                if vt is None or vt > now.isoformat():
                    tariff = ag.get("tariff_code")
            cons, rates = [], []
            if serial:
                r = s.get(f"{base}/electricity-meter-points/{mpan}/meters/{serial}/consumption/",
                          params={"period_from": start, "page_size": 200, "order_by": "period"}, timeout=30)
                if r.ok:
                    cons = r.json().get("results", [])
            if tariff:
                product = "-".join(tariff.split("-")[2:-1])
                r = s.get(f"{base}/products/{product}/electricity-tariffs/{tariff}/standard-unit-rates/",
                          params={"period_from": start, "page_size": 200}, timeout=30)
                if r.ok:
                    rates = r.json().get("results", [])
            out[kind] = {"mpan": mpan, "tariff": tariff, "consumption": cons, "rates": rates}
    return out


def main():
    tokens = get_tokens()
    tok = tokens["access_token"]
    log = []

    products = api(tok, "GET", "/api/1/products")
    sites = [p for p in products if "energy_site_id" in p]
    if not sites:
        sys.exit("no energy sites")
    site = str(sites[0]["energy_site_id"])

    cfg = json.load(open("automations.json"))
    tz = zoneinfo.ZoneInfo(cfg.get("timezone", "Europe/London"))
    now = datetime.datetime.now(tz)

    site_info = api(tok, "GET", f"/api/1/energy_sites/{site}/site_info")
    live = api(tok, "GET", f"/api/1/energy_sites/{site}/live_status")

    def set_reserve(pct, why):
        if site_info.get("backup_reserve_percent") != pct:
            api(tok, "POST", f"/api/1/energy_sites/{site}/backup",
                json={"backup_reserve_percent": int(pct)})
            log.append(f"reserve -> {pct}% ({why})")

    def set_mode(mode, why):
        if site_info.get("default_real_mode") != mode:
            api(tok, "POST", f"/api/1/energy_sites/{site}/operation",
                json={"default_real_mode": mode})
            log.append(f"mode -> {mode} ({why})")

    def set_storm(enabled, why):
        if site_info.get("user_settings", {}).get("storm_mode_enabled") != enabled:
            api(tok, "POST", f"/api/1/energy_sites/{site}/storm_mode",
                json={"enabled": bool(enabled)})
            log.append(f"storm watch -> {enabled} ({why})")

    def set_grid_charging(allowed, why):
        cur = site_info.get("components", {}).get("disallow_charge_from_grid_with_solar_installed")
        want = not allowed
        if cur != want:
            api(tok, "POST", f"/api/1/energy_sites/{site}/grid_import_export",
                json={"disallow_charge_from_grid_with_solar_installed": want})
            log.append(f"grid charging allowed -> {allowed} ({why})")

    # ----- manual command takes priority -----
    if COMMAND and COMMAND != "poll":
        if COMMAND == "reserve":
            set_reserve(int(VALUE), "manual")
        elif COMMAND == "mode":
            set_mode(VALUE, "manual")
        elif COMMAND == "storm":
            set_storm(VALUE == "on", "manual")
        elif COMMAND == "grid_charging":
            set_grid_charging(VALUE == "on", "manual")
    elif cfg.get("enabled", True):
        # ----- scheduled automation -----
        cw = cfg.get("cheap_window", {})
        if cw.get("enabled"):
            start = datetime.datetime.strptime(cw["start"], "%H:%M").time()
            end = datetime.datetime.strptime(cw["end"], "%H:%M").time()
            t = now.time()
            in_window = (start <= t < end) if start < end else (t >= start or t < end)
            if in_window:
                set_reserve(cw.get("reserve", 100), "cheap window")
                set_mode(cw.get("mode", "self_consumption"), "cheap window")
                set_grid_charging(cw.get("allow_grid_charging", True), "cheap window")
            else:
                day = cfg.get("day", {})
                set_reserve(day.get("reserve", 20), "daytime")
                set_mode(day.get("mode", "self_consumption"), "daytime")
                set_grid_charging(day.get("allow_grid_charging", False), "daytime")
        if "storm_watch" in cfg:
            set_storm(cfg["storm_watch"], "config")

    # refresh site_info if we changed anything
    if log:
        site_info = api(tok, "GET", f"/api/1/energy_sites/{site}/site_info")

    # ----- history bundle -----
    hist = []
    if os.path.exists("data/dashboard.enc"):
        try:
            hist = json.loads(decrypt(open("data/dashboard.enc").read())).get("history", [])
        except Exception:
            pass
    hist.append({
        "t": now.isoformat(timespec="minutes"),
        "soc": live.get("percentage_charged"),
        "solar": live.get("solar_power"),
        "load": live.get("load_power"),
        "grid": live.get("grid_power"),
        "battery": live.get("battery_power"),
    })
    hist = hist[-700:]  # ~7 days at 15-min cadence

    end_d = now.date() + datetime.timedelta(days=1)
    start_d = now.date() - datetime.timedelta(days=30)
    try:
        energy = api(tok, "GET", f"/api/1/energy_sites/{site}/calendar_history", params={
            "kind": "energy", "period": "day",
            "start_date": f"{start_d}T00:00:00Z", "end_date": f"{end_d}T00:00:00Z",
            "time_zone": cfg.get("timezone", "Europe/London")})
    except Exception as e:
        energy = {"error": str(e)[:200]}

    # ----- Octopus Energy (optional) -----
    octopus = None
    okey, oacct = os.environ.get("OCTOPUS_API_KEY"), os.environ.get("OCTOPUS_ACCOUNT")
    if okey and oacct:
        try:
            octopus = fetch_octopus(okey, oacct, now)
        except Exception as e:
            octopus = {"error": str(e)[:200]}

    bundle = {
        "octopus": octopus,
        "generated_at": now.isoformat(timespec="seconds"),
        "site_name": sites[0].get("site_name"),
        "live": live,
        "site_info": {k: site_info.get(k) for k in (
            "backup_reserve_percent", "default_real_mode", "installation_date",
            "nameplate_power", "nameplate_energy", "battery_count", "user_settings",
            "components")},
        "energy_daily": (energy or {}).get("time_series", []),
        "history": hist,
        "automations": cfg,
        "log": log,
    }
    os.makedirs("data", exist_ok=True)
    open("data/dashboard.enc", "w").write(encrypt(json.dumps(bundle).encode()))
    print("ok:", ", ".join(log) if log else "no changes", "| soc:", live.get("percentage_charged"))


if __name__ == "__main__":
    main()
