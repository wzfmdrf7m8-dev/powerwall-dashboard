#!/usr/bin/env python3
"""
Mint myVAILLANT tokens from a residential IP and publish them to Cloudflare R2.

Why this exists
---------------
Vaillant's WAF returns 403 on identity.vaillant-group.com for datacentre IPs —
Cloudflare Workers and GitHub Actions runners both get blocked. On 2026-07-22
Vaillant also added ALTCHA (proof-of-work anti-bot) to the Keycloak login form,
which killed the plain form-post login the GitHub Action was doing.

api.vaillant-group.com is NOT blocked. So only the *login* has to happen from a
residential connection. This job runs on the NAS, logs in via myPyllant (which
handles ALTCHA upstream), and drops the resulting tokens into R2 as vailtok.json.
The Cloudflare Worker adopts them from there and keeps refreshing as before —
nothing else about the worker changes.

Credentials are read from the environment only. Never commit them.
"""

import asyncio
import json
import os
import sys
import time

import boto3
from botocore.config import Config
from myPyllant.api import MyPyllantAPI

R2_ACCOUNT = os.environ["R2_ACCOUNT_ID"]
R2_BUCKET = os.environ.get("R2_BUCKET", "powerwall-data")
R2_OBJECT = os.environ.get("R2_OBJECT", "vailtok.json")
INTERVAL = int(os.environ.get("INTERVAL_SECONDS", "3600"))  # background floor
REQ_OBJECT = os.environ.get("R2_REQ_OBJECT", "vailmint.json")
CHECK = int(os.environ.get("CHECK_SECONDS", "45"))
# Never log in more often than this when responding to requests. The worker
# re-asks every couple of minutes while it is broken, and Vaillant's WAF is
# not something to poke hundreds of times a day.
MIN_GAP = int(os.environ.get("MIN_ONDEMAND_GAP", "300"))

BRAND = os.environ.get("VAILLANT_BRAND", "vaillant")
COUNTRY = os.environ.get("VAILLANT_COUNTRY", "unitedkingdom")


def extract(api):
    """Pull the token payload out of the library session.

    myPyllant does not document these attributes, so fail loudly and print what
    IS available rather than silently writing a malformed vailtok.json — a bad
    token file is worse than no token file, because the worker will adopt it.
    """
    session = getattr(api, "oauth_session", None)
    if not isinstance(session, dict):
        raise SystemExit(
            f"oauth_session is {type(session).__name__}, expected dict. "
            f"Available attrs: {[a for a in dir(api) if 'token' in a or 'session' in a]}"
        )

    access = session.get("access_token")
    refresh = session.get("refresh_token")
    if not access:
        raise SystemExit(f"no access_token in oauth_session. Keys present: {sorted(session)}")
    if not refresh:
        print(
            "WARNING: no refresh_token returned. The worker will only stay "
            "authenticated until this access token expires.",
            file=sys.stderr,
        )

    now = time.time()
    expires_at = getattr(api, "oauth_session_expires", None)
    if hasattr(expires_at, "timestamp"):
        exp = int(expires_at.timestamp()) - 60
    else:
        exp = int(now + int(session.get("expires_in", 300)) - 60)

    # shape must match what worker.js vaillantToken() reads from vailtok.json
    return {"t": int(now), "access": access, "refresh": refresh, "exp": exp}


async def mint():
    email = os.environ["MYVAILLANT_EMAIL"]
    password = os.environ["MYVAILLANT_PASSWORD"]
    async with MyPyllantAPI(email, password, BRAND, COUNTRY) as api:
        return extract(api)


def s3client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def publish(token, s3=None):
    (s3 or s3client()).put_object(
        Bucket=R2_BUCKET,
        Key=R2_OBJECT,
        Body=json.dumps(token).encode(),
        ContentType="application/json",
    )


def mint_requested(s3, since):
    """The worker drops a flag in R2 when its token chain has died.

    Minting on demand beats simply polling faster: recovery drops from hours to
    about a minute, without logging in to Vaillant hundreds of times a day.
    """
    try:
        o = s3.get_object(Bucket=R2_BUCKET, Key=REQ_OBJECT)
        body = json.loads(o["Body"].read().decode())
    except Exception:
        return None
    return body if int(body.get("want") or 0) > since else None


def stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def run_once(s3=None):
    token = asyncio.run(mint())
    publish(token, s3)
    print(
        f"[{stamp()}] minted -> r2://{R2_BUCKET}/{R2_OBJECT} "
        f"(refresh_token: {'yes' if token['refresh'] else 'NO'}, "
        f"access expires in {token['exp'] - int(time.time())}s)",
        flush=True,
    )


if __name__ == "__main__":
    if "--once" in sys.argv:
        run_once()
        sys.exit(0)

    s3 = s3client()
    last = 0.0
    # ignore any request left over from before this process started
    handled = int(time.time())
    fails = 0
    while True:
        now = time.time()
        due = now - last >= INTERVAL
        req = None
        if not due and now - last >= MIN_GAP * min(2 ** fails, 8):
            req = mint_requested(s3, handled)
        if due or req:
            if req:
                print(f"[{stamp()}] mint requested: {str(req.get('why'))[:80]}", flush=True)
            try:
                run_once(s3)
                last = time.time()
                fails = 0
            except Exception as exc:  # keep the loop alive across transient failures
                fails += 1
                last = time.time() if due else last
                print(f"[{stamp()}] MINT FAILED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            finally:
                # mark the request seen either way, so a failure cannot spin
                handled = int(time.time())
        time.sleep(CHECK)
