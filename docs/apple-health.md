# Apple Health → dashboard

Adds the **❤️ Health** pill, fed by HealthKit data pushed from the iPhone.

## Why it needs an app on the phone

HealthKit is a device-local framework. There is no server API, no OAuth flow, no
cloud endpoint — health data can only leave the device from an app running on it
with explicit per-type consent. So the pill is only live while something on the
phone is actively pushing; that is a property of Apple's design, not a choice.

## Architecture

```
iPhone (Health Auto Export, hourly)
  └─ POST /hk/ingest        x-api-key: HK_TOKEN
       └─ R2  hk/raw/<iso>-<rand>.ndjson      append-only, never mutated
            └─ every-minute cron: hkFold()
                 ├─ R2  hk/state.json          daily accumulator
                 ├─ R2  hk/cursor.json         last folded batch
                 └─ R2  hk.enc                 AES-CBC bundle the page reads
                      └─ GET /hk  →  fitness.html  (decrypts with the dashboard password)
```

Writes are append-only so two overlapping syncs cannot corrupt state. The fold is
single-threaded on the cron, which is what makes the merge safe without a lock.

## Setup

1. **Generate a token** and add it as the GitHub secret `HK_TOKEN`:

   ```
   openssl rand -hex 32
   ```

   Push to `main` — `deploy-worker` pushes it to the worker as a secret.

2. **On the iPhone**, install *Health Auto Export*, then
   **Automations → Add Automation → REST API**:

   | Setting | Value |
   | --- | --- |
   | URL | `https://powerwall-api.randlefamily.com/hk/ingest` |
   | Header | `x-api-key: <your HK_TOKEN>` |
   | Format | JSON |
   | Aggregation | Hourly |
   | Date range | Since Last Sync |
   | Frequency | every 1 hour |
   | Batch requests | on |

   Select Activity, Heart, Sleep, Body and Workouts. Anything not in the registry
   is still kept, under a derived name.

3. **Backfill your history** (optional, one-off). Export from the Health app:
   profile picture → *Export All Health Data*.

   ```
   node pipeline/health-backfill.mjs ~/Downloads/export.zip \
        --url https://powerwall-api.randlefamily.com \
        --token "$HK_TOKEN"
   ```

   The export is streamed and reduced to one value per metric per day before
   anything is sent, so a multi-GB file becomes a few MB.

## Behaviour

- **Fresh** (synced < 6 h): green badge with the time of the last push.
- **Stale** (6–48 h): amber badge, data still shown.
- **Stopped** (> 48 h, or never): red badge, last-known figures still shown, plus
  the setup steps as a fault guide.

## Correctness notes

- **Day bucketing** uses the local date in the timestamp, not UTC — otherwise
  late-evening activity lands on the wrong day.
- **Sleep** is attributed to the day it *ended*, matching the Health app. Time
  asleep is the sum of core + deep + REM (+ any unspecified), not the in-bed span.
- **Replays are safe.** Cumulative metrics (steps, energy, distance) are keyed by
  hour stamp, so a redelivered hour replaces its previous value rather than adding
  to it. Batches are additionally deduplicated by content hash, since Health Auto
  Export retries on timeout. Means are naturally replay-safe.
- **Units** are normalised to metric/SI on the way in, so a historical backfill in
  imperial and a live sync in metric agree.
- **Direction awareness**: a falling resting heart rate is rendered as an
  improvement, not a decline. Same for body fat, waist and awake-in-bed.
- `/hk/rebuild` replays every raw batch from scratch. It is resumable — if it
  times out, call it again and it continues from the cursor.

## Files

| Path | What it is |
| --- | --- |
| `worker/src/health.js` | ingest, registry, accumulator, bundle builder |
| `worker/src/worker.js` | routes `/hk`, `/hk/ingest`, `/hk/rebuild` + cron fold |
| `fitness.html` | the Health pill |
| `pipeline/health-backfill.mjs` | one-off `export.xml` import |
