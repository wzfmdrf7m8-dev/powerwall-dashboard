// Powerwall poller — Cloudflare Worker port of apply.py
// Cron: every minute. Storage: R2 (binding PW). Data served at /data, commands at /cmd.

const STANDING_FALLBACK = 66.38; // pence/day — from the Jun/Jul 2026 statement (66.38p/day)
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";
const TESLA_TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token";
// Ohme's Firebase web key lives in env.OHME_GOOGLE_KEY, not here. It is a public
// client identifier rather than a real secret, but keeping key-shaped strings out
// of the repo stops secret scanning alerts drowning out a genuine one later.
const REPO_RAW = "https://raw.githubusercontent.com/wzfmdrf7m8-dev/powerwall-dashboard";
const TZ = "Europe/London";
const HIST_MAX = 1600; // ~26h of minutes; older days are served from day_bins instead

const DEFAULT_CONFIG = {
  enabled: false,
  timezone: TZ,
  cheap_window: { enabled: true, start: "23:30", end: "05:30", reserve: 100, mode: "self_consumption", allow_grid_charging: true },
  day: { reserve: 0, mode: "self_consumption", allow_grid_charging: true },
  storm_watch: true,
  follow_ohme_slots: false,
};

/* ---------------- time helpers ---------------- */
// hoisted: constructing Intl.DateTimeFormat per call burns the Worker CPU budget
const LONDON_FMT = new Intl.DateTimeFormat("en-GB", {
  timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
});
function londonParts(d = new Date()) {
  const p = {};
  for (const { type, value } of LONDON_FMT.formatToParts(d)) p[type] = value;
  if (p.hour === "24") p.hour = "00";
  return p;
}
function localMinuteISO(d = new Date()) {
  const p = londonParts(d);
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
}
function localOffsetISO(d = new Date()) {
  // RFC3339 with London offset, for Tesla calendar_history
  const off = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, timeZoneName: "longOffset" })
    .formatToParts(d).find((x) => x.type === "timeZoneName").value; // "GMT+01:00" or "GMT"
  const m = off.match(/GMT([+-]\d{2}:\d{2})?/);
  const offset = (m && m[1]) || "+00:00";
  const p = londonParts(d);
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}${offset}`;
}
function hhmm(d = new Date()) { const p = londonParts(d); return `${p.hour}:${p.minute}`; }
function londonDayEndISO(d) {
  const p = londonParts(d);
  const offset = localOffsetISO(d).slice(19) || "+00:00";
  return `${p.year}-${p.month}-${p.day}T23:59:59${offset}`;
}
function londonDayStartISO(d) {
  const p = londonParts(d);
  const offset = localOffsetISO(d).slice(19) || "+00:00";
  return `${p.year}-${p.month}-${p.day}T00:00:00${offset}`;
}

/* ---------------- crypto (matches dashboard: salt16|iv16|AES-CBC(PKCS7)) ---------------- */
const te = new TextEncoder(), td = new TextDecoder();
const b64e = (buf) => {
  const u8 = new Uint8Array(buf); let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
};
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function importAes(rawBytes, usages) {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-CBC" }, false, usages);
}
async function encryptBundle(state, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await importAes(b64d(state.keyRaw), ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, te.encode(JSON.stringify(obj)));
  const salt = b64d(state.keySalt);
  const out = new Uint8Array(16 + 16 + ct.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 32);
  return b64e(out);
}
/* ---------------- state ---------------- */
async function loadState(env) {
  const obj = await env.PW.get("state.json");
  const state = obj ? JSON.parse(await obj.text()) : {};
  state.config = { ...DEFAULT_CONFIG, ...(state.config || {}) };
  state.hist = state.hist || [];
  // one-time migration (requested 2026-07-15): enable Powerwall follow-Ohme-slots
  if (!state.mig_fo1) { state.config.follow_ohme_slots = true; state.mig_fo1 = 1; }
  // one-time migration (requested 2026-07-16): grid charging always allowed
  if (!state.mig_gc1) { state.config.day = { ...(state.config.day || {}), allow_grid_charging: true }; state.mig_gc1 = 1; }
  // one-time migration (2026-07-17): re-run the Octopus deep fill so cached daily
  // rows gain standing charges; also refetch immediately rather than in 30 min
  if (!state.mig_std1) { state.octoDeepFill = 0; state.lastOcto = 0; state.mig_std1 = 1; }
  // one-time migration (2026-07-17): refill again with the 71p/day standing fallback
  if (!state.mig_std2) { state.octoDeepFill = 0; state.lastOcto = 0; state.mig_std2 = 1; }
  // one-time migration (2026-07-17): statements showed our rates were wrong — refill
  // the year pricing each period under its actual agreement (per-agreement rates)
  if (!state.mig_agr1) { state.octoDeepFill = 0; delete state.octoFillCursor; state.lastOcto = 0; state.mig_agr1 = 1; }
  // one-time migration (2026-07-17b): refill once more with midnight-aligned chunks
  // (mid-day chunk cuts corrupted boundary days) — also reset the cursor mirror
  if (!state.mig_agr2) {
    state.octoDeepFill = 0; delete state.octoFillCursor; state.lastOcto = 0; state.mig_agr2 = 1;
    try { await env.PW.delete("octofill.txt"); } catch (e) {}
  }
  // one-time migration (2026-07-17c): refill with big-draw slot repricing (historical
  // IO smart-charge slots billed at night rate — imports were overstated ~30%)
  if (!state.mig_agr3) {
    state.octoDeepFill = 0; delete state.octoFillCursor; state.lastOcto = 0; state.mig_agr3 = 1;
    try { await env.PW.delete("octofill.txt"); } catch (e) {}
  }
  // one-time migration (2026-07-17d): refetch 12 months of Tesla daily energy — the
  // BST anchor bug meant whole months (incl. June) were missing from the charts
  if (!state.mig_en1) { state.energyDeepFill = 0; state.lastEnergy = 0; state.mig_en1 = 1; }
  // one-time migration (2026-07-17f): refresh octopus promptly to pull Home Mini telemetry
  if (!state.mig_tel1) { state.lastOcto = 0; state.mig_tel1 = 1; }
  // one-time migration (2026-07-20): hot water to 65° during Ohme slots (requested)
  if (!state.mig_dhw1) { state.config.dhw_ohme_slots = true; state.mig_dhw1 = 1; }
  if (!state.mig_dhw2) { state.dhwBoosted = 0; state.mig_dhw2 = 1; } // re-arm after adding boost support
  if (!state.mig_pw1) { state.pwSlotCharge = null; state.mig_pw1 = 1; } // re-evaluate slot charging with 50% start line
  if (!state.mig_agex1) { state.config.export_agile_from = "2026-07-26"; state.lastOcto = 0; state.mig_agex1 = 1; } // Agile Outgoing live from 26 Jul; reprice now
  if (!state.mig_agex2) { state.lastOcto = 0; state.mig_agex2 = 1; } // bridge now unconditional — reprice again
  if (!state.mig_pw2) { state.pwSlotCharge = null; state.mig_pw2 = 1; } // re-evaluate with fill-to-95 rule
  if (!state.mig_pw3) { state.pwSlotCharge = null; state.mig_pw3 = 1; } // enter<95 / stop@95 / restart<50
  if (!state.mig_ts1) { state.config.tariff_sync = { enabled: true, offpeak: 5.9, peak: 31.33 }; state.mig_ts1 = 1; }
  // flat evening export plan pushed to the Powerwall (not a real price)
  if (!state.mig_plan1) { state.config.export_plan = { pence: 20, fromH: 16, toH: 22 }; state.mig_plan1 = 1; }
  // don't force export when the slot is genuinely poor — leave those at the real price
  if (!state.mig_plan2) { state.config.export_plan = { pence: 20, fromH: 16, toH: 22, minP: 12 }; state.mig_plan2 = 1; }
  // what the Powerwall does during an Ohme cheap slot: "charge" (existing) or
  // "hold" (leave the cheap import for the car, and stop the battery exporting)
  if (!state.mig_ohold1) {
    state.config.ohme_slot_mode = state.config.ohme_slot_mode || "charge";
    state.config.ohme_hold_export = state.config.ohme_hold_export || "pv_only";
    state.mig_ohold1 = 1;
  }
  // auto: charge outside the export window, hold inside it
  if (!state.mig_ohold2) { state.config.ohme_slot_mode = "auto"; state.mig_ohold2 = 1; }
  // one-time migration (2026-07-17e): extend history to ~2 years for the Year view
  if (!state.mig_yr1) {
    state.octoDeepFill = 0; delete state.octoFillCursor; state.lastOcto = 0;
    state.energyDeepFill = 0; state.lastEnergy = 0; state.mig_yr1 = 1;
    try { await env.PW.delete("octofill.txt"); } catch (e) {}
  }
  // key material is pre-derived at deploy time (PBKDF2 is too heavy for worker CPU limits)
  state.keySalt = env.DASH_SALT_B64;
  state.keyRaw = env.DASH_KEY_B64;
  return state;
}
async function saveState(env, state) {
  await env.PW.put("state.json", JSON.stringify(state));
}

/* ---------------- tesla ---------------- */
async function teslaToken(env, state) {
  const now = Date.now() / 1000;
  if (state.access_token && (state.access_exp || 0) > now + 600) return state.access_token;
  // candidates: state copy, tiny R2 mirror (survives failed state saves), deploy-time secret
  let mirror = null;
  try { const o = await env.PW.get("refresh_token.txt"); if (o) mirror = (await o.text()).trim(); } catch (e) {}
  const candidates = [...new Set([state.refresh_token, mirror, env.TESLA_REFRESH_TOKEN].filter(Boolean))];
  let lastErr = "no refresh token candidates";
  for (const rt of candidates) {
    const r = await fetch(TESLA_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: env.TESLA_CLIENT_ID, refresh_token: rt }),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.access_token) {
      state.access_token = j.access_token;
      state.access_exp = now + (j.expires_in || 28800);
      state.refresh_token = j.refresh_token;
      // persist the rotated token FIRST to a tiny dedicated key (a failed multi-MB
      // state save must never orphan a single-use token again), then the full state
      try { await env.PW.put("refresh_token.txt", j.refresh_token); } catch (e) {}
      await saveState(env, state);
      return state.access_token;
    }
    lastErr = JSON.stringify(j).slice(0, 200);
  }
  throw new Error("tesla token refresh failed: " + lastErr);
}
async function tesla(env, state, method, path, body, params) {
  const tok = await teslaToken(env, state);
  const url = new URL(TESLA_API + path);
  for (const [k, v] of Object.entries(params || {})) url.searchParams.set(k, v);
  const r = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${tok}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`tesla ${path} ${r.status}: ${(await r.text()).slice(0, 150)}`);
  return (await r.json()).response;
}
async function siteId(env, state) {
  if (state.siteId) return state.siteId;
  const products = await tesla(env, state, "GET", "/api/1/products");
  const site = (products || []).find((p) => p.energy_site_id);
  if (!site) throw new Error("no energy site");
  state.siteId = String(site.energy_site_id);
  state.siteName = site.site_name || "Powerwall";
  return state.siteId;
}

/* ---------------- octopus ---------------- */
function rateAtEpoch(rates, tms) {
  for (const r of rates || []) {
    const from = Date.parse(r.valid_from), to = r.valid_to ? Date.parse(r.valid_to) : Infinity;
    if (from <= tms && tms < to) return r.value_inc_vat;
  }
  return null;
}
// Kraken GraphQL (Home Mini live telemetry — the REST consumption feed lags ~a day)
async function krakenGQL(env, state, query, variables) {
  const now = Date.now() / 1000;
  const k = (state.kraken = state.kraken || {});
  if (!k.token || now - (k.birth || 0) > 3000) {
    const r = await fetch("https://api.octopus.energy/v1/graphql/", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "mutation($k:String!){obtainKrakenToken(input:{APIKey:$k}){token}}", variables: { k: env.OCTOPUS_API_KEY } }),
    });
    const j = await r.json().catch(() => ({}));
    k.token = (((j || {}).data || {}).obtainKrakenToken || {}).token;
    k.birth = now;
    if (!k.token) throw new Error("kraken auth failed");
  }
  const r2 = await fetch("https://api.octopus.energy/v1/graphql/", {
    method: "POST", headers: { "Content-Type": "application/json", Authorization: k.token },
    body: JSON.stringify({ query, variables }),
  });
  const j2 = await r2.json();
  if (j2.errors) throw new Error("kraken: " + JSON.stringify(j2.errors).slice(0, 120));
  return j2.data;
}
async function krakenDeviceId(env, state) {
  if (state.octoDevId) return state.octoDevId;
  const d = await krakenGQL(env, state,
    "query($a:String!){account(accountNumber:$a){electricityAgreements(active:true){meterPoint{meters{smartDevices{deviceId}}}}}}",
    { a: env.OCTOPUS_ACCOUNT });
  for (const ag of (((d || {}).account || {}).electricityAgreements) || [])
    for (const m of ((ag.meterPoint || {}).meters) || [])
      for (const sd of m.smartDevices || [])
        if (sd.deviceId) { state.octoDevId = sd.deviceId; return sd.deviceId; }
  throw new Error("no smart device (Home Mini) found");
}
async function fetchOctopus(env, state) {
  const auth = "Basic " + btoa(env.OCTOPUS_API_KEY + ":");
  const get = async (url, params) => {
    const u = new URL(url);
    for (const [k, v] of Object.entries(params || {})) u.searchParams.set(k, v);
    const r = await fetch(u, { headers: { Authorization: auth } });
    return r.ok ? r.json() : null;
  };
  const getAll = async (url, params) => {
    let results = [];
    let u = new URL(url);
    for (const [k, v] of Object.entries(params || {})) u.searchParams.set(k, v);
    for (let i = 0; i < 8 && u; i++) {
      const r = await fetch(u, { headers: { Authorization: auth } });
      if (!r.ok) break;
      const j = await r.json();
      results = results.concat(j.results || []);
      u = j.next ? new URL(j.next) : null;
    }
    return results;
  };
  const acct = await get(`https://api.octopus.energy/v1/accounts/${env.OCTOPUS_ACCOUNT}/`);
  if (!acct) return { error: "octopus account fetch failed" };
  // deep fill: pull the past year in 45-day chunks (one per tick — a whole year of
  // half-hourly rows in one invocation exceeds the Worker CPU limit), then 35-day top-ups
  const deep = !(state && state.octoDeepFill);
  const CHUNK = 12; // days per tick — bigger chunks exceed the Worker CPU budget
  let chunkEnd = null;
  let start;
  if (deep) {
    // resume from the tiny cursor mirror if the last tick died before saving state
    if (state.octoFillCursor == null) {
      try { const o = await env.PW.get("octofill.txt"); if (o) { const v = parseInt(await o.text(), 10); if (v > 35) state.octoFillCursor = v; } } catch (e) {}
    }
    const cur = (state.octoFillCursor = state.octoFillCursor ?? 750); // days ago, counts down (~2 years)
    // chunk boundaries at LOCAL midnight — a mid-day cut leaves partial days that
    // overwrite the other half, silently dropping the overnight cheap-rate usage
    start = londonDayStartISO(new Date(Date.now() - cur * 864e5));
    chunkEnd = londonDayStartISO(new Date(Date.now() - Math.max(0, cur - CHUNK) * 864e5));
  } else {
    start = londonDayStartISO(new Date(Date.now() - 35 * 864e5));
  }
  // half-hours our poller saw as IO-slot/car-charging (billed off-peak on Intelligent Octopus)
  const ioSet = new Set();
  for (const p of (state && state.hist) || []) {
    if (p.io || (p.ev || 0) > 250) {
      const mm = parseInt(p.t.slice(14, 16), 10) < 30 ? "00" : "30";
      ioSet.add(p.t.slice(0, 14) + mm);
    }
  }
  const out = {};
  const daily = {};
  const dayOf = (iso) => localMinuteISO(new Date(Date.parse(iso))).slice(0, 10);
  for (const prop of acct.properties || []) {
    for (const mp of prop.electricity_meter_points || []) {
      const kind = mp.is_export ? "export" : "import";
      let serial = null;
      for (const m of mp.meters || []) if (m.serial_number) serial = m.serial_number;
      let tariff = null;
      for (const ag of mp.agreements || []) {
        if (!ag.valid_to || ag.valid_to > new Date().toISOString()) tariff = ag.tariff_code;
      }
      let consumption = [], rates = [], standing = [];
      if (serial) {
        consumption = await getAll(`https://api.octopus.energy/v1/electricity-meter-points/${mp.mpan}/meters/${serial}/consumption/`,
          { period_from: start, page_size: "20000", order_by: "period", ...(chunkEnd ? { period_to: chunkEnd } : {}) });
      }
      // price each period under the agreement that was actually in force (the
      // tariff changed twice this year — statements: Go 5.71/29.06 → 4.00/27.46 → 5.62/29.84)
      // rates fetched up to +2 days: Agile publishes next-day prices ~16:30, and we
      // want tonight's export half-hours priced correctly the moment they're live.
      const winEnd = chunkEnd || new Date().toISOString();
      const rateEnd = chunkEnd || new Date(Date.now() + 2 * 864e5).toISOString();
      for (const ag of mp.agreements || []) {
        const af = ag.valid_from || "2000", at = ag.valid_to || "9999";
        if (at <= start || af >= rateEnd) continue; // agreement outside our pull window
        const code = ag.tariff_code;
        const product = code.split("-").slice(2, -1).join("-");
        const params = { period_from: af > start ? af : start, period_to: at < rateEnd ? at : rateEnd, page_size: "1500" };
        rates = rates.concat(await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${code}/standard-unit-rates/`, params));
        if (kind === "import")
          standing = standing.concat(await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${code}/standing-charges/`, params));
      }
      if (kind === "export") {
        // Bridge for account-feed lag after a switch to Agile Outgoing: the public
        // products API has the rates with no account involved. Prepending makes them
        // win over the stale flat agreement; self-retires once the feed shows AGILE.
        try {
          const agFrom = (state.config || {}).export_agile_from;
          // bridge only the gap the account feed has not backfilled: it reports the
          // AGILE agreement starting later than the real switch date, so days before
          // that start would otherwise price at the old flat rate. Self-retires once
          // the feed agile agreement covers export_agile_from. Duplicate rows are
          // deduped below, so overlapping with the feed is harmless.
          const agileAgFrom = (mp.agreements || [])
            .filter((a) => /AGILE/i.test(a.tariff_code || ""))
            .map((a) => Date.parse(a.valid_from || 0))
            .sort((a, b) => a - b)[0];
          if (agFrom && (agileAgFrom == null || agileAgFrom > Date.parse(agFrom) + 36e5)) {
            if (!state.agileExpCode || Date.now() / 1000 - (state.agileExpCodeT || 0) > 86400) {
              const prods = await getAll("https://api.octopus.energy/v1/products/", { page_size: "250" });
              const p = prods.filter((x) => x.direction === "EXPORT" && /AGILE/i.test(x.code) && !x.available_to)
                             .sort((a, b) => (a.available_from < b.available_from ? 1 : -1))[0];
              const region = (tariff || "").trim().slice(-1) || "A";
              if (p) { state.agileExpProduct = p.code; state.agileExpCode = `E-1R-${p.code}-${region}`; state.agileExpCodeT = Date.now() / 1000; }
            }
            if (state.agileExpCode) {
              const agRates = await getAll(`https://api.octopus.energy/v1/products/${state.agileExpProduct}/electricity-tariffs/${state.agileExpCode}/standard-unit-rates/`,
                { period_from: agFrom, period_to: rateEnd, page_size: "1500" });
              if (agRates.length) rates = agRates.concat(rates);
              console.log(`agile bridge: ${state.agileExpCode} -> ${agRates.length} rates from ${agFrom}`);
              out.bridge = { code: state.agileExpCode, n: agRates.length };
            }
          }
        } catch (e) {}
      }
      // normalise before pricing: rateAtEpoch takes the FIRST match, so a long-span
      // agreement row (the old flat export tariff is open-ended, valid_to null) would
      // otherwise beat the half-hourly Agile row covering the same instant. Most
      // specific first, then newest, dropping duplicates from overlapping sources.
      {
        const spanOf = (r) => (r.valid_to ? Date.parse(r.valid_to) : 8.64e15) - Date.parse(r.valid_from || 0);
        const seenAll = new Set();
        rates = rates
          .filter((r) => {
            const k = (r.valid_from || "") + "|" + (r.valid_to || "");
            if (seenAll.has(k)) return false;
            seenAll.add(k);
            return true;
          })
          .sort((a, b) => (spanOf(a) - spanOf(b)) || (Date.parse(b.valid_from || 0) - Date.parse(a.valid_from || 0)));
      }
      if (kind === "import") {
        out.standing_now = rateAtEpoch(standing, Date.now()) ?? STANDING_FALLBACK;
        out._standing = (out._standing || []).concat(standing);
      }
      // cheapest rate per local day (the "night" rate under whichever product applied)
      const shortMin = {}, longRows = [];
      for (const r of rates) {
        const f = Date.parse(r.valid_from || 0), t = r.valid_to ? Date.parse(r.valid_to) : null;
        if (t && t - f <= 2 * 864e5) {
          for (const ms of [f, t - 1]) {
            const k = localMinuteISO(new Date(ms)).slice(0, 10);
            if (shortMin[k] == null || r.value_inc_vat < shortMin[k]) shortMin[k] = r.value_inc_vat;
          }
        } else longRows.push(r);
      }
      const minRateAt = (ms, dy) => {
        let m = shortMin[dy];
        for (const r of longRows) {
          const f = Date.parse(r.valid_from || 0), t = r.valid_to ? Date.parse(r.valid_to) : Infinity;
          if (f <= ms && ms < t && (m == null || r.value_inc_vat < m)) m = r.value_inc_vat;
        }
        return m;
      };
      for (const c of consumption) {
        if (!c.interval_start) continue;
        const ts = Date.parse(c.interval_start);
        const lm = localMinuteISO(new Date(ts)); // once per row
        const dy = lm.slice(0, 10);
        const d = (daily[dy] = daily[dy] || { d: dy, impKwh: 0, impCost: 0, offKwh: 0, peakKwh: 0, expKwh: 0, expEarn: 0 });
        let rate = rateAtEpoch(rates, ts);
        if (kind === "import") {
          const dayMin = minRateAt(ts, dy);
          const localKey = lm.slice(0, 16);
          // Intelligent Octopus bills smart-charge slots at the night rate even outside
          // the window. Historical slots aren't in the API, but only EV/Powerwall
          // charging sustains ≥4 kW for a half-hour — reprice those (≥2 kWh/HH).
          const bigDraw = (c.consumption || 0) >= 2.0;
          if ((ioSet.has(localKey) || bigDraw) && dayMin != null) rate = dayMin;
          if (rate == null) rate = dayMin ?? 5.9; // inc-VAT night rate fallback
          d.impKwh += c.consumption;
          d.impCost += c.consumption * rate;
          if (dayMin != null && rate <= dayMin + 0.01) d.offKwh += c.consumption; else d.peakKwh += c.consumption;
          d.cov = Math.max(d.cov || 0, Date.parse(c.interval_end || c.interval_start) || 0);
          d.nImp = (d.nImp || 0) + 1;
        } else {
          if (rate == null) { rate = 12; out.expFallback = (out.expFallback || 0) + 1; }
          d.expKwh += c.consumption;
          d.expEarn += c.consumption * rate;
          d.nExp = (d.nExp || 0) + 1;
        }
      }
      // keep every rate row still relevant to pricing (last 10 days + published
      // future) rather than a fixed row count. A count cap silently discards the
      // newest half-hours once volume grows — that is how sell prices went stale.
      // Order is preserved from the normalisation above so the stored copy resolves
      // exactly the way the pricing loop did.
      const keepFrom = Date.now() - 10 * 864e5;
      const keptRates = rates.filter((r) => (r.valid_to ? Date.parse(r.valid_to) : Infinity) > keepFrom);
      out[kind] = { mpan: mp.mpan, tariff, consumption: consumption.slice(-150), rates: keptRates };
    }
  }
  // last-2-days accuracy: Octopus's REST feeds lag (imports ~a day, exports worse).
  // Home Mini telemetry closes the gap — consumptionDelta (Wh) for imports, the
  // cumulative export register for exports. REST takes over once a day is complete.
  if (!chunkEnd) {
    try {
      const impRates = ((out.import || {}).rates) || [];
      const expRates = ((out.export || {}).rates) || [];
      const dayKeys = [0, 1].map((n) => localMinuteISO(new Date(Date.now() - n * 864e5)).slice(0, 10));
      const needImp = dayKeys.filter((k) => !daily[k] || (daily[k].nImp || 0) < 46);
      const needExp = dayKeys.slice(); // always re-price the last 2 days' export against the latest rates
      if (needImp.length || needExp.length) {
        const devId = await krakenDeviceId(env, state);
        const s = new Date(Date.parse(londonDayStartISO(new Date(Date.now() - 864e5))) - 1800e3);
        const tel = await krakenGQL(env, state,
          "query($d:String!,$s:DateTime!,$e:DateTime!){smartMeterTelemetry(deviceId:$d,grouping:HALF_HOURLY,start:$s,end:$e){readAt consumptionDelta export}}",
          { d: devId, s: s.toISOString(), e: new Date().toISOString() });
        const rows = ((tel || {}).smartMeterTelemetry || []).filter((r) => r.readAt).sort((a, b) => (a.readAt < b.readAt ? -1 : 1));
        const dayMinCache = {};
        const minFor = (dy) => {
          if (dy in dayMinCache) return dayMinCache[dy];
          let m = null;
          for (const r of impRates) {
            const f = Date.parse(r.valid_from || 0), t = r.valid_to ? Date.parse(r.valid_to) : null;
            if (t && t - f <= 2 * 864e5)
              for (const ms of [f, t - 1])
                if (localMinuteISO(new Date(ms)).slice(0, 10) === dy && (m == null || r.value_inc_vat < m)) m = r.value_inc_vat;
          }
          return (dayMinCache[dy] = m);
        };
        const expDayAvg = (dy) => {
          let sum = 0, n = 0;
          for (const r of expRates) {
            const f = Date.parse(r.valid_from || 0);
            if (localMinuteISO(new Date(f)).slice(0, 10) === dy) { sum += r.value_inc_vat; n++; }
          }
          return n ? sum / n : 12;
        };
                const blank = (k) => (daily[k] = daily[k] || { d: k, impKwh: 0, impCost: 0, offKwh: 0, peakKwh: 0, expKwh: 0, expEarn: 0 });
        for (const k of needImp) { const dd = blank(k); dd.impKwh = dd.impCost = dd.offKwh = dd.peakKwh = 0; dd.telemetry = 1; }
        for (const k of needExp) { const dd = blank(k); dd.expKwh = dd.expEarn = 0; dd.telemetry = 1; }
        let prevReg = null;
        for (const row of rows) {
          const ts = Date.parse(row.readAt);
          if (!ts) continue;
          const lm2 = localMinuteISO(new Date(ts));
          const dy = lm2.slice(0, 10);
          const kwh = (parseFloat(row.consumptionDelta) || 0) / 1000;
          if (needImp.includes(dy) && kwh > 0) {
            const dd = daily[dy];
            let rate = rateAtEpoch(impRates, ts);
            const dm = minFor(dy);
            if ((ioSet.has(lm2.slice(0, 16)) || kwh >= 2.0) && dm != null) rate = dm;
            if (rate == null) rate = dm ?? 5.9;
            dd.impKwh += kwh; dd.impCost += kwh * rate;
            if (dm != null && rate <= dm + 0.01) dd.offKwh += kwh; else dd.peakKwh += kwh;
            dd.cov = Math.max(dd.cov || 0, ts + 1800e3);
          }
          const reg = parseFloat(row.export);
          if (!isNaN(reg)) {
            if (prevReg != null && reg > prevReg && needExp.includes(dy)) {
              const ek = (reg - prevReg) / 1000;
              const dd = daily[dy];
              dd.expKwh += ek; dd.expEarn += ek * (rateAtEpoch(expRates, ts) ?? expDayAvg(dy));
              // Coverage has to follow the export register as well, not just the
              // import one. In the evening the house is net exporting, so the
              // import delta is zero, the import branch is skipped and cov froze
              // at the last import - while expKwh kept climbing. The energy page
              // then re-integrated everything after cov on top of a figure that
              // already included it, near enough doubling the day's exports.
              dd.cov = Math.max(dd.cov || 0, ts);
            }
            prevReg = reg;
          }
        }
      }
      for (const k of needExp) if (daily[k]) console.log(`exp repriced ${k}: ${(daily[k].expKwh || 0).toFixed(1)} kWh -> ${(daily[k].expEarn || 0).toFixed(0)}p`);
    } catch (e) { console.log("telemetry reprice failed: " + String(e).slice(0, 120)); }
  }
  // per-day standing charge from the dated tariff schedule
  for (const k of Object.keys(daily)) {
    daily[k].standing = rateAtEpoch(out._standing || [], Date.parse(k + "T12:00:00Z")) ?? out.standing_now ?? STANDING_FALLBACK;
  }
  delete out._standing;
  // merge with previously cached daily costs, fresh values win
  const merged = {};
  for (const r of ((state && state.octopus) || {}).daily || []) merged[r.d] = r;
  Object.assign(merged, daily);
  out.daily = Object.keys(merged).sort().map((k) => merged[k]).slice(-750);
  if (state && deep) {
    state.octoFillCursor = Math.max(35, (state.octoFillCursor ?? 370) - CHUNK);
    // persist progress instantly — a later CPU overrun must not rewind the fill
    try { await env.PW.put("octofill.txt", String(state.octoFillCursor)); } catch (e) {}
    if (state.octoFillCursor <= 35) { state.octoDeepFill = 1; delete state.octoFillCursor; }
  }
  return out;
}

/* ---------------- ohme ---------------- */
async function ohmeToken(env, state) {
  const o = (state.ohmeAuth = state.ohmeAuth || {});
  const now = Date.now() / 1000;
  if (o.idToken && now - (o.birth || 0) < 2700) return o.idToken;
  if (o.refreshToken) {
    const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${(env.OHME_GOOGLE_KEY || "")}`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grantType: "refresh_token", refreshToken: o.refreshToken }),
    });
    if (r.ok) {
      const j = await r.json();
      o.idToken = j.id_token; o.refreshToken = j.refresh_token; o.birth = now;
      return o.idToken;
    }
  }
  const r = await fetch(`https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=${(env.OHME_GOOGLE_KEY || "")}`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: env.OHME_EMAIL, password: env.OHME_PASSWORD, returnSecureToken: "true" }),
  });
  if (!r.ok) throw new Error("ohme login failed");
  const j = await r.json();
  o.idToken = j.idToken; o.refreshToken = j.refreshToken; o.birth = now;
  return o.idToken;
}
async function fetchOhme(env, state) {
  const tok = await ohmeToken(env, state);
  const r = await fetch("https://api.ohme.io/v1/chargeSessions", {
    headers: { Authorization: `Firebase ${tok}`, "Content-Type": "application/json", "User-Agent": "pw-worker/1.0" },
  });
  if (!r.ok) throw new Error("ohme session fetch " + r.status);
  const s = (await r.json())[0] || {};
  const mode = s.mode || "";
  let status = "plugged in";
  if (mode === "DISCONNECTED") status = "unplugged";
  else if (mode === "PENDING_APPROVAL") status = "pending approval";
  else if (mode === "STOPPED") status = "paused";
  else if (mode === "FINISHED_CHARGE") status = "finished";
  else if ((s.power || {}).watt > 0) status = "charging";
  const slots = (s.allSessionSlots || []).map((sl) => ({
    start: new Date(sl.startTimeMs).toISOString(),
    end: new Date(sl.endTimeMs).toISOString(),
  }));
  return {
    status,
    power: { watts: (s.power || {}).watt || 0 },
    energy: ((s.batterySoc || {}).wh) || 0,
    battery: (((s.car || {}).batterySoc || {}).percent) || ((s.batterySoc || {}).percent) || 0,
    slots,
  };
}

/* ---------------- automation ---------------- */
async function vaillantSetDhw(env, state, temp) {
  const tok = await vaillantToken(env, state);
  const base = (state.vaillantCtrl === "vrc700" ? VAILLANT_API.replace("end-user-app-api/v1", "vrc700/v1") : VAILLANT_API)
    + `/systems/${state.vaillantSys}/${state.vaillantCtrl || "tli"}`;
  const r = await fetch(`${base}/domestic-hot-water/${state.vaillantDhwIdx ?? 255}/temperature`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json", "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" },
    body: JSON.stringify({ setpoint: Math.round(temp) }),
  });
  if (!r.ok && r.status !== 204) throw new Error(`dhw set ${r.status}: ${(await r.text()).slice(0, 80)}`);
}
/* ---------------- tesla tariff sync ----------------
   Buy side: IO Go off-peak window + currently granted Ohme slots at the off-peak
   rate, peak elsewhere. Sell side: today's 48 Agile Outgoing half-hours.
   Rewritten daily and whenever Ohme's granted slots change. */
function tariffIntervals(state) {
  // half-hour marks for the current London day
  const marks = new Array(48).fill(false);
  for (let h = 0; h < 48; h++) { const m = h * 30; if (m >= 1410 || m < 330) marks[h] = true; } // 23:30-05:30
  const base = Date.parse(londonDayStartISO(new Date()));
  for (const sl of ((state.ohmeData || {}).slots) || []) {
    const sMs = Date.parse(sl.start), eMs = Date.parse(sl.end);
    if (!sMs || !eMs) continue;
    for (let h = 0; h < 48; h++) {
      const hs = base + h * 1800e3;
      if (sMs < hs + 1800e3 && eMs > hs) marks[h] = true;
    }
  }
  const off = []; let run = null;
  for (let h = 0; h < 48; h++) {
    if (marks[h]) { if (!run) run = { s: h * 30, e: h * 30 + 30 }; else run.e = h * 30 + 30; }
    else if (run) { off.push(run); run = null; }
  }
  if (run) off.push(run);
  const on = []; let cur = 0;
  for (const x of off) { if (x.s > cur) on.push({ s: cur, e: x.s }); cur = x.e; }
  if (cur < 1440) on.push({ s: cur, e: 1440 });
  return { off, on };
}
function touPeriods(intervals) {
  return { periods: intervals.map((iv) => ({
    fromDayOfWeek: 0, toDayOfWeek: 6,
    fromHour: Math.floor(iv.s / 60), fromMinute: iv.s % 60,
    toHour: Math.floor(iv.e / 60) % 24, toMinute: iv.e % 60,
  })) };
}
async function pushTariff(env, state, sid, log) {
  const cfgT = ((state.config || {}).tariff_sync) || {};
  const offP = (cfgT.offpeak ?? 5.9) / 100, onP = (cfgT.peak ?? 31.33) / 100;
  const expRates = (((state.octopus || {}).export) || {}).rates || [];
  if (!expRates.length) { log.push("tariff sync: no export rates yet"); return false; }
  // one-time backup of the app-configured plan
  if (!state.tariffBackedUp) {
    try {
      const si = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/site_info`);
      const cur = si.tariff_content_v2 || si.tariff_content;
      if (cur) { await env.PW.put("tariff_backup.json", JSON.stringify(cur)); state.tariffBackedUp = 1; }
    } catch (e) {}
  }
  const { off, on } = tariffIntervals(state);
  const base = Date.parse(londonDayStartISO(new Date()));
  const sellAll = expRates.filter((r) => true);
  // Agile is always half-hourly, so a match against a long-span row means the real
  // rate is not published yet. The old flat export agreement is open-ended and would
  // otherwise answer for every slot — that is how a dead 12p tariff reached the
  // Powerwall. Treat a long-span match as unpriced rather than as a price.
  const agileAt = (ms) => {
    for (const r of sellAll) {
      const f = Date.parse(r.valid_from), t = r.valid_to ? Date.parse(r.valid_to) : Infinity;
      if (f <= ms && ms < t) return t - f <= 2 * 864e5 ? r.value_inc_vat : null;
    }
    return null;
  };
  let avg = 0, nAvg = 0;
  for (let h = 0; h < 48; h++) { const v = agileAt(base + h * 1800e3 + 900e3); if (v != null) { avg += v; nAvg++; } }
  avg = nAvg ? avg / nAvg : 12;
  const sellRates = {}, sellPeriods = {};
  const missing = [];
  for (let h = 0; h < 48; h++) {
    const k = "R" + String(h).padStart(2, "0");
    let v = agileAt(base + h * 1800e3 + 900e3);
    if (v == null) { missing.push(h); v = avg; }
    sellRates[k] = Math.round(v * 10) / 1000; // p -> GBP, 3dp
    const m = h * 30;
    sellPeriods[k] = touPeriods([{ s: m, e: m + 30 }]);
  }
  // Octopus publishes next-day Agile ~16:15, so a couple of unpublished slots at the
  // tail of the day is normal — estimate those from today’s own average and say so.
  // A large gap is the signature of the Jul 2026 truncation bug, where 29 contiguous
  // slots fell through to a dead 12p tariff. Never push that.
  if (missing.length > 6) throw new Error("sell rates missing for " + missing.length + " of 48 half-hours (first slot " + missing[0] + ") — not pushing");
  if (missing.length) log.push("tariff sync: " + missing.length + " slot(s) unpublished, estimated at " + avg.toFixed(1) + "p");
  // Evening export plan: pin the sell price to a flat rate across the peak window
  // so Time-Based Control discharges steadily through it instead of chasing spikes.
  // This is a CONTROL SIGNAL, not a price. The ledger's daily metered totals are
  // priced from the real Octopus rates and are deliberately untouched by this.
  // Snapshot the true Agile prices before any override, so the ledger can show
  // what we pushed alongside what Octopus is actually paying.
  const realSell = Array.from({ length: 48 }, (_, h) =>
    Math.round(sellRates["R" + String(h).padStart(2, "0")] * 10000) / 100);
  const ocfg = ((state.config || {}).export_plan) || { pence: 0, fromH: 16, toH: 22, minP: 0 };
  const planFrom = Math.max(0, Math.round(ocfg.fromH * 2)); // 16:00 -> slot 32
  const oTo = Math.min(47, Math.round(ocfg.toH * 2) - 1);   // 22:00 -> slot 43
  const minP = ocfg.minP ?? 0;
  const planOn = [];
  let oFrom = planFrom;
  const planExtra = [];   // ohme-earned slots outside the core window
  if (ocfg.pence > 0) {
    const key = (h) => "R" + String(h).padStart(2, "0");
    const realAt = (h) => realSell[h];   // pence, captured before we touch anything
    const hhmm = (h) => String(Math.floor(h / 2)).padStart(2, "0") + (h % 2 ? ":30" : ":00");

    /* How much extra export has Ohme earned? Every half-hour the car charges
       outside the overnight cheap window is a half-hour the battery was topped
       up for next to nothing, so it buys one extra half-hour of forced export.
       The cheap window itself never counts - a whole solar day follows it and
       refills the battery regardless. */
    const lmNow = localMinuteISO();
      const todayLocal = lmNow.slice(0, 10);
      // a slot that has already been and gone can't be exported into, so spending
      // an earned credit on it just throws the credit away
      const nowIdx = Math.floor(((+lmNow.slice(11, 13)) * 60 + (+lmNow.slice(14, 16))) / 30);
    const cw = (state.config || {}).cheap_window || {};
    const toIdx = (x, dflt) => {
      const m = /^(\d{1,2}):(\d{2})$/.exec(String(x || ""));
      return m ? Math.floor((+m[1] * 60 + +m[2]) / 30) : dflt;
    };
    const cwA = toIdx(cw.start, 47), cwB = toIdx(cw.end, 11);
    const inCheap = (i) => (cwA <= cwB ? i >= cwA && i < cwB : i >= cwA || i < cwB);
    const ohmeAll = new Set();   // every half-hour the car is due to charge
    const earned = new Set();    // ...of those, the ones that earn an export slot
    for (const sl of ((state.ohmeData || {}).slots) || []) {
      const st = Date.parse((sl || {}).start), en = Date.parse((sl || {}).end);
      if (!st || !en || en <= st) continue;
      for (let ms = st; ms < en; ms += 18e5) {
        const lm = localMinuteISO(new Date(ms));
        if (lm.slice(0, 10) !== todayLocal) continue;
        const i = Math.floor(((+lm.slice(11, 13)) * 60 + (+lm.slice(14, 16))) / 30);
        ohmeAll.add(i);
        // Two ways an ohme slot earns extra export. Before the window, it tops the
        // battery up cheaply. Inside the window, hold cancels export we had already
        // planned at the plan price and the energy stays in the battery. Either way
        // it needs somewhere else to go. After the window it earns nothing - there
        // is no export left today to move it to.
        if (i <= oTo && !inCheap(i)) earned.add(i);
      }
    }

    // the core window: flat plan price, except where Agile is below the floor
    let skipped = 0;
    for (let h = planFrom; h <= oTo; h++) {
      if (realAt(h) < minP) { skipped++; continue; }
      sellRates[key(h)] = Math.round(ocfg.pence * 10) / 1000;
      planOn.push(h);
    }

    /* Spend the earned slots on the best-paying shoulders rather than simply
       backdating from the window start: rank the half-hours either side of it
       and take the highest. Half-hours the car is charging in are excluded,
       since exporting while importing for the car is just churn. */
    let picks = [];
    if (earned.size) {
      const shoulder = [];
      for (let h = Math.max(0, planFrom - 4); h < planFrom; h++) shoulder.push(h); // 14:00-16:00
      for (let h = oTo + 1; h <= Math.min(47, oTo + 3); h++) shoulder.push(h);     // 22:00-23:30
      picks = shoulder
        .filter((h) => h > nowIdx && !ohmeAll.has(h) && !inCheap(h) && realAt(h) >= minP)
        .sort((a, b) => realAt(b) - realAt(a) || a - b)
        .slice(0, earned.size);
      for (const h of picks) {
        // never push a slot down: if Agile already beats the plan price, keep the
        // real one so the Powerwall still ranks that half-hour above the rest
        sellRates[key(h)] = Math.round(Math.max(realAt(h), ocfg.pence) * 10) / 1000;
        planOn.push(h);
      }
      planExtra.push(...picks.slice().sort((a, b) => a - b));
      planOn.sort((a, b) => a - b);
      log.push("ohme earned " + earned.size + " extra slot(s), took " + picks.length +
        (picks.length ? ": " + picks.slice().sort((a, b) => a - b).map(hhmm).join(", ") : ""));
    }
    log.push("export plan: " + ocfg.pence + "p on " + planOn.length + " slot(s), " +
      skipped + " left at real price (below " + minP + "p)");
  }
  const season = { fromMonth: 1, fromDay: 1, toMonth: 12, toDay: 31 };
  const content = {
    version: 1, monthly_minimum_bill: 0, min_applicable_demand: 0, max_applicable_demand: 0, monthly_charges: 0,
    utility: "Octopus Energy", code: "IOGO-AGILE-SYNC", name: "IO Go buy + Agile sell (auto-sync)", currency: "GBP",
    daily_charges: [{ name: "Charge", amount: 0 }], daily_demand_charges: {},
    demand_charges: { ALL: { rates: { ALL: 0 } }, AllYear: { rates: {} } },
    energy_charges: { ALL: { rates: { ALL: 0 } }, AllYear: { rates: { OFF_PEAK: offP, ON_PEAK: onP } } },
    seasons: { AllYear: { ...season, tou_periods: { OFF_PEAK: touPeriods(off), ON_PEAK: touPeriods(on) } } },
    sell_tariff: {
      min_applicable_demand: 0, monthly_minimum_bill: 0, monthly_charges: 0, max_applicable_demand: 0,
      utility: "Octopus Energy", code: "AGILE-OUTGOING", name: "Agile Outgoing (auto-sync)", currency: "GBP",
      daily_charges: [{ name: "Charge", amount: 0 }], daily_demand_charges: {},
      demand_charges: { ALL: { rates: { ALL: 0 } }, AllYear: { rates: {} } },
      energy_charges: { ALL: { rates: { ALL: 0 } }, AllYear: { rates: sellRates } },
      seasons: { AllYear: { ...season, tou_periods: sellPeriods } },
    },
  };
  await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/time_of_use_settings`, { tou_settings: { tariff_content_v2: content } });
  state.tariffPushed = {
    t: localOffsetISO().slice(0, 19),
    off, offP: Math.round(offP * 10000) / 100, onP: Math.round(onP * 10000) / 100,
    sell: Array.from({ length: 48 }, (_, h) => Math.round(sellRates["R" + String(h).padStart(2, "0")] * 10000) / 100),
    missing: missing.length,
    plan: ocfg.pence > 0 ? { p: ocfg.pence, from: oFrom, to: oTo, minP, extra: planExtra, on: planOn } : null,
    real: realSell,
  };
  log.push(`tariff synced: ${off.length} cheap window(s), sell avg ${avg.toFixed(1)}p`);
  console.log(`tariff synced: off=${JSON.stringify(off)} sellAvg=${avg.toFixed(2)}p`);
  // Persist immediately. When a push runs inside a /cmd request the every-minute
  // cron holds its own copy of state and writes it back afterwards, clobbering
  // this field — the push reached Tesla but the record of it was lost.
  try { await env.PW.put("tariffpush.json", JSON.stringify(state.tariffPushed)); } catch (e) {}
  return true;
}

// R2 is the source of truth for the last push, for the reason above.
async function lastTariffPush(env, state) {
  let cur = state.tariffPushed || null;
  try {
    const o = await env.PW.get("tariffpush.json");
    if (o) {
      const j = JSON.parse(await o.text());
      if (j && (!cur || String(j.t || "") > String(cur.t || ""))) { cur = j; state.tariffPushed = j; }
    }
  } catch (e) {}
  return cur;
}

async function vaillantDhwBoost(env, state, on) {
  const tok = await vaillantToken(env, state);
  const base = (state.vaillantCtrl === "vrc700" ? VAILLANT_API.replace("end-user-app-api/v1", "vrc700/v1") : VAILLANT_API)
    + `/systems/${state.vaillantSys}/${state.vaillantCtrl || "tli"}`;
  const r = await fetch(`${base}/domestic-hot-water/${state.vaillantDhwIdx ?? 255}/boost`, {
    method: on ? "POST" : "DELETE",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json", "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" },
    body: on ? "{}" : undefined,
  });
  if (!r.ok && r.status !== 204) throw new Error(`dhw boost ${r.status}: ${(await r.text()).slice(0, 80)}`);
}
async function applyAutomation(env, state, sid, siteInfo, log) {
  const cfg = state.config;
  const setReserve = async (pct, why) => {
    if (siteInfo.backup_reserve_percent !== pct) {
      await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/backup`, { backup_reserve_percent: Math.round(pct) });
      log.push(`reserve -> ${pct}% (${why})`);
    }
  };
  const setExportRule = async (rule, why) => {
    const cur = ((siteInfo.components || {}).customer_preferred_export_rule);
    if (cur !== rule) {
      await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/grid_import_export`,
        { customer_preferred_export_rule: rule });
      log.push(`export rule -> ${rule} (${why})`);
    }
  };
  const setGridCharging = async (allowed, why) => {
    const cur = ((siteInfo.components || {}).disallow_charge_from_grid_with_solar_installed);
    if (cur !== !allowed) {
      await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/grid_import_export`,
        { disallow_charge_from_grid_with_solar_installed: !allowed });
      log.push(`grid charging -> ${allowed} (${why})`);
    }
  };
  if (cfg.follow_ohme_slots) {
    // fail-safe: if Ohme state is unknown/errored, treat as NOT in a slot so we
    // always revert to day settings rather than staying parked at 100% reserve
    const ohmeOk = state.ohmeData && !state.ohmeData.error;
    const nowIso = new Date().toISOString();
    const inSlot = ohmeOk && (state.ohmeData.slots || []).some((sl) => sl.start <= nowIso && nowIso < sl.end);
    const day = cfg.day || {};
    // "auto" ties slot behaviour to the export window: a cheap slot outside it is
    // a chance to fill the battery, but one inside it would mean importing and
    // exporting in the same half-hour, so we hold instead. Window is read from the
    // export plan config so the two can never drift apart.
    const pw = cfg.export_plan || {};
    const pFrom = (pw.fromH ?? 16) * 60, pTo = (pw.toH ?? 22) * 60;
    const lmNow = localMinuteISO();
    const nowMin = (+lmNow.slice(11, 13)) * 60 + (+lmNow.slice(14, 16));
    const inExportWindow = nowMin >= pFrom && nowMin < pTo;
    const modeCfg = cfg.ohme_slot_mode || "charge";
    const slotMode = modeCfg === "auto" ? (inExportWindow ? "hold" : "charge") : modeCfg;
    // The export rule is asserted from config on every cycle rather than being
    // remembered and restored. The previous version stashed the pre-slot value in
    // state and put it back when the slot ended, which fails the moment the worker
    // restarts mid-slot: the stash is lost, the restore never runs and pv_only
    // latches on indefinitely. That is exactly what happened overnight, and it
    // would have blocked the battery from exporting all of the next day.
    const holdNow = inSlot && slotMode === "hold";
    const wantExport = holdNow
      ? cfg.ohme_hold_export || "pv_only"
      : cfg.ohme_export_normal || "battery_ok";
    const haveExport = (siteInfo.components || {}).customer_preferred_export_rule;
    await setExportRule(wantExport, holdNow ? "ohme slot, hold" : "no hold in effect");
    // Watchdog. pv_only with no hold in effect means either something outside this
    // worker set it, or our own correction is failing. It is completely silent and
    // it costs a whole day of export, so count consecutive cycles and surface it
    // rather than quietly fixing it and moving on.
    if (haveExport === "pv_only" && wantExport !== "pv_only") {
      state.exportStuck = (state.exportStuck || 0) + 1;
      if (state.exportStuck === 1 || state.exportStuck % 15 === 0)
        log.push("WARNING: export was pv_only with no hold in effect (" +
          state.exportStuck + " cycle(s)) - corrected to " + wantExport);
    } else {
      state.exportStuck = 0;
    }
    if (inSlot && slotMode === "hold") {
      // Hold: the cheap import is for the car. Don't pull the Powerwall up on it,
      // and stop the battery exporting so it isn't discharging into a half-hour
      // we're deliberately importing in. Remember the export rule to restore after.
      state.pwSlotCharge = null;
      await setReserve(day.reserve ?? 0, "ohme slot, hold");
      await setGridCharging(false, "ohme slot, hold - cheap import is for the car");
      await setExportRule(cfg.ohme_hold_export || "pv_only", "ohme slot, hold");
    } else if (inSlot) {
      // slot rule: enter below 95% -> charge; stop at 95%; only restart if it drops to 50%
      const soc = (((state.hist || [])[ (state.hist || []).length - 1 ]) || {}).soc ?? 0;
      if (state.pwSlotCharge == null) state.pwSlotCharge = soc < 95 ? 1 : 0;
      if (soc >= 95 && state.pwSlotCharge) { state.pwSlotCharge = 0; log.push(`powerwall ${soc.toFixed(0)}% — charge released, free to export`); }
      else if (soc < 50 && !state.pwSlotCharge) { state.pwSlotCharge = 1; log.push(`powerwall ${soc.toFixed(0)}% — charging in slot`); }
      if (state.pwSlotCharge) { await setReserve(100, "ohme slot, charging to 95%"); await setGridCharging(true, "ohme slot"); }
      else { await setReserve(day.reserve ?? 0, "ohme slot, battery full"); await setGridCharging(true, "always enabled"); }
    } else {
      state.pwSlotCharge = null;
      await setReserve(day.reserve ?? 0, "outside ohme slots");
      await setGridCharging(true, "always enabled");
    }
  }
  // heat the hot water tank to 65° during Ohme off-peak slots, restore after
  if (!(cfg.dhw_ohme_slots && env.MYVAILLANT_EMAIL && state.vaillantSys))
    console.log(`dhw gate closed: cfg=${!!cfg.dhw_ohme_slots} vailEnv=${!!env.MYVAILLANT_EMAIL} sys=${!!state.vaillantSys}`);
  if (cfg.dhw_ohme_slots && env.MYVAILLANT_EMAIL && state.vaillantSys) {
    const ohmeOk2 = state.ohmeData && !state.ohmeData.error;
    const nowIso2 = new Date().toISOString();
    const inSlot2 = ohmeOk2 && (state.ohmeData.slots || []).some((sl) => sl.start <= nowIso2 && nowIso2 < sl.end);
    console.log(`dhw: ohmeOk=${!!ohmeOk2} slots=${JSON.stringify((state.ohmeData || {}).slots || [])} now=${nowIso2} inSlot=${!!inSlot2} boosted=${state.dhwBoosted || 0}`);
    try {
      if (inSlot2 && !state.dhwBoosted) {
        const cur = (((state.home || {}).vaillant) || {}).dhwTarget ?? 45;
        state.dhwPrev = cur >= 58 ? (state.dhwPrev ?? 45) : cur;   // never save a boosted target as "previous"
        await vaillantSetDhw(env, state, 60);
        // setpoint alone is passive — the boost forces heating now, regardless of the DHW schedule
        try { await vaillantDhwBoost(env, state, true); log.push(`hot water -> 60° + boost on (ohme slot, was ${state.dhwPrev}°)`); }
        catch (e) { log.push(`hot water -> 60°, boost failed: ${String(e).slice(0, 70)}`); }
        state.dhwBoosted = 1;
      } else if (!inSlot2 && state.dhwBoosted) {
        await vaillantSetDhw(env, state, state.dhwPrev ?? 45);
        try { await vaillantDhwBoost(env, state, false); } catch (e) {}
        log.push(`hot water -> ${state.dhwPrev ?? 45}°, boost off (slot ended)`);
        state.dhwBoosted = 0;
      }
    } catch (e) { log.push("dhw automation: " + String(e).slice(0, 100)); }
  }
  if (cfg.enabled) {
    const cw = cfg.cheap_window || {};
    if (cw.enabled) {
      const t = hhmm(), inWin = cw.start < cw.end ? (t >= cw.start && t < cw.end) : (t >= cw.start || t < cw.end);
      const tgt = inWin ? cw : (cfg.day || {});
      await setReserve(tgt.reserve ?? 0, inWin ? "cheap window" : "daytime");
      await setGridCharging(true, "always enabled");
    }
  }
}

/* ---------------- energy daily + backfill ---------------- */
async function fetchEnergyDaily(env, state, sid) {
  const monthSeries = async (anchor) => {
    const r = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/calendar_history`, null,
      { kind: "energy", period: "month", end_date: localOffsetISO(anchor), time_zone: TZ });
    return (r || {}).time_series || [];
  };
  const now = new Date();
  // month anchors at NOON UTC on the month's last day — 23:59 UTC is already the
  // next month in BST, which silently skipped whole months (June was never fetched)
  const monthEnd = (mBack) => new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - mBack + 1, 0, 12));
  let rows = [
    ...await monthSeries(monthEnd(1)),
    ...await monthSeries(now),
  ];
  // one-off deep fill: 12 months of daily history, then cached in state
  // (waits for the octopus fill to finish so one tick never does both)
  if (!state.energyDeepFill && state.octoDeepFill) {
    for (let mBack = 2; mBack <= 25; mBack++) {
      try {
        rows = rows.concat(await monthSeries(monthEnd(mBack)));
      } catch (e) {}
    }
    state.energyDeepFill = 1;
  }
  // Tesla may return sub-daily rows — aggregate freshly fetched rows per day
  const fresh = {};
  for (const r of rows) {
    const day = (r.timestamp || "").slice(0, 10);
    if (!day) continue;
    const o = (fresh[day] = fresh[day] || { timestamp: day + "T00:00:00" });
    for (const [k, v] of Object.entries(r)) {
      if (typeof v === "number") o[k] = (o[k] || 0) + v;
    }
  }
  // merge: cached daily rows, overwritten by fresh aggregates
  const byDay = {};
  for (const r of state.energyDaily || []) if (r.timestamp) byDay[r.timestamp.slice(0, 10)] = r;
  Object.assign(byDay, fresh);
  return Object.keys(byDay).sort().map((k) => byDay[k]).slice(-750);
}
async function backfillHistory(env, state, sid) {
  const merged = {};
  for (const p of state.hist) if (p.t) merged[p.t.slice(0, 16)] = p;
  for (let off = 2; off >= 0; off--) {
    const d = new Date(Date.now() - off * 864e5);
    const r = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/calendar_history`, null,
      { kind: "power", period: "day", end_date: londonDayEndISO(d), time_zone: TZ });
    for (const row of (r || {}).time_series || []) {
      const ts = (row.timestamp || "").slice(0, 16);
      if (!ts || merged[ts]) continue;
      const so = row.solar_power || 0, ba = row.battery_power || 0, gr = row.grid_power || 0;
      merged[ts] = { t: ts, soc: row.percentage_charged, solar: so, grid: gr, battery: ba,
        load: row.load_power != null ? row.load_power : so + ba + gr };
    }
  }
  state.hist = Object.values(merged).sort((a, b) => (a.t < b.t ? -1 : 1)).slice(-HIST_MAX);
}

// rebuild a day's cost ledger from the (self-healed) minute/5-min history — used
// after an outage, when the live per-minute accumulation has holes
function rebuildLedgerDay(state, dKey) {
  const rows = state.hist.filter((p) => p.t && p.t.slice(0, 10) === dKey).sort((a, b) => (a.t < b.t ? -1 : 1));
  if (!rows.length) return false;
  const day = { impOff: 0, impPeak: 0, basisOff: 0, basisPeak: 0, exp: 0, rebuilt: 1 };
  for (let i = 0; i < rows.length; i++) {
    const p = rows[i];
    let dt = 1 / 60;
    if (i + 1 < rows.length) {
      const gap = (Date.parse(rows[i + 1].t + ":00Z") - Date.parse(p.t + ":00Z")) / 36e5;
      if (gap > 0) dt = Math.min(gap, 1 / 6); // cap at 10 min so big holes don't overweight
    }
    const hm = p.t.slice(11, 16);
    const off = (hm >= "23:30" || hm < "05:30") || p.io || (p.ev || 0) > 250;
    const imp = Math.max(p.grid || 0, 0) + (p.ev || 0), ex = Math.max(-(p.grid || 0), 0);
    const basis = Math.max(p.load || 0, 0) + Math.max(-(p.battery || 0), 0) + (p.ev || 0);
    if (off) { day.impOff += imp * dt; day.basisOff += basis * dt; }
    else { day.impPeak += imp * dt; day.basisPeak += basis * dt; }
    day.exp += ex * dt;
  }
  (state.ledger = state.ledger || {})[dKey] = day;
  return true;
}

/* ---------------- poll cycle ---------------- */
async function pollCycle(env, state, opts = {}) {
  const log = [];
  const sid = await siteId(env, state);
  const now = Date.now() / 1000;

  const live = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/live_status`);
  const nowIso = new Date().toISOString();
  const inIoSlot = (((state.ohmeData || {}).slots) || []).some((sl) => sl.start <= nowIso && nowIso < sl.end);
  state.hist.push({
    t: localMinuteISO(), soc: live.percentage_charged, solar: live.solar_power,
    load: live.load_power, grid: live.grid_power, battery: live.battery_power,
    ...(inIoSlot ? { io: 1 } : {}),
    ...(state.ohmeData && !state.ohmeData.error ? { ev: (state.ohmeData.power || {}).watts || 0 } : {}),
  });
  // fast release: the main automation runs on a ~4-min cadence, but at full grid-charge
  // rate that overshoots the 95% stop line — so check the stop condition every minute.
  if (state.pwSlotCharge === 1 && (live.percentage_charged || 0) >= 95) {
    try {
      const day = (state.config || {}).day || {};
      await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/backup`, { backup_reserve_percent: Math.round(day.reserve ?? 0) });
      state.pwSlotCharge = 0;
      if (state.siteInfo) state.siteInfo.backup_reserve_percent = Math.round(day.reserve ?? 0);
      log.push(`powerwall ${(live.percentage_charged || 0).toFixed(0)}% — charge released`);
    } catch (e) { log.push("fast release: " + String(e).slice(0, 80)); }
  }
  // daily battery-health sample: capacity fade needs total_pack_energy over time.
  // record the day's peak observed capacity + energy (near full = most accurate).
  {
    const dKey = localMinuteISO().slice(0, 10);
    const H = (state.pwHealth = state.pwHealth || {});
    const cap = live.total_pack_energy || 0, left = live.energy_left || 0, soc = live.percentage_charged || 0;
    if (cap > 0) {
      const rec = (H[dKey] = H[dKey] || { d: dKey, cap: 0, left: 0, socMax: 0 });
      if (cap > rec.cap) rec.cap = cap;              // best (fullest) capacity reading of the day
      if (soc > rec.socMax) { rec.socMax = soc; rec.left = left; }
      const ks = Object.keys(H).sort();
      for (const k of ks.slice(0, Math.max(0, ks.length - 800))) delete H[k]; // ~2 years
    }
  }
  // permanent daily ledger: exact off-peak/peak accumulation, minute by minute
  {
    const t = hhmm();
    const evW = (state.ohmeData && !state.ohmeData.error && (state.ohmeData.power || {}).watts) || 0;
    const off = (t >= "23:30" || t < "05:30") || inIoSlot || evW > 250;
    const dKey = localMinuteISO().slice(0, 10);
    const L = (state.ledger = state.ledger || {});
    const day = (L[dKey] = L[dKey] || { impOff: 0, impPeak: 0, basisOff: 0, basisPeak: 0, exp: 0 });
    const dt = 1 / 60;
    // the Ohme circuit bypasses Tesla's CTs: its draw is real grid import too
    const impW = Math.max(live.grid_power || 0, 0) + evW, expW = Math.max(-(live.grid_power || 0), 0);
    const basisW = Math.max(live.load_power || 0, 0) + Math.max(-(live.battery_power || 0), 0) + evW;
    if (off) { day.impOff += impW * dt; day.basisOff += basisW * dt; }
    else { day.impPeak += impW * dt; day.basisPeak += basisW * dt; }
    day.exp += expW * dt;
    const keys = Object.keys(L).sort();
    for (const k of keys.slice(0, Math.max(0, keys.length - 400))) delete L[k];
  }
  // background ledger reconstruction: fill past days from Tesla's 5-min power history
  // (skipped on ticks doing other heavy work, to stay under subrequest limits)
  const heavyTick = !state.octoDeepFill || !state.energyDeepFill;
  if (!state.ledgerFillDone && !heavyTick) {
    try {
      state.ledgerFillCursor = state.ledgerFillCursor ?? 2;
      let n = 0;
      while (n < 8 && state.ledgerFillCursor <= 370) {
        const d = new Date(Date.now() - state.ledgerFillCursor * 864e5);
        const dKey = londonDayEndISO(d).slice(0, 10);
        if (!(state.ledger || {})[dKey]) {
          const r = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/calendar_history`, null,
            { kind: "power", period: "day", end_date: londonDayEndISO(d), time_zone: TZ });
          const day = { impOff: 0, impPeak: 0, basisOff: 0, basisPeak: 0, exp: 0, fill: 1 };
          let count = 0;
          for (const row of (r || {}).time_series || []) {
            const hm = (row.timestamp || "").slice(11, 16);
            const off = hm >= "23:30" || hm < "05:30";
            const dt = 5 / 60;
            const so = row.solar_power || 0, ba = row.battery_power || 0, gr = row.grid_power || 0;
            const lo = row.load_power != null ? row.load_power : so + ba + gr;
            const imp = Math.max(gr, 0), ex = Math.max(-gr, 0);
            const basis = Math.max(lo, 0) + Math.max(-ba, 0);
            if (off) { day.impOff += imp * dt; day.basisOff += basis * dt; }
            else { day.impPeak += imp * dt; day.basisPeak += basis * dt; }
            day.exp += ex * dt; count++;
          }
          if (count > 0) { state.ledger = state.ledger || {}; state.ledger[dKey] = day; }
          n++;
        }
        state.ledgerFillCursor++;
      }
      if (state.ledgerFillCursor > 370) state.ledgerFillDone = 1;
    } catch (e) { log.push("ledgerfill error: " + String(e).slice(0, 100)); }
  }
  // per-day 15-min bins for the dashboard day picker: self-healing scan — any day
  // in the last 35 with missing/sparse bins is refetched from Tesla's 5-min history
  // (merged under existing live bins, which carry EV data Tesla can't see)
  if (state.ledgerFillDone && !heavyTick && now - (state.lastBinScan || 0) > 1800) {
    state.lastBinScan = now;
    try {
      state.dayBins = state.dayBins || {};
      let n = 0;
      for (let off = 1; off <= 35 && n < 3; off++) {
        const d = new Date(Date.now() - off * 864e5);
        const dKey = londonDayEndISO(d).slice(0, 10);
        const existing = state.dayBins[dKey];
        const filled = existing ? existing.filter(Boolean).length : 0;
        if (filled >= 88) continue; // effectively complete
        const r = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/calendar_history`, null,
          { kind: "power", period: "day", end_date: londonDayEndISO(d), time_zone: TZ });
        const sums = Array(96).fill(null), cnt = Array(96).fill(0);
        for (const row of (r || {}).time_series || []) {
          const ts = row.timestamp || "";
          const idx = parseInt(ts.slice(11, 13), 10) * 4 + Math.floor(parseInt(ts.slice(14, 16), 10) / 15);
          if (!(idx >= 0 && idx < 96)) continue;
          const b = (sums[idx] = sums[idx] || [0, 0, 0, 0, 0]);
          const so = row.solar_power || 0, ba = row.battery_power || 0, gr = row.grid_power || 0;
          b[0] += so; b[1] += row.load_power != null ? row.load_power : so + ba + gr;
          b[2] += gr; b[3] += ba; cnt[idx]++;
        }
        if (cnt.some((c) => c > 0)) {
          const fresh = sums.map((b, i) => (b && cnt[i] ? b.map((v) => Math.round(v / cnt[i])) : null));
          // live bins win (they include EV); Tesla fills the gaps
          state.dayBins[dKey] = fresh.map((f, i) => (existing && existing[i]) || f);
          state.binsDirty = 1; n++;
        }
      }
    } catch (e) { log.push("daybins error: " + String(e).slice(0, 100)); }
  }
  // dedupe + trim
  const seen = new Set(); const dedup = [];
  for (const p of state.hist) { const k = (p.t || "").slice(0, 16); if (!seen.has(k)) { seen.add(k); dedup.push(p); } }
  state.hist = dedup.slice(-HIST_MAX);

  // slower loops
  if (!state.siteInfo || now - (state.lastInfo || 0) > 240 || opts.force) {
    state.siteInfo = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/site_info`);
    state.lastInfo = now;
    try { state.ohmeData = env.OHME_EMAIL ? await fetchOhme(env, state) : null; }
    catch (e) { state.ohmeData = { error: String(e).slice(0, 150) }; }
    try {
      await applyAutomation(env, state, sid, state.siteInfo, log);
      if (log.length) { state.siteInfo = await tesla(env, state, "GET", `/api/1/energy_sites/${sid}/site_info`); state.lastLog = log; }
    } catch (e) { log.push("automation error: " + String(e).slice(0, 120)); }
    // tesla tariff sync — repush when the day rolls over or granted slots change
    try {
      const ts = ((state.config || {}).tariff_sync) || {};
      if (ts.enabled) {
        // config is part of the signature so changing the export plan or the
        // buy rates forces a push on the next cycle instead of waiting for midnight
        const sig = localMinuteISO().slice(0, 10)
          + JSON.stringify(tariffIntervals(state).off)
          + JSON.stringify(ts)
          + JSON.stringify((((state.ohmeData || {}).slots) || []).map((s) => s.start + '/' + s.end))
          + JSON.stringify((state.config || {}).export_plan || null);
        // 5-min throttle: a fresh Ohme grant minutes after a push (e.g. the midnight
        // rewrite) must reach the Powerwall while the slot is still running
        if (state.tariffSig !== sig && now - (state.lastTariffPush || 0) > 300) {
          // only record success on an actual push — a silent no-op previously
          // suppressed every retry until the day rolled over
          if (await pushTariff(env, state, sid, log)) { state.tariffSig = sig; state.lastTariffPush = now; }
        }
      }
    } catch (e) { log.push("tariff sync: " + String(e).slice(0, 120)); console.log("tariff sync failed: " + String(e).slice(0, 200)); }
  }
  // daily energy counters refresh fast (5 min) so today's totals track NetZero/Tesla;
  // the heavier self-heal work below stays on the 30-min cadence
  if (!state.energyDaily || now - (state.lastEnergy || 0) > 300 || opts.force) {
    try { state.energyDaily = await fetchEnergyDaily(env, state, sid); state.lastEnergy = now; }
    catch (e) { log.push("energy error: " + String(e).slice(0, 120)); }
  }
  if (now - (state.lastHeavy || 0) > 1800 || opts.force) {
    state.lastHeavy = now;
    // self-heal intraday chart gaps from Tesla's stored 5-min power history
    try { await backfillHistory(env, state, sid); state.hist = state.hist.slice(-HIST_MAX); }
    catch (e) { log.push("autofill error: " + String(e).slice(0, 120)); }
    // refresh per-day bins for the days covered by the minute history (incl. ev)
    try {
      const bins = (state.dayBins = state.dayBins || {});
      const sums = {}, cnts = {};
      for (const p of state.hist) {
        if (!p.t) continue;
        const dk = p.t.slice(0, 10);
        const idx = parseInt(p.t.slice(11, 13), 10) * 4 + Math.floor(parseInt(p.t.slice(14, 16), 10) / 15);
        if (!(idx >= 0 && idx < 96)) continue;
        const S = (sums[dk] = sums[dk] || Array(96).fill(null));
        const C = (cnts[dk] = cnts[dk] || Array(96).fill(0));
        const b = (S[idx] = S[idx] || [0, 0, 0, 0, 0]);
        b[0] += p.solar || 0; b[1] += p.load || 0; b[2] += p.grid || 0; b[3] += p.battery || 0; b[4] += p.ev || 0;
        C[idx]++;
      }
      for (const dk of Object.keys(sums)) {
        const fresh = sums[dk].map((b, i) => (b && cnts[dk][i] ? b.map((v) => Math.round(v / cnts[dk][i])) : null));
        // merge: never wipe a day's earlier hours just because they've left the hist window
        const old = bins[dk];
        bins[dk] = fresh.map((f, i) => f || (old && old[i]) || null);
      }
      const keys = Object.keys(bins).sort();
      for (const k of keys.slice(0, Math.max(0, keys.length - 35))) delete bins[k];
      state.binsDirty = 1;
    } catch (e) {}
    // solar forecast: Open-Meteo irradiance scaled to this system's observed peak
    try {
      const si = state.siteInfo || {};
      const lat = si.latitude ?? 51.5, lon = si.longitude ?? -0.12;
      const r = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&hourly=shortwave_radiation&forecast_days=1&timezone=Europe%2FLondon`);
      if (r.ok) {
        const rad = ((await r.json()).hourly || {}).shortwave_radiation || [];
        let maxSolar = 3000;
        for (const p of state.hist) if ((p.solar || 0) > maxSolar) maxSolar = p.solar;
        const k = maxSolar / 900; // ~900 W/m² ≈ observed peak output
        state.solarForecast = rad.slice(0, 24).map((v, h) => ({ h, w: Math.round(Math.max(0, (v || 0) * k)) }));
      }
    } catch (e) {}
  }
  // tado device-code approval pending: poll every tick until Jon confirms
  if (state.tadoDevice) { try { await tadoPollToken(env, state, log); } catch (e) {} }
  // home integrations (tado / vaillant / eero) every 5 min
  if (now - (state.lastHome || 0) > 300 || opts.force) {
    state.lastHome = now;
    // heat pump energy report data, hourly
    if (now - (state.lastVailEnergy || 0) > 3600) {
      state.lastVailEnergy = now;
      try { await fetchVaillantEnergy(env, state, log); } catch (e) { log.push("vail energy: " + String(e).slice(0, 80)); }
    }
    // Oura ring, hourly (data only changes after the ring syncs)
    if (now - (state.lastOura || 0) > 3600 || opts.force) {
      state.lastOura = now;
      try { state.oura = await fetchOura(env); } catch (e) { log.push("oura: " + String(e).slice(0, 80)); }
      // pair each synced night with the sampled bedroom temperature
      try {
        const o = state.oura || {};
        if (o.nights && o.nights.length) {
          const SL = (state.sleepLog = state.sleepLog || []);
          const have = new Set(SL.map((x) => x.d));
          for (const n of o.nights) {
            const b = ((state.bedNights || {})[n.day]);
            if (!b || !b.n || have.has(n.day)) continue;
            const sc = (o.sleep || []).find((s) => s.day === n.day) || {};
            SL.push({ d: n.day, temp: Math.round(10 * b.sum / b.n) / 10, tmin: b.min, tmax: b.max, room: b.room,
              score: sc.score ?? null, deep: n.deep, rem: n.rem, dur: n.dur, eff: n.eff, hrv: n.hrv, lhr: n.lhr });
          }
          SL.sort((a, b) => (a.d < b.d ? -1 : 1));
          if (SL.length > 400) SL.splice(0, SL.length - 400);
        }
      } catch (e) {}
    }
    await refreshHome(env, state, log);
  }
  if (env.OCTOPUS_API_KEY && (!state.octopus || !state.octoDeepFill || now - (state.lastOcto || 0) > 1800 || opts.force)) {
    try { state.octopus = await fetchOctopus(env, state); state.lastOcto = now; }
    catch (e) {
      // keep the previous good data; note the error; retry in 5 min, not every tick
      const msg = String(e).slice(0, 150);
      if (state.octopus && state.octopus.daily) state.octopus.error = msg;
      else state.octopus = { error: msg };
      state.lastOcto = now - 1500;
      log.push("octopus error: " + msg.slice(0, 80));
    }
  }

  // heat pump live draw (myVAILLANT mpc) every tick — feeds the flow scene
  if (env.MYVAILLANT_EMAIL && state.vaillantSys) {
    try {
      const tok = await vaillantToken(env, state);
      const r = await fetch(`${VAILLANT_API}/hem/${state.vaillantSys}/mpc`, { headers: { Authorization: `Bearer ${tok}`, "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "Accept": "application/json, text/plain, */*", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" } });
      if (r.ok) {
        const mpc = await r.json();
        const w = ((mpc || {}).devices || []).reduce((a, d) => a + (d.currentPower ?? d.current_power ?? 0), 0);
        state.hp = { w: Math.round(w), t: new Date().toISOString() };
      }
    } catch (e) {}
  }

  const bundle = {
    generated_at: localOffsetISO().slice(0, 19),
    site_name: state.siteName,
    live,
    site_info: (({ backup_reserve_percent, default_real_mode, installation_date, nameplate_power,
      nameplate_energy, battery_count, user_settings, components }) =>
      ({ backup_reserve_percent, default_real_mode, installation_date, nameplate_power,
         nameplate_energy, battery_count, user_settings, components }))(state.siteInfo || {}),
    // recent slices only — full 750-day history lives in the archive blob (/daybins)
    energy_daily: (state.energyDaily || []).slice(-60),
    solar_forecast: state.solarForecast || [],
    ledger: state.ledger || {},
    history: state.hist,
    automations: state.config,
    log: log.length ? log : (state.lastLog || []),
    octopus: state.octopus ? { ...state.octopus, daily: (state.octopus.daily || []).slice(-60) } : null,
    ohme: state.ohmeData || null,
    hp: state.hp || null,
    pw_health: Object.values(state.pwHealth || {}).sort((a, b) => (a.d < b.d ? -1 : 1)).slice(-400),
    tariff_push: await lastTariffPush(env, state),
    export_stuck: state.exportStuck || 0,
    source: "cloudflare-worker",
  };
  const enc = await encryptBundle(state, bundle);
  await env.PW.put("dashboard.enc", enc);
  // tiny access snapshot for the live-streaming Durable Object (never refreshes
  // tokens itself — avoids racing the single-use refresh-token rotation)
  try {
    await env.PW.put("access.json", JSON.stringify({
      access_token: state.access_token, access_exp: state.access_exp, siteId: state.siteId,
    }));
  } catch (e) {}
  try { if (state.hp) await env.PW.put("hp.json", JSON.stringify(state.hp)); } catch (e) {}
  // archive blob (day bins + full daily history), written only when it changes
  // (~every 30 min) — keeps the every-minute encrypt small and CPU per tick down
  if (state.binsDirty) {
    await env.PW.put("daybins.enc", await encryptBundle(state, {
      day_bins: state.dayBins || {},
      energy_daily: state.energyDaily || [],
      octopus_daily: ((state.octopus || {}).daily) || [],
    }));
    state.binsDirty = 0;
  }
  await saveState(env, state);
  console.log("wrote dashboard.enc", enc.length, "chars,", state.hist.length, "samples");
  return log;
}

/* ---------------- commands ---------------- */
async function runCommand(env, state, command, value) {
  const sid = await siteId(env, state);
  const log = [];
  if (command === "reserve") {
    await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/backup`, { backup_reserve_percent: parseInt(value, 10) });
    log.push(`reserve -> ${value}% (manual)`);
  } else if (command === "mode") {
    await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/operation`, { default_real_mode: value });
    log.push(`mode -> ${value} (manual)`);
  } else if (command === "storm") {
    await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/storm_mode`, { enabled: value === "on" });
    log.push(`storm -> ${value} (manual)`);
  } else if (command === "grid_charging") {
    await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/grid_import_export`,
      { disallow_charge_from_grid_with_solar_installed: value !== "on" });
    log.push(`grid charging -> ${value} (manual)`);
  } else if (command === "tado_presence") {
    const tok = await tadoToken(env, state);
    const r = await fetch(`https://my.tado.com/api/v2/homes/${state.tadoHome}/presenceLock`, {
      method: "PUT", headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
      body: JSON.stringify({ homePresence: value }),
    });
    if (!r.ok && r.status !== 204) throw new Error(`tado presence ${r.status}`);
    log.push(`tado home mode -> ${value}`);
  } else if (command === "tado_set") {
    const [zid, temp] = String(value).split("|");
    const tok = await tadoToken(env, state);
    const r = await fetch(`https://my.tado.com/api/v2/homes/${state.tadoHome}/zones/${zid}/overlay`, {
      method: "PUT", headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        setting: { type: "HEATING", power: "ON", temperature: { celsius: parseFloat(temp) } },
        termination: { type: "TADO_MODE" },
      }),
    });
    if (!r.ok) throw new Error(`tado set ${r.status}: ${(await r.text()).slice(0, 100)}`);
    log.push(`tado zone ${zid} -> ${temp}° (until schedule change)`);
  } else if (command === "tado_set_all" || command === "tado_resume_all") {
    const tok = await tadoToken(env, state);
    const zr = await fetch(`https://my.tado.com/api/v2/homes/${state.tadoHome}/zones`, { headers: { Authorization: `Bearer ${tok}` } });
    const zones = (await zr.json()).filter((z) => z.type === "HEATING");
    let n = 0;
    for (const z of zones) {
      const url = `https://my.tado.com/api/v2/homes/${state.tadoHome}/zones/${z.id}/overlay`;
      const r = command === "tado_set_all"
        ? await fetch(url, { method: "PUT", headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
            body: JSON.stringify({ setting: { type: "HEATING", power: "ON", temperature: { celsius: parseFloat(value) } }, termination: { type: "TADO_MODE" } }) })
        : await fetch(url, { method: "DELETE", headers: { Authorization: `Bearer ${tok}` } });
      if (r.ok || r.status === 204) n++;
    }
    log.push(command === "tado_set_all" ? `all rooms -> ${value}° (${n}/${zones.length})` : `all rooms -> schedule (${n}/${zones.length})`);
  } else if (command === "eero_pause") {
    const [durl, on] = String(value).split("|");
    const path = durl.replace(/^\/2\.2\//, "");
    const r = await fetch(`https://api-user.e2ro.com/2.2/${path}`, {
      method: "PUT", headers: { Cookie: `s=${state.eeroTok}`, "Content-Type": "application/json" },
      body: JSON.stringify({ paused: on === "on" }),
    });
    const j = await r.json().catch(() => ({}));
    if ((((j || {}).meta || {}).code) !== 200) throw new Error(`eero pause ${JSON.stringify((j || {}).meta).slice(0, 80)}`);
    log.push(`device ${on === "on" ? "paused" : "resumed"}`);
  } else if (command === "tado_resume") {
    const tok = await tadoToken(env, state);
    const r = await fetch(`https://my.tado.com/api/v2/homes/${state.tadoHome}/zones/${value}/overlay`, {
      method: "DELETE", headers: { Authorization: `Bearer ${tok}` },
    });
    if (!r.ok && r.status !== 204) throw new Error(`tado resume ${r.status}`);
    log.push(`tado zone ${value} -> back to schedule`);
  } else if (command.startsWith("vaillant_")) {
    const tok = await vaillantToken(env, state);
    const base = (state.vaillantCtrl === "vrc700" ? VAILLANT_API.replace("end-user-app-api/v1", "vrc700/v1") : VAILLANT_API)
      + `/systems/${state.vaillantSys}/${state.vaillantCtrl || "tli"}`;
    const vh = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json", "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" };
    const vreq = async (method, path, body) => {
      const r = await fetch(base + path, { method, headers: vh, body: body ? JSON.stringify(body) : undefined });
      if (!r.ok && r.status !== 204) throw new Error(`vaillant ${path} ${r.status}: ${(await r.text()).slice(0, 100)}`);
    };
    if (command === "vaillant_dhw_boost") {
      const dIdx = state.vaillantDhwIdx ?? 255;
      if (value === "on") { await vreq("POST", `/domestic-hot-water/${dIdx}/boost`, {}); log.push("hot water boost started"); }
      else { await vreq("DELETE", `/domestic-hot-water/${dIdx}/boost`); log.push("hot water boost cancelled"); }
    } else if (command === "vaillant_dhw_temp") {
      await vreq("PATCH", `/domestic-hot-water/${state.vaillantDhwIdx ?? 255}/temperature`, { setpoint: Math.round(parseFloat(value)) });
      log.push(`hot water target -> ${Math.round(parseFloat(value))}°`);
    } else if (command === "vaillant_veto") {
      const [idx, temp] = String(value).split("|");
      await vreq("POST", `/zones/${idx}/quick-veto`, { desiredRoomTemperatureSetpoint: parseFloat(temp), duration: 4 });
      log.push(`zone ${idx} veto -> ${temp}° for 4h`);
    } else if (command === "vaillant_veto_cancel") {
      await vreq("DELETE", `/zones/${value}/quick-veto`);
      log.push(`zone ${value} veto cancelled`);
    }
  } else if (command === "eero_reboot" || command === "eero_guest" || command === "eero_speedtest") {
    const ecall = async (method, p, body) => {
      const r = await fetch(`https://api-user.e2ro.com/2.2/${p}`, {
        method, headers: { Cookie: `s=${state.eeroTok}`, "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      const j = await r.json().catch(() => ({}));
      const code = ((j || {}).meta || {}).code;
      if (code !== 200 && code !== 201 && code !== 202) throw new Error(`eero ${p} ${code}: ${JSON.stringify((j || {}).meta).slice(0, 80)}`);
      return j.data;
    };
    if (command === "eero_reboot") { await ecall("POST", `eeros/${value}/reboot`); log.push(`rebooting eero ${value}`); }
    else if (command === "eero_guest") { await ecall("PUT", `networks/${state.eeroNet}/guestnetwork`, { enabled: value === "on" }); log.push(`guest network -> ${value}`); }
    else { await ecall("POST", `networks/${state.eeroNet}/speedtest`, {}); log.push("speed test started — results in a few minutes"); }
  } else if (command === "tado_auth") {
    const r = await fetch("https://login.tado.com/oauth2/device_authorize?" + new URLSearchParams({
      client_id: TADO_CLIENT, scope: "offline_access",
    }), { method: "POST" });
    const j = await r.json();
    if (!j.device_code) throw new Error("tado device_authorize failed");
    state.tadoDevice = { device_code: j.device_code, expires: Date.now() / 1000 + (j.expires_in || 300) };
    log.push(`tado: approve at ${j.verification_uri_complete} (code ${j.user_code})`);
  } else if (command === "eero_login") {
    const r = await fetch("https://api-user.e2ro.com/2.2/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: value }),
    });
    const j = await r.json();
    if ((((j || {}).meta || {}).code) !== 200) throw new Error("eero login: " + JSON.stringify(j.meta).slice(0, 100));
    state.eeroPending = j.data.user_token;
    log.push("eero: verification code sent — enter it with Verify");
  } else if (command === "eero_verify") {
    if (!state.eeroPending) throw new Error("run eero login first");
    const r = await fetch("https://api-user.e2ro.com/2.2/login/verify", {
      method: "POST", headers: { "Content-Type": "application/json", Cookie: `s=${state.eeroPending}` },
      body: JSON.stringify({ code: String(value).trim() }),
    });
    const j = await r.json();
    if ((((j || {}).meta || {}).code) !== 200) throw new Error("eero verify: " + JSON.stringify(j.meta).slice(0, 100));
    state.eeroTok = state.eeroPending; delete state.eeroPending; delete state.eeroNet;
    log.push("eero connected ✓");
  } else if (command === "export_rule") {
    // battery_ok = export everything (solar + Powerwall), pv_only = solar only, never = no export
    const rule = { everything: "battery_ok", solar: "pv_only", never: "never" }[value] || value;
    await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/grid_import_export`,
      { customer_preferred_export_rule: rule });
    log.push(`export rule -> ${rule} (manual)`);
  } else if (command === "ohme_mode") {
    state.config.ohme_slot_mode = ["hold", "charge", "auto"].indexOf(value) >= 0 ? value : "auto";
    log.push(`ohme slot mode -> ${state.config.ohme_slot_mode}`);
  } else if (command === "follow_ohme") {
    state.config.follow_ohme_slots = value === "on";
    log.push(`follow ohme slots -> ${value}`);
  } else if (command === "tariff_sync") {
    state.config.tariff_sync = state.config.tariff_sync || {};
    state.config.tariff_sync.enabled = value === "on";
    if (value === "on") { state.tariffSig = null; log.push("tariff sync on — pushing within ~5 min"); }
    else log.push("tariff sync off — re-pick your plan in the Tesla app, or use Restore");
  } else if (command === "tariff_push") {
    await pushTariff(env, state, await siteId(env, state), log);
    state.lastTariffPush = Date.now() / 1000;
  } else if (command === "tariff_restore") {
    const o = await env.PW.get("tariff_backup.json");
    if (!o) throw new Error("no tariff backup stored");
    await tesla(env, state, "POST", `/api/1/energy_sites/${await siteId(env, state)}/time_of_use_settings`,
      { tou_settings: { tariff_content_v2: JSON.parse(await o.text()) } });
    if (state.config.tariff_sync) state.config.tariff_sync.enabled = false;
    log.push("original tariff restored, sync disabled");
  } else if (command === "dhw_ohme") {
    state.config.dhw_ohme_slots = value === "on";
    if (value !== "on" && state.dhwBoosted) {
      try { await vaillantSetDhw(env, state, state.dhwPrev ?? 45); state.dhwBoosted = 0; log.push(`hot water restored to ${state.dhwPrev ?? 45}°`); } catch (e) {}
    }
    log.push(`hot water in ohme slots -> ${value}`);
  } else if (command === "automation") {
    state.config.enabled = value === "on";
    log.push(`automation -> ${value}`);
  } else if (command === "backfill") {
    await backfillHistory(env, state, sid);
    log.push(`backfilled (${state.hist.length} samples)`);
    // rebuild today's + yesterday's cost ledger from the healed history
    for (const off of [1, 0]) {
      const dKey = localMinuteISO(new Date(Date.now() - off * 864e5)).slice(0, 10);
      if (rebuildLedgerDay(state, dKey)) log.push(`ledger rebuilt for ${dKey}`);
    }
  } // "poll" falls through — cycle below refreshes everything
  state.lastLog = log;
  await pollCycle(env, state, { force: true });
  return log;
}

/* ---------------- home integrations: tado / vaillant / eero ---------------- */
const TADO_CLIENT = "1bb50063-6b0c-4d11-bd99-387f4a91cc46";
async function tadoPollToken(env, state, log) {
  // device-code flow pending: poll until Jon approves in the browser
  const dv = state.tadoDevice;
  if (!dv) return;
  if (Date.now() / 1000 > dv.expires) { delete state.tadoDevice; log.push("tado auth expired — run Connect tado again"); return; }
  const r = await fetch("https://login.tado.com/oauth2/token?" + new URLSearchParams({
    client_id: TADO_CLIENT, device_code: dv.device_code,
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
  }), { method: "POST" });
  const j = await r.json().catch(() => ({}));
  if (j.access_token) {
    state.tado = { access: j.access_token, exp: Date.now() / 1000 + (j.expires_in || 599) - 60, refresh: j.refresh_token };
    try { await env.PW.put("tado_rt.txt", j.refresh_token); } catch (e) {}
    delete state.tadoDevice;
    // fresh token — clear any rate-limit backoff/error and force an immediate refresh
    if (state.tadoCache) state.tadoCache.backoffT = 0;
    state.lastTado = 0;
    if (state.home && state.home.tado) delete state.home.tado.error;
    try { state.home = state.home || {}; state.home.tado = await fetchTado(env, state); state.lastTado = Date.now() / 1000;
      await env.PW.put("home.enc", await encryptBundle(state, { generated_at: localOffsetISO().slice(0, 19), ...state.home })); } catch (e) {}
    log.push("tado connected ✓");
  }
}
async function tadoToken(env, state) {
  const t = (state.tado = state.tado || {});
  if (t.access && Date.now() / 1000 < (t.exp || 0)) return t.access;
  let mirror = null;
  try { const o = await env.PW.get("tado_rt.txt"); if (o) mirror = (await o.text()).trim(); } catch (e) {}
  const candidates = [...new Set([t.refresh, mirror].filter(Boolean))];
  let lastErr = "tado not connected";
  for (const rt of candidates) {
    const r = await fetch("https://login.tado.com/oauth2/token?" + new URLSearchParams({
      client_id: TADO_CLIENT, grant_type: "refresh_token", refresh_token: rt,
    }), { method: "POST" });
    const j = await r.json().catch(() => ({}));
    if (j.access_token) {
      t.access = j.access_token; t.exp = Date.now() / 1000 + (j.expires_in || 599) - 60; t.refresh = j.refresh_token;
      try { await env.PW.put("tado_rt.txt", j.refresh_token); } catch (e) {}
      await saveState(env, state);
      return t.access;
    }
    lastErr = JSON.stringify(j).slice(0, 120);
  }
  throw new Error("tado token: " + lastErr);
}
async function fetchTado(env, state) {
  // tado free tier allows only ~100 API calls/day (since 2025) — be frugal:
  // zoneStates every refresh, zones daily, weather 6-hourly, presence 2-hourly, 2h backoff on 429
  const nowS = Date.now() / 1000;
  const T = (state.tadoCache = state.tadoCache || {});
  if (T.backoffT && nowS < T.backoffT)
    throw new Error("tado rate-limited, retrying after " + new Date(T.backoffT * 1000).toISOString().slice(11, 16) + "Z");
  const tok = await tadoToken(env, state);
  const get = async (p) => {
    const r = await fetch("https://my.tado.com/api/v2" + p, { headers: { Authorization: `Bearer ${tok}` } });
    if (r.status === 429) { T.backoffT = nowS + 7200; throw new Error(`tado ${p} 429 — paused 2h (free tier: 100 calls/day)`); }
    if (!r.ok) throw new Error(`tado ${p} ${r.status}`);
    return r.json();
  };
  if (!state.tadoHome) {
    const me = await get("/me");
    state.tadoHome = (((me || {}).homes || [])[0] || {}).id;
  }
  const h = state.tadoHome;
  if (!T.zones || nowS - (T.zonesT || 0) > 86400) { T.zones = await get(`/homes/${h}/zones`); T.zonesT = nowS; }
  const zoneStates = await get(`/homes/${h}/zoneStates`);
  if (!T.weather || nowS - (T.weatherT || 0) > 21600) { T.weather = await get(`/homes/${h}/weather`); T.weatherT = nowS; }
  if (!T.homeState || nowS - (T.homeStateT || 0) > 7200) { T.homeState = await get(`/homes/${h}/state`); T.homeStateT = nowS; }
  const zones = T.zones, weather = T.weather, homeState = T.homeState;
  const zs = (zoneStates || {}).zoneStates || {};
  const rooms = (zones || []).filter((z) => z.type === "HEATING").map((z) => {
    const s = zs[z.id] || {};
    const sd = s.sensorDataPoints || {};
    return {
      id: z.id,
      name: z.name,
      temp: ((sd.insideTemperature || {}).celsius),
      humidity: ((sd.humidity || {}).percentage),
      target: (((s.setting || {}).temperature) || {}).celsius ?? null,
      power: ((((s.activityDataPoints || {}).heatingPower) || {}).percentage) || 0,
      mode: (s.setting || {}).power,
      openWindow: !!s.openWindow,
    };
  });
  return {
    t: localOffsetISO().slice(0, 19),
    rooms,
    presence: (homeState || {}).presence,
    outside: (((weather || {}).outsideTemperature) || {}).celsius,
    solar: (((weather || {}).solarIntensity) || {}).percentage,
    weather: (((weather || {}).weatherState) || {}).value,
  };
}

const VAILLANT_REALM = "vaillant-unitedkingdom-b2c";
const VAILLANT_AUTH = `https://identity.vaillant-group.com/auth/realms/${VAILLANT_REALM}`;
const VAILLANT_API = "https://api.vaillant-group.com/service-connected-control/end-user-app-api/v1";
function b64url(buf) { return b64e(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function vaillantLogin(env, state) {
  // PKCE + Keycloak login form (no OIDC UI available for machine use)
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = b64url(verifierBytes);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", te.encode(verifier)));
  const q = new URLSearchParams({
    response_type: "code", client_id: "myvaillant", code: "code_challenge",
    redirect_uri: "enduservaillant.page.link://login",
    code_challenge_method: "S256", code_challenge: challenge,
  });
  const bh = { "User-Agent": "okhttp/4.9.2", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-GB,en;q=0.9" };
  const r1 = await fetch(`${VAILLANT_AUTH}/protocol/openid-connect/auth?${q}`, { redirect: "manual", headers: bh });
  const cookies = (r1.headers.getSetCookie ? r1.headers.getSetCookie() : []).map((c) => c.split(";")[0]).join("; ");
  const html = await r1.text();
  // form action may be absolute or relative depending on Keycloak version
  let m = html.match(/action="([^"]*login-actions\/authenticate[^"]*)"/);
  if (!m) m = html.match(new RegExp(`(${VAILLANT_AUTH}/login-actions/authenticate\\?[^"]*)`.replace(/[/.]/g, (c) => "\\" + c)));
  if (!m) {
    console.log("vaillant login page (no form):", r1.status, html.slice(0, 400).replace(/\s+/g, " "));
    throw new Error(`vaillant: login form not found (http ${r1.status})`);
  }
  let loginUrl = m[1].replace(/&amp;/g, "&");
  if (!loginUrl.startsWith("http")) loginUrl = new URL(loginUrl, VAILLANT_AUTH).toString();
  const r2 = await fetch(loginUrl, {
    method: "POST", redirect: "manual",
    headers: { ...bh, "Content-Type": "application/x-www-form-urlencoded", Cookie: cookies },
    body: new URLSearchParams({ username: env.MYVAILLANT_EMAIL, password: env.MYVAILLANT_PASSWORD, credentialId: "" }),
  });
  const loc = r2.headers.get("Location") || "";
  const code = new URLSearchParams(loc.split("?")[1] || "").get("code");
  if (!code) throw new Error("vaillant: login failed (check credentials)");
  const r3 = await fetch(`${VAILLANT_AUTH}/protocol/openid-connect/token`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", client_id: "myvaillant", code,
      code_verifier: verifier, redirect_uri: "enduservaillant.page.link://login",
    }),
  });
  const j = await r3.json();
  if (!j.access_token) throw new Error("vaillant token: " + JSON.stringify(j).slice(0, 120));
  return j;
}
async function vaillantToken(env, state) {
  const v = (state.vaillant = state.vaillant || {});
  const now = Date.now() / 1000;
  if (v.access && now < (v.exp || 0)) return v.access;
  if (v.refresh) {
    const r = await fetch(`${VAILLANT_AUTH}/protocol/openid-connect/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: "myvaillant", refresh_token: v.refresh }),
    });
    const j = await r.json().catch(() => ({}));
    if (j.access_token) { v.access = j.access_token; v.refresh = j.refresh_token || v.refresh; v.exp = now + (j.expires_in || 300) - 30; return v.access; }
  }
  // fallback: tokens minted by the vaillant-login GitHub Action (non-CF IPs beat the WAF)
  try {
    const o = await env.PW.get("vailtok.json");
    if (o) {
      const jt = JSON.parse(await o.text());
      if (jt.t && jt.t !== v.usedT) {
        v.usedT = jt.t;
        if (jt.refresh) {
          const r = await fetch(`${VAILLANT_AUTH}/protocol/openid-connect/token`, {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ grant_type: "refresh_token", client_id: "myvaillant", refresh_token: jt.refresh }),
          });
          const j2 = await r.json().catch(() => ({}));
          if (j2.access_token) { v.access = j2.access_token; v.refresh = j2.refresh_token || jt.refresh; v.exp = now + (j2.expires_in || 300) - 30; v.loginFailT = 0; return v.access; }
        }
        if (jt.access && (jt.exp || 0) > now) { v.access = jt.access; v.refresh = jt.refresh; v.exp = jt.exp; v.loginFailT = 0; return v.access; }
      }
    }
  } catch (e) {}
  if (v.loginFailT && now - v.loginFailT < 600) throw new Error("vaillant: login cooling down after failure");
  try {
    const j = await vaillantLogin(env, state);
    v.access = j.access_token; v.refresh = j.refresh_token; v.exp = now + (j.expires_in || 300) - 30;
    v.loginFailT = 0;
    return v.access;
  } catch (e) { v.loginFailT = now; throw e; }
}
async function fetchVaillant(env, state) {
  if (!env.MYVAILLANT_EMAIL) return { error: "myVAILLANT credentials not set" };
  const tok = await vaillantToken(env, state);
  const get = async (u) => {
    const r = await fetch(u, { headers: { Authorization: `Bearer ${tok}`, "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "Accept": "application/json, text/plain, */*", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" } });
    if (!r.ok) throw new Error(`vaillant ${r.status}: ${(await r.text()).slice(0, 100)}`);
    return r.json();
  };
  if (!state.vaillantSys) {
    const homes = await get(`${VAILLANT_API}/homes`);
    state.vaillantSys = ((homes || [])[0] || {}).systemId;
    state.vaillantCtrl = (((homes || [])[0] || {}).productMetadata || {}).controlIdentifier || "tli";
  }
  const base = state.vaillantCtrl === "vrc700" ? VAILLANT_API.replace("end-user-app-api/v1", "vrc700/v1") : VAILLANT_API;
  const sys = await get(`${base}/systems/${state.vaillantSys}/${state.vaillantCtrl}`);
  const st = (sys || {}).state || {}, props = (sys || {}).properties || {}, cfg = (sys || {}).configuration || {};
  const sState = st.system || {}, sProps = props.system || {};
  const zones = (st.zones || []).map((z, i) => ({
    index: z.index ?? i,
    name: ((((cfg.zones || [])[i]) || {}).general || {}).name || `Zone ${i + 1}`,
    temp: z.currentRoomTemperature, target: z.desiredRoomTemperatureSetpoint,
    humidity: z.currentRoomHumidity,
  }));
  const dhw = ((st.domesticHotWater || [])[0]) || {};
  if (dhw.index != null) state.vaillantDhwIdx = dhw.index;
  const dhwCfg = ((cfg.domesticHotWater || [])[0]) || {};
  const circuit = ((st.circuits || [])[0]) || {};
  // live power draw per device (mpc = my power consumption)
  let power = null;
  try {
    const mpc = await get(`${VAILLANT_API}/hem/${state.vaillantSys}/mpc`);
    power = ((mpc || {}).devices || []).reduce((a, d) => a + (d.currentPower ?? d.current_power ?? 0), 0);
  } catch (e) {}
  return {
    t: localOffsetISO().slice(0, 19),
    outdoor: sState.outdoorTemperature,
    pressure: sState.systemWaterPressure,
    flowTemp: sState.systemFlowTemperature ?? circuit.currentCircuitFlowTemperature,
    dhwTemp: dhw.currentDhwTemperature,
    dhwTarget: dhwCfg.tappingSetpoint,
    power,
    zones,
    energyDaily: ((state.vailEnergy || {}).daily) || [],
  };
}
// hourly: pull daily electrical-consumption buckets for the energy report
async function fetchVaillantEnergy(env, state, log) {
  if (!env.MYVAILLANT_EMAIL || !state.vaillantSys) return;
  const tok = await vaillantToken(env, state);
  const vh = { Authorization: `Bearer ${tok}`, "x-app-identifier": "VAILLANT", "Accept-Language": "en-GB", "Accept": "application/json, text/plain, */*", "x-client-locale": "en-GB", "x-idm-identifier": "KEYCLOAK", "ocp-apim-subscription-key": "1e0a2f3511fb4c5bbb1c7f9fedd20b1c", "User-Agent": "okhttp/4.9.2" };
  const get = async (u) => { const r = await fetch(u, { headers: vh }); if (!r.ok) throw new Error(`vaillant emf ${r.status}`); return r.json(); };
  const cs = await get(`${VAILLANT_API}/emf/v2/${state.vaillantSys}/currentSystem`);
  const byDay = {};
  const start = new Date(Date.now() - 395 * 864e5).toISOString();
  const end = new Date().toISOString();
  for (const dev of (cs || {}).devices || (Array.isArray(cs) ? cs : []) || []) {
    for (const d of dev.data || []) {
      const et = d.valueType || d.energyType || d.value_type;
      if (et !== "CONSUMED_ELECTRICAL_ENERGY") continue;
      const om = d.operationMode || d.operation_mode;
      const from = (d.from && d.from > start) ? d.from : start;
      const q = new URLSearchParams({ resolution: "DAY", operationMode: om, energyType: et, startDate: from, endDate: end });
      try {
        const b = await get(`${VAILLANT_API}/emf/v2/${state.vaillantSys}/devices/${dev.deviceUuid || dev.device_uuid}/buckets?${q}`);
        for (const row of (b || {}).data || []) {
          const day = (row.startDate || row.start_date || "").slice(0, 10);
          if (!day) continue;
          const o = (byDay[day] = byDay[day] || { d: day, kwh: 0, dhw: 0 });
          const kwh = (row.value || 0) / 1000; // Wh → kWh
          o.kwh += kwh;
          if (om === "DOMESTIC_HOT_WATER") o.dhw += kwh;
        }
      } catch (e) {}
    }
  }
  const daily = Object.keys(byDay).sort().map((k) => ({ d: byDay[k].d, kwh: Math.round(byDay[k].kwh * 100) / 100, dhw: Math.round(byDay[k].dhw * 100) / 100 }));
  if (daily.length) state.vailEnergy = { daily, t: Date.now() / 1000 };
}

async function fetchEero(env, state) {
  if (!state.eeroTok) return { error: "eero not connected" };
  const call = async (p, opts) => {
    const r = await fetch(`https://api-user.e2ro.com/2.2/${p}`, {
      ...opts, headers: { ...(opts || {}).headers, Cookie: `s=${state.eeroTok}`, "Content-Type": "application/json" },
    });
    const j = await r.json().catch(() => ({}));
    const code = ((j || {}).meta || {}).code;
    if (code === 401) {
      // rotate session token
      const rr = await fetch("https://api-user.e2ro.com/2.2/login/refresh", { method: "POST", headers: { Cookie: `s=${state.eeroTok}` } });
      const rj = await rr.json().catch(() => ({}));
      if ((((rj || {}).meta || {}).code) === 200) { state.eeroTok = rj.data.user_token; return call(p, opts); }
      throw new Error("eero session expired — reconnect");
    }
    if (code !== 200 && code !== 201) throw new Error(`eero ${p} ${code}`);
    return j.data;
  };
  if (!state.eeroNet) {
    const acct = await call("account");
    const url = ((((acct || {}).networks || {}).data || [])[0] || {}).url || "";
    state.eeroNet = (url.match(/\/(\d+)$/) || [])[1];
  }
  const [net, devices, nodes] = await Promise.all([
    call(`networks/${state.eeroNet}`), call(`networks/${state.eeroNet}/devices`), call(`networks/${state.eeroNet}/eeros`),
  ]);
  const conn = (devices || []).filter((d) => d.connected);
  return {
    t: localOffsetISO().slice(0, 19),
    status: (net || {}).status,
    name: (net || {}).name,
    speed: (net || {}).speed || null,
    guest: (((net || {}).guest_network) || {}).enabled || false,
    deviceCount: conn.length,
    nodes: (nodes || []).map((n) => ({ id: ((n.url || "").match(/\/(\d+)$/) || [])[1], location: n.location, status: n.status, model: n.model })),
    devices: conn.slice(0, 60).map((d) => ({
      name: d.nickname || d.hostname || d.manufacturer || "unknown",
      ip: d.ip, wireless: d.wireless, band: (d.connectivity || {}).frequency || null,
      url: d.url || null, paused: !!d.paused,
    })),
  };
}

/* ---------------- Oura ring ---------------- */
async function fetchOura(env) {
  if (!env.OURA_TOKEN) return { error: "Oura token not set — add the OURA_TOKEN secret" };
  const H = { Authorization: `Bearer ${env.OURA_TOKEN}` };
  const base = "https://api.ouraring.com/v2/usercollection";
  const since = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  const until = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
  const get = async (p, dated = true) => {
    const u = dated ? `${base}/${p}?start_date=${since}&end_date=${until}` : `${base}/${p}`;
    const r = await fetch(u, { headers: H });
    if (!r.ok) throw new Error(`oura ${p} ${r.status}`);
    return r.json();
  };
  const out = { t: localOffsetISO().slice(0, 19) };
  try { const i = await get("personal_info", false); out.info = { age: i.age, weight: i.weight, height: i.height, sex: i.biological_sex }; }
  catch (e) { out.error = String(e).slice(0, 120); return out; }
  const pull = async (name, key, map) => { try { out[key] = (((await get(name)).data) || []).map(map); } catch (e) {} };
  await pull("daily_sleep", "sleep", (d) => ({ day: d.day, score: d.score, c: d.contributors }));
  await pull("daily_readiness", "readiness", (d) => ({ day: d.day, score: d.score, temp: d.temperature_deviation, c: d.contributors }));
  await pull("daily_activity", "activity", (d) => ({ day: d.day, score: d.score, steps: d.steps, cal: d.active_calories, totalCal: d.total_calories, high: d.high_activity_time, med: d.medium_activity_time, low: d.low_activity_time, sed: d.sedentary_time }));
  await pull("daily_stress", "stress", (d) => ({ day: d.day, high: d.stress_high, recov: d.recovery_high, summary: d.day_summary }));
  await pull("daily_spo2", "spo2", (d) => ({ day: d.day, avg: (d.spo2_percentage || {}).average, bdi: d.breathing_disturbance_index }));
  await pull("daily_resilience", "resilience", (d) => ({ day: d.day, level: d.level, c: d.contributors }));
  await pull("daily_cardiovascular_age", "cardio", (d) => ({ day: d.day, age: d.vascular_age }));
  await pull("vO2_max", "vo2", (d) => ({ day: d.day, vo2: d.vo2_max }));
  try {
    const s = await get("sleep");
    out.nights = (((s || {}).data) || []).filter((x) => x.type === "long_sleep" || (x.total_sleep_duration || 0) > 3 * 3600).slice(-7).map((d) => ({
      day: d.day, start: d.bedtime_start, end: d.bedtime_end, dur: d.total_sleep_duration, tib: d.time_in_bed,
      eff: d.efficiency, deep: d.deep_sleep_duration, rem: d.rem_sleep_duration, light: d.light_sleep_duration,
      awake: d.awake_time, hr: d.average_heart_rate, lhr: d.lowest_heart_rate, hrv: d.average_hrv, br: d.average_breath,
    }));
  } catch (e) {}
  try { const r = await get("ring_configuration", false); const rc = (((r || {}).data) || [])[0] || {}; out.ring = { color: rc.color, design: rc.design, size: rc.size, hw: rc.hardware_type, fw: rc.firmware_version }; } catch (e) {}
  return out;
}

async function refreshHome(env, state, log) {
  const home = (state.home = state.home || {});
  if (Date.now() / 1000 - (state.lastTado || 0) > 1740) {
    state.lastTado = Date.now() / 1000;
    try { home.tado = await fetchTado(env, state); } catch (e) { home.tado = { ...(home.tado || {}), error: String(e).slice(0, 140) }; }
  }
  try { home.vaillant = await fetchVaillant(env, state); } catch (e) { home.vaillant = { ...(home.vaillant || {}), error: String(e).slice(0, 140) }; }
  // overnight bedroom temperature sampling (22:00-09:00) for the sleep correlation
  try {
    const rooms = ((home.tado || {}).rooms) || [];
    const bed = rooms.find((r) => /main\s*bed|master/i.test(r.name || "")) || rooms.find((r) => /bed/i.test(r.name || ""));
    if (bed && bed.temp != null) {
      const hr = parseInt(hhmm().slice(0, 2), 10);
      if (hr >= 22 || hr < 9) {
        const dKey = hr >= 22 ? londonDayEndISO(new Date(Date.now() + 864e5)).slice(0, 10) : localMinuteISO().slice(0, 10);
        const B = (state.bedNights = state.bedNights || {});
        if (B[dKey] && B[dKey].room !== bed.name) delete B[dKey]; // room choice changed — restart tonight's record
        const rec = (B[dKey] = B[dKey] || { sum: 0, n: 0, min: 99, max: -99, room: bed.name });
        rec.sum += bed.temp; rec.n++;
        rec.min = Math.min(rec.min, bed.temp); rec.max = Math.max(rec.max, bed.temp);
        const ks = Object.keys(B).sort();
        for (const k of ks.slice(0, Math.max(0, ks.length - 45))) delete B[k];
      }
    }
  } catch (e) {}
  try { home.eero = await fetchEero(env, state); } catch (e) { home.eero = { ...(home.eero || {}), error: String(e).slice(0, 140) }; }
  home.oura = state.oura || { error: "Oura not connected yet" };
  home.sleepLog = state.sleepLog || [];
  try {
    await env.PW.put("home.enc", await encryptBundle(state, { generated_at: localOffsetISO().slice(0, 19), ...home }));
  } catch (e) { log.push("home blob error: " + String(e).slice(0, 80)); }
}

/* ---------------- live streaming (Durable Object) ---------------- */
// Holds dashboard/app WebSockets; while anyone is connected it polls Tesla's
// live_status every 10s and broadcasts. Reads the cron-maintained access token
// snapshot — it must NEVER refresh tokens itself (single-use rotation).
export class LiveHub {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket")
      return new Response("expected websocket", { status: 426 });
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ authed: false, t: Date.now() });
    if (!(await this.state.storage.getAlarm())) await this.state.storage.setAlarm(Date.now() + 1000);
    return new Response(null, { status: 101, webSocket: client });
  }
  async webSocketMessage(ws, msg) {
    let j = {}; try { j = JSON.parse(msg); } catch (e) {}
    const att = ws.deserializeAttachment() || {};
    if (!att.authed) {
      if (j.auth && j.auth === this.env.DASH_PASSWORD) {
        ws.serializeAttachment({ authed: true });
        try { ws.send(JSON.stringify({ type: "hello", ok: true })); } catch (e) {}
      } else { try { ws.close(4001, "unauthorized"); } catch (e) {} }
    }
  }
  async webSocketClose(ws) { /* alarm loop notices empty socket list and stops */ }
  async webSocketError(ws) { try { ws.close(); } catch (e) {} }
  async alarm() {
    const socks = this.state.getWebSockets();
    // drop connections that never authenticated within 10s
    for (const w of socks) {
      const a = w.deserializeAttachment() || {};
      if (!a.authed && Date.now() - (a.t || 0) > 10000) { try { w.close(4001, "auth timeout"); } catch (e) {} }
    }
    const authed = socks.filter((w) => (w.deserializeAttachment() || {}).authed);
    if (!socks.length) return; // nobody listening — let the loop die
    if (authed.length) {
      try {
        const live = await this.teslaLive();
        if (!this.hpT || Date.now() - this.hpT > 30000) {
          this.hpT = Date.now();
          try { const o = await this.env.PW.get("hp.json"); this.hp = o ? JSON.parse(await o.text()) : null; } catch (e) {}
        }
        const payload = JSON.stringify({ type: "live", t: new Date().toISOString(), live, hp: this.hp || null });
        for (const w of authed) { try { w.send(payload); } catch (e) {} }
      } catch (e) { /* stale token beat — cron refreshes access.json within a minute */ }
    }
    await this.state.storage.setAlarm(Date.now() + 10000);
  }
  async teslaLive() {
    const now = Date.now();
    if (!this.access || (this.accessExp || 0) < now / 1000 + 60) {
      const o = await this.env.PW.get("access.json");
      if (!o) throw new Error("no access snapshot yet");
      const j = JSON.parse(await o.text());
      this.access = j.access_token; this.accessExp = j.access_exp || 0; this.siteId = j.siteId;
    }
    if (!this.access || !this.siteId) throw new Error("access snapshot incomplete");
    const r = await fetch(`${TESLA_API}/api/1/energy_sites/${this.siteId}/live_status`,
      { headers: { Authorization: `Bearer ${this.access}` } });
    if (!r.ok) { this.access = null; throw new Error("live_status " + r.status); }
    return (await r.json()).response;
  }
}

/* ---------------- entrypoints ---------------- */
const ALLOWED_ORIGIN = "https://powerwall.randlefamily.com";
const CORS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "content-type,x-auth",
  "Vary": "Origin",
};

export default {
  async scheduled(event, env, ctx) {
    const state = await loadState(env);
    try { await pollCycle(env, state); }
    catch (e) {
      // log the failure but don't rethrow — avoids alert spam; /health shows lastError
      console.error("cycle error:", String(e), (e && e.stack || "").slice(0, 500));
      state.lastError = { t: new Date().toISOString(), e: String(e).slice(0, 300) };
      try { await saveState(env, state); } catch (e2) { console.error("state save failed:", String(e2)); }
    }
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (url.pathname === "/data") {
      const obj = await env.PW.get("dashboard.enc");
      if (!obj) return new Response("no data yet", { status: 404, headers: CORS });
      return new Response(await obj.text(), {
        headers: { ...CORS, "Content-Type": "text/plain", "Cache-Control": "no-store",
          "x-updated": (obj.uploaded ? new Date(obj.uploaded).toISOString() : ""),
          "Access-Control-Expose-Headers": "x-updated" },
      });
    }
    if (url.pathname === "/live") {
      const id = env.LIVE.idFromName("hub");
      return env.LIVE.get(id).fetch(request);
    }
    if (url.pathname === "/daybins" || url.pathname === "/home") {
      const obj = await env.PW.get(url.pathname === "/home" ? "home.enc" : "daybins.enc");
      if (!obj) return new Response("no data yet", { status: 404, headers: CORS });
      return new Response(await obj.text(), {
        headers: { ...CORS, "Content-Type": "text/plain", "Cache-Control": "no-store" },
      });
    }
    // Octopus dashboard proxy (ported from the randle-energy Pages functions).
    // The API key and account number stay server-side; gated by the dashboard password.
    if (url.pathname.startsWith("/octo")) {
      const oj = (obj, status = 200) => new Response(JSON.stringify(obj),
        { status, headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "private, no-store" } });
      if (request.headers.get("x-auth") !== env.DASH_PASSWORD) return oj({ error: "unauthorized" }, 401);
      if (request.method !== "GET") return oj({ error: "Method not allowed" }, 405);
      if (!env.OCTOPUS_API_KEY || !env.OCTOPUS_ACCOUNT) return oj({ error: "Server not configured: set OCTOPUS_API_KEY and OCTOPUS_ACCOUNT secrets." }, 500);
      const path = url.pathname.replace(/^\/octo/, "");
      const OCTO = "https://api.octopus.energy";
      const oauth = { Authorization: "Basic " + btoa(env.OCTOPUS_API_KEY + ":") };
      const ogql = async (query, variables, token) => {
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = token;
        const res = await fetch(OCTO + "/v1/graphql/", { method: "POST", headers, body: JSON.stringify({ query, variables }) });
        const data = await res.json();
        if (data.errors) throw new Error(data.errors[0].message);
        return data.data;
      };
      const kraken = async () => (await ogql("mutation($key:String!){obtainKrakenToken(input:{APIKey:$key}){token}}", { key: env.OCTOPUS_API_KEY }, null)).obtainKrakenToken.token;
      try {
        if (path === "/account") {
          const r = await fetch(`${OCTO}/v1/accounts/${env.OCTOPUS_ACCOUNT}/`, { headers: oauth });
          const body = await r.json();
          if (r.ok) body.number = env.OCTOPUS_ACCOUNT;
          return oj(body, r.status);
        }
        if (path === "/financials") {
          const token = await kraken();
          const d = await ogql("query($a:String!){account(accountNumber:$a){balance}}", { a: env.OCTOPUS_ACCOUNT }, token);
          const out = { balance: d.account.balance, txns: [] };
          const queries = [
            "query($a:String!){account(accountNumber:$a){transactions(first:250){edges{node{postedDate title amount balanceCarriedForward isCredit}}}}}",
            "query($a:String!){account(accountNumber:$a){transactions(first:250){edges{node{postedDate balanceCarriedForward}}}}}",
          ];
          for (const q of queries) {
            try {
              const r = await ogql(q, { a: env.OCTOPUS_ACCOUNT }, token);
              out.txns = (r.account.transactions.edges || []).map((e) => e.node).filter((n) => n && n.postedDate);
              break;
            } catch (e) { /* try next shape */ }
          }
          return oj(out);
        }
        if (path === "/live") {
          try {
            const token = await kraken();
            const d = await ogql("query($a:String!){account(accountNumber:$a){electricityAgreements(active:true){meterPoint{meters{smartDevices{deviceId}}}}}}", { a: env.OCTOPUS_ACCOUNT }, token);
            let deviceId = null;
            for (const ag of (d.account.electricityAgreements || []))
              for (const m of (((ag.meterPoint || {}).meters) || []))
                for (const sd of (m.smartDevices || []))
                  if (sd.deviceId && !deviceId) deviceId = sd.deviceId;
            if (!deviceId) return oj({ available: false, reason: "no Home Mini device found" });
            const end = new Date(), start = new Date(end.getTime() - 30 * 60 * 1000);
            const q = `query { smartMeterTelemetry(deviceId: "${deviceId}", grouping: ONE_MINUTE, start: "${start.toISOString()}", end: "${end.toISOString()}") { readAt demand consumptionDelta costDelta } }`;
            const tel = await ogql(q, {}, token);
            return oj({ available: true, readings: tel.smartMeterTelemetry || [] });
          } catch (e) { return oj({ available: false, reason: String(e.message || e) }); }
        }
        if (path.startsWith("/v1/") && !path.includes("graphql")) {
          const r = await fetch(OCTO + path + url.search, { headers: oauth });
          return new Response(r.body, { status: r.status, headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "private, no-store" } });
        }
        return oj({ error: "Not found" }, 404);
      } catch (e) { return oj({ error: String(e.message || e) }, 502); }
    }
    if (url.pathname === "/health") {
      // gated: only returns detail to an authenticated caller
      if (request.headers.get("x-auth") !== env.DASH_PASSWORD)
        return new Response("ok", { headers: CORS });
      const state = await loadState(env);
      return new Response(JSON.stringify({
        ok: true, samples: state.hist.length,
        lastError: state.lastError || null,
        lastSample: state.hist.length ? state.hist[state.hist.length - 1].t : null,
      }), { headers: { ...CORS, "Content-Type": "application/json" } });
    }
    if (url.pathname === "/cmd" && request.method === "POST") {
      if (request.headers.get("x-auth") !== env.DASH_PASSWORD)
        return new Response("unauthorized", { status: 401, headers: CORS });
      const { command, value } = await request.json();
      const state = await loadState(env);
      try {
        const log = await runCommand(env, state, command, String(value ?? ""));
        return new Response(JSON.stringify({ ok: true, log }), { headers: { ...CORS, "Content-Type": "application/json" } });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e).slice(0, 300) }),
          { status: 500, headers: { ...CORS, "Content-Type": "application/json" } });
      }
    }
    return new Response("powerwall poller", { headers: CORS });
  },
};
