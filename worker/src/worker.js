// Powerwall poller — Cloudflare Worker port of apply.py
// Cron: every minute. Storage: R2 (binding PW). Data served at /data, commands at /cmd.

const STANDING_FALLBACK = 66.38; // pence/day — from the Jun/Jul 2026 statement (66.38p/day)
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";
const TESLA_TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token";
const OHME_GOOGLE_KEY = "AIzaSyC8ZeZngm33tpOXLpbXeKfwtyZ1WrkbdBY";
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
      const winEnd = chunkEnd || new Date().toISOString();
      for (const ag of mp.agreements || []) {
        const af = ag.valid_from || "2000", at = ag.valid_to || "9999";
        if (at <= start || af >= winEnd) continue; // agreement outside our pull window
        const code = ag.tariff_code;
        const product = code.split("-").slice(2, -1).join("-");
        const params = { period_from: af > start ? af : start, period_to: at < winEnd ? at : winEnd, page_size: "1500" };
        rates = rates.concat(await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${code}/standard-unit-rates/`, params));
        if (kind === "import")
          standing = standing.concat(await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${code}/standing-charges/`, params));
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
          if (rate == null) rate = 12;
          d.expKwh += c.consumption;
          d.expEarn += c.consumption * rate;
          d.nExp = (d.nExp || 0) + 1;
        }
      }
      out[kind] = { mpan: mp.mpan, tariff, consumption: consumption.slice(-150), rates: rates.slice(-200) };
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
      const needExp = dayKeys.filter((k) => !daily[k] || (daily[k].nExp || 0) < 46);
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
              dd.expKwh += ek; dd.expEarn += ek * (rateAtEpoch(expRates, ts) ?? 12);
            }
            prevReg = reg;
          }
        }
      }
    } catch (e) { /* no Home Mini / telemetry hiccup — REST catches up */ }
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
    const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${OHME_GOOGLE_KEY}`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grantType: "refresh_token", refreshToken: o.refreshToken }),
    });
    if (r.ok) {
      const j = await r.json();
      o.idToken = j.id_token; o.refreshToken = j.refresh_token; o.birth = now;
      return o.idToken;
    }
  }
  const r = await fetch(`https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=${OHME_GOOGLE_KEY}`, {
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
async function applyAutomation(env, state, sid, siteInfo, log) {
  const cfg = state.config;
  const setReserve = async (pct, why) => {
    if (siteInfo.backup_reserve_percent !== pct) {
      await tesla(env, state, "POST", `/api/1/energy_sites/${sid}/backup`, { backup_reserve_percent: Math.round(pct) });
      log.push(`reserve -> ${pct}% (${why})`);
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
    if (inSlot) { await setReserve(100, "ohme slot"); await setGridCharging(true, "ohme slot"); }
    else { await setReserve(day.reserve ?? 0, "outside ohme slots"); await setGridCharging(!!day.allow_grid_charging, "outside ohme slots"); }
  }
  if (cfg.enabled) {
    const cw = cfg.cheap_window || {};
    if (cw.enabled) {
      const t = hhmm(), inWin = cw.start < cw.end ? (t >= cw.start && t < cw.end) : (t >= cw.start || t < cw.end);
      const tgt = inWin ? cw : (cfg.day || {});
      await setReserve(tgt.reserve ?? 0, inWin ? "cheap window" : "daytime");
      await setGridCharging(!!tgt.allow_grid_charging, inWin ? "cheap window" : "daytime");
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
      if (value === "on") { await vreq("POST", "/domestic-hot-water/0/boost", {}); log.push("hot water boost started"); }
      else { await vreq("DELETE", "/domestic-hot-water/0/boost"); log.push("hot water boost cancelled"); }
    } else if (command === "vaillant_dhw_temp") {
      await vreq("PATCH", "/domestic-hot-water/0/temperature", { setpoint: Math.round(parseFloat(value)) });
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
  } else if (command === "follow_ohme") {
    state.config.follow_ohme_slots = value === "on";
    log.push(`follow ohme slots -> ${value}`);
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
  const tok = await tadoToken(env, state);
  const get = async (p) => {
    const r = await fetch("https://my.tado.com/api/v2" + p, { headers: { Authorization: `Bearer ${tok}` } });
    if (!r.ok) throw new Error(`tado ${p} ${r.status}`);
    return r.json();
  };
  if (!state.tadoHome) {
    const me = await get("/me");
    state.tadoHome = (((me || {}).homes || [])[0] || {}).id;
  }
  const h = state.tadoHome;
  const [zones, zoneStates, weather, homeState] = await Promise.all([
    get(`/homes/${h}/zones`), get(`/homes/${h}/zoneStates`), get(`/homes/${h}/weather`), get(`/homes/${h}/state`),
  ]);
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
  const r1 = await fetch(`${VAILLANT_AUTH}/protocol/openid-connect/auth?${q}`, { redirect: "manual" });
  const cookies = (r1.headers.getSetCookie ? r1.headers.getSetCookie() : []).map((c) => c.split(";")[0]).join("; ");
  const html = await r1.text();
  const m = html.match(new RegExp(`${VAILLANT_AUTH}/login-actions/authenticate\\?[^"]*`.replace(/[/.]/g, (c) => "\\" + c)));
  if (!m) throw new Error("vaillant: login form not found");
  const loginUrl = m[0].replace(/&amp;/g, "&");
  const r2 = await fetch(loginUrl, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookies },
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
  const j = await vaillantLogin(env, state);
  v.access = j.access_token; v.refresh = j.refresh_token; v.exp = now + (j.expires_in || 300) - 30;
  return v.access;
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

async function refreshHome(env, state, log) {
  const home = (state.home = state.home || {});
  try { home.tado = await fetchTado(env, state); } catch (e) { home.tado = { ...(home.tado || {}), error: String(e).slice(0, 140) }; }
  try { home.vaillant = await fetchVaillant(env, state); } catch (e) { home.vaillant = { ...(home.vaillant || {}), error: String(e).slice(0, 140) }; }
  try { home.eero = await fetchEero(env, state); } catch (e) { home.eero = { ...(home.eero || {}), error: String(e).slice(0, 140) }; }
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
        const payload = JSON.stringify({ type: "live", t: new Date().toISOString(), live });
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
