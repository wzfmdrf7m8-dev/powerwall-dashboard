// Powerwall poller — Cloudflare Worker port of apply.py
// Cron: every minute. Storage: R2 (binding PW). Data served at /data, commands at /cmd.

const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";
const TESLA_TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token";
const OHME_GOOGLE_KEY = "AIzaSyC8ZeZngm33tpOXLpbXeKfwtyZ1WrkbdBY";
const REPO_RAW = "https://raw.githubusercontent.com/wzfmdrf7m8-dev/powerwall-dashboard";
const TZ = "Europe/London";
const HIST_MAX = 2880;

const DEFAULT_CONFIG = {
  enabled: false,
  timezone: TZ,
  cheap_window: { enabled: true, start: "23:30", end: "05:30", reserve: 100, mode: "self_consumption", allow_grid_charging: true },
  day: { reserve: 0, mode: "self_consumption", allow_grid_charging: true },
  storm_watch: true,
  follow_ohme_slots: false,
};

/* ---------------- time helpers ---------------- */
function londonParts(d = new Date()) {
  const fmt = new Intl.DateTimeFormat("en-GB", {
    timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
  const p = {};
  for (const { type, value } of fmt.formatToParts(d)) p[type] = value;
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
  const candidates = [state.refresh_token, env.TESLA_REFRESH_TOKEN].filter(Boolean);
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
      await saveState(env, state); // persist rotation immediately
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
  // deep fill: one-off pull of a full year of half-hourly data, then 35-day top-ups
  const deep = !(state && state.octoDeepFill);
  const start = new Date(Date.now() - (deep ? 370 : 35) * 864e5).toISOString();
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
          { period_from: start, page_size: "10000", order_by: "period" });
      }
      if (tariff) {
        const product = tariff.split("-").slice(2, -1).join("-");
        rates = await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${tariff}/standard-unit-rates/`,
          { period_from: start, page_size: "1500" });
        if (kind === "import") {
          standing = await getAll(`https://api.octopus.energy/v1/products/${product}/electricity-tariffs/${tariff}/standing-charges/`,
            { period_from: start, page_size: "1500" });
          out.standing_now = rateAtEpoch(standing, Date.now()) ?? 0;
          out._standing = standing;
        }
      }
      const offRate = rates.length ? Math.min(...rates.map((r) => r.value_inc_vat)) : 5.9;
      for (const c of consumption) {
        if (!c.interval_start) continue;
        const dy = dayOf(c.interval_start);
        const d = (daily[dy] = daily[dy] || { d: dy, impKwh: 0, impCost: 0, offKwh: 0, peakKwh: 0, expKwh: 0, expEarn: 0 });
        let rate = rateAtEpoch(rates, Date.parse(c.interval_start));
        if (kind === "import") {
          const localKey = localMinuteISO(new Date(Date.parse(c.interval_start))).slice(0, 16);
          if (ioSet.has(localKey)) rate = offRate; // IO bonus slot repricing
          if (rate == null) rate = offRate;
          d.impKwh += c.consumption;
          d.impCost += c.consumption * rate;
          if (rate === offRate) d.offKwh += c.consumption; else d.peakKwh += c.consumption;
        } else {
          if (rate == null) rate = 15;
          d.expKwh += c.consumption;
          d.expEarn += c.consumption * rate;
        }
      }
      out[kind] = { mpan: mp.mpan, tariff, consumption: consumption.slice(-150), rates: rates.slice(-200) };
    }
  }
  // per-day standing charge from the dated tariff schedule
  for (const k of Object.keys(daily)) {
    daily[k].standing = rateAtEpoch(out._standing || [], Date.parse(k + "T12:00:00Z")) ?? (out.standing_now || 0);
  }
  delete out._standing;
  // merge with previously cached daily costs, fresh values win
  const merged = {};
  for (const r of ((state && state.octopus) || {}).daily || []) merged[r.d] = r;
  Object.assign(merged, daily);
  out.daily = Object.keys(merged).sort().map((k) => merged[k]).slice(-370);
  if (state && deep) state.octoDeepFill = 1;
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
  let rows = [
    ...await monthSeries(new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59)),
    ...await monthSeries(now),
  ];
  // one-off deep fill: 12 months of daily history, then cached in state
  if (!state.energyDeepFill) {
    for (let mBack = 2; mBack <= 12; mBack++) {
      try {
        rows = rows.concat(await monthSeries(new Date(now.getFullYear(), now.getMonth() - mBack + 1, 0, 23, 59, 59)));
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
  return Object.keys(byDay).sort().map((k) => byDay[k]).slice(-370);
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
    const impW = Math.max(live.grid_power || 0, 0), expW = Math.max(-(live.grid_power || 0), 0);
    const basisW = Math.max(live.load_power || 0, 0) + Math.max(-(live.battery_power || 0), 0) + evW;
    if (off) { day.impOff += impW * dt; day.basisOff += basisW * dt; }
    else { day.impPeak += impW * dt; day.basisPeak += basisW * dt; }
    day.exp += expW * dt;
    const keys = Object.keys(L).sort();
    for (const k of keys.slice(0, Math.max(0, keys.length - 400))) delete L[k];
  }
  // background ledger reconstruction: fill past days from Tesla's 5-min power history
  if (!state.ledgerFillDone) {
    try {
      state.ledgerFillCursor = state.ledgerFillCursor ?? 2;
      let n = 0;
      while (n < 12 && state.ledgerFillCursor <= 370) {
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
  if (!state.energyDaily || now - (state.lastEnergy || 0) > 1800 || opts.force) {
    try { state.energyDaily = await fetchEnergyDaily(env, state, sid); state.lastEnergy = now; }
    catch (e) { log.push("energy error: " + String(e).slice(0, 120)); }
    // self-heal intraday chart gaps from Tesla's stored 5-min power history
    try { await backfillHistory(env, state, sid); state.hist = state.hist.slice(-HIST_MAX); }
    catch (e) { log.push("autofill error: " + String(e).slice(0, 120)); }
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
  if (env.OCTOPUS_API_KEY && (!state.octopus || now - (state.lastOcto || 0) > 1800 || opts.force)) {
    try { state.octopus = await fetchOctopus(env, state); state.lastOcto = now; }
    catch (e) { state.octopus = { error: String(e).slice(0, 150) }; }
  }

  const bundle = {
    generated_at: localOffsetISO().slice(0, 19),
    site_name: state.siteName,
    live,
    site_info: (({ backup_reserve_percent, default_real_mode, installation_date, nameplate_power,
      nameplate_energy, battery_count, user_settings, components }) =>
      ({ backup_reserve_percent, default_real_mode, installation_date, nameplate_power,
         nameplate_energy, battery_count, user_settings, components }))(state.siteInfo || {}),
    energy_daily: state.energyDaily || [],
    solar_forecast: state.solarForecast || [],
    ledger: state.ledger || {},
    history: state.hist,
    automations: state.config,
    log: log.length ? log : (state.lastLog || []),
    octopus: state.octopus || null,
    ohme: state.ohmeData || null,
    source: "cloudflare-worker",
  };
  await env.PW.put("dashboard.enc", await encryptBundle(state, bundle));
  await saveState(env, state);
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
  } else if (command === "follow_ohme") {
    state.config.follow_ohme_slots = value === "on";
    log.push(`follow ohme slots -> ${value}`);
  } else if (command === "automation") {
    state.config.enabled = value === "on";
    log.push(`automation -> ${value}`);
  } else if (command === "backfill") {
    await backfillHistory(env, state, sid);
    log.push(`backfilled (${state.hist.length} samples)`);
  } // "poll" falls through — cycle below refreshes everything
  state.lastLog = log;
  await pollCycle(env, state, { force: true });
  return log;
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
      state.lastError = { t: new Date().toISOString(), e: String(e).slice(0, 300) };
      await saveState(env, state);
      throw e;
    }
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (url.pathname === "/data") {
      const obj = await env.PW.get("dashboard.enc");
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
