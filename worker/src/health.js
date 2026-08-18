/* ---------------------------------------------------------------------------
   Apple Health (HealthKit) ingest + rollup.

   The phone pushes to POST /hk/ingest on a schedule (Health Auto Export's REST
   API automation). Writes are append-only NDJSON into R2 so two syncs can never
   race; the every-minute cron folds new batches into hk/state.json and re-encrypts
   hk.enc with the same salt16|iv16|AES-CBC scheme the rest of the dashboard uses.

   Nothing here trusts the payload: unknown metrics are kept under derived names
   rather than dropped, and anything non-numeric is ignored.
--------------------------------------------------------------------------- */

/* ---------------- metric registry ---------------- */
// agg: sum = cumulative through the day, avg = point-in-time readings, last = latest
export const HK_METRICS = {
  step_count:                   { g: "activity", agg: "sum", l: "Steps",                u: "count",  p: 0 },
  walking_running_distance:     { g: "activity", agg: "sum", l: "Walk + Run",           u: "km",     p: 2 },
  cycling_distance:             { g: "activity", agg: "sum", l: "Cycling",              u: "km",     p: 2 },
  flights_climbed:              { g: "activity", agg: "sum", l: "Flights Climbed",      u: "count",  p: 0 },
  active_energy:                { g: "activity", agg: "sum", l: "Active Energy",        u: "kcal",   p: 0 },
  basal_energy_burned:          { g: "activity", agg: "sum", l: "Resting Energy",       u: "kcal",   p: 0 },
  apple_exercise_time:          { g: "activity", agg: "sum", l: "Exercise",             u: "min",    p: 0 },
  apple_stand_hour:             { g: "activity", agg: "sum", l: "Stand Hours",          u: "hr",     p: 0 },
  physical_effort:              { g: "activity", agg: "avg", l: "Physical Effort",      u: "MET",    p: 1 },
  walking_speed:                { g: "activity", agg: "avg", l: "Walking Speed",        u: "km/hr",  p: 2 },
  apple_walking_steadiness:     { g: "activity", agg: "avg", l: "Walking Steadiness",   u: "%",      p: 0 },

  // Running. running_speed arrives from Health Auto Export in mi/hr; declaring
  // km/hr here makes the unit table convert it. See MIGRATIONS for the history.
  running_speed:                { g: "running", agg: "avg", l: "Running Speed",        u: "km/hr",  p: 2 },
  running_power:                { g: "running", agg: "avg", l: "Running Power",        u: "W",      p: 0 },
  running_stride_length:        { g: "running", agg: "avg", l: "Stride Length",        u: "m",      p: 2 },
  running_ground_contact_time:  { g: "running", agg: "avg", l: "Ground Contact",       u: "ms",     p: 0, inv: 1 },
  running_vertical_oscillation: { g: "running", agg: "avg", l: "Vertical Oscillation", u: "cm",     p: 2, inv: 1 },
  six_minute_walking_test_distance: { g: "running", agg: "avg", l: "6-Minute Walk",    u: "m",      p: 0 },
  stair_speed_up:               { g: "running", agg: "avg", l: "Stair Speed Up",       u: "",       p: 2 },
  stair_speed_down:             { g: "running", agg: "avg", l: "Stair Speed Down",     u: "",       p: 2 },

  heart_rate:                   { g: "cardio", agg: "avg", l: "Heart Rate",             u: "bpm",    p: 0 },
  resting_heart_rate:           { g: "cardio", agg: "avg", l: "Resting HR",             u: "bpm",    p: 0, inv: 1 },
  walking_heart_rate_average:   { g: "cardio", agg: "avg", l: "Walking HR",             u: "bpm",    p: 0, inv: 1 },
  heart_rate_variability:       { g: "cardio", agg: "avg", l: "HRV",                    u: "ms",     p: 0 },
  vo2_max:                      { g: "cardio", agg: "avg", l: "VO₂ Max",                u: "ml/kg/min", p: 1 },
  blood_oxygen_saturation:      { g: "cardio", agg: "avg", l: "Blood Oxygen",           u: "%",      p: 1 },
  respiratory_rate:             { g: "cardio", agg: "avg", l: "Respiratory Rate",       u: "br/min", p: 1 },
  body_temperature:            { g: "cardio", agg: "avg", l: "Body Temperature",        u: "°C",     p: 1 },
  blood_pressure_systolic:      { g: "cardio", agg: "avg", l: "Systolic BP",            u: "mmHg",   p: 0, inv: 1 },
  blood_pressure_diastolic:     { g: "cardio", agg: "avg", l: "Diastolic BP",           u: "mmHg",   p: 0, inv: 1 },
  cardio_recovery:              { g: "cardio", agg: "avg", l: "Cardio Recovery",        u: "bpm",    p: 0 },

  sleep_asleep:                 { g: "sleep", agg: "sum", l: "Time Asleep",             u: "hr",     p: 2 },
  sleep_in_bed:                 { g: "sleep", agg: "sum", l: "Time in Bed",             u: "hr",     p: 2 },
  sleep_deep:                   { g: "sleep", agg: "sum", l: "Deep Sleep",              u: "hr",     p: 2 },
  sleep_core:                   { g: "sleep", agg: "sum", l: "Core Sleep",              u: "hr",     p: 2 },
  sleep_rem:                    { g: "sleep", agg: "sum", l: "REM Sleep",               u: "hr",     p: 2 },
  sleep_awake:                  { g: "sleep", agg: "sum", l: "Awake in Bed",            u: "hr",     p: 2, inv: 1 },
  sleep_efficiency:             { g: "sleep", agg: "avg", l: "Sleep Efficiency",        u: "%",      p: 1 },

  weight_body_mass:             { g: "body", agg: "avg",  l: "Weight",                  u: "kg",     p: 2 },
  body_fat_percentage:          { g: "body", agg: "avg",  l: "Body Fat",                u: "%",      p: 1, inv: 1 },
  lean_body_mass:               { g: "body", agg: "avg",  l: "Lean Mass",               u: "kg",     p: 2 },
  body_mass_index:              { g: "body", agg: "avg",  l: "BMI",                     u: "",       p: 1 },
  waist_circumference:          { g: "body", agg: "avg",  l: "Waist",                   u: "cm",     p: 1, inv: 1 },
  height:                       { g: "body", agg: "last", l: "Height",                  u: "cm",     p: 0 },

  dietary_water:                { g: "other", agg: "sum", l: "Water",                   u: "L",      p: 2 },
  dietary_energy:               { g: "other", agg: "sum", l: "Dietary Energy",          u: "kcal",   p: 0 },
  mindful_minutes:              { g: "other", agg: "sum", l: "Mindful Minutes",         u: "min",    p: 0 },
  time_in_daylight:             { g: "other", agg: "sum", l: "Daylight",                u: "min",    p: 0 },
  environmental_audio_exposure: { g: "other", agg: "avg", l: "Environmental Sound",     u: "dB",     p: 0, inv: 1 },
  headphone_audio_exposure:     { g: "other", agg: "avg", l: "Headphone Audio",         u: "dB",     p: 0, inv: 1 },
};

export const HK_GROUPS = { activity: "Activity", running: "Running", cardio: "Cardio & Vitals", sleep: "Sleep", body: "Body", other: "Other" };
const HEADLINE = ["step_count", "active_energy", "apple_exercise_time", "sleep_asleep",
  "resting_heart_rate", "heart_rate_variability", "weight_body_mass", "vo2_max"];

const titleise = (n) => String(n).replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
const meta = (n) => HK_METRICS[n] || { g: "other", agg: "avg", l: titleise(n), u: "", p: 2 };

/* ---------------- units → metric/SI ---------------- */
const CONV = {
  mi: ["km", (v) => v * 1.609344], km: ["km", (v) => v], yd: ["m", (v) => v * 0.9144], ft: ["m", (v) => v * 0.3048],
  lb: ["kg", (v) => v * 0.45359237], st: ["kg", (v) => v * 6.35029318], kg: ["kg", (v) => v], g: ["kg", (v) => v / 1000],
  in: ["cm", (v) => v * 2.54], cm: ["cm", (v) => v],
  degF: ["°C", (v) => (v - 32) * 5 / 9], degC: ["°C", (v) => v],
  L: ["L", (v) => v], ml: ["L", (v) => v / 1000], fl_oz_us: ["L", (v) => v * 0.0295735],
  kcal: ["kcal", (v) => v], Cal: ["kcal", (v) => v], kJ: ["kcal", (v) => v * 0.239006],
  s: ["min", (v) => v / 60], min: ["min", (v) => v], hr: ["hr", (v) => v],
  "mi/hr": ["km/hr", (v) => v * 1.609344], "m/s": ["km/hr", (v) => v * 3.6], "km/hr": ["km/hr", (v) => v],
};
function conv(name, value, unit) {
  const m = meta(name);
  const v = Number(value);
  if (!Number.isFinite(v)) return null;
  const c = unit ? CONV[String(unit).trim()] : null;
  return c && c[0] === m.u ? c[1](v) : v;
}

const localDay = (s) => { const m = String(s || "").match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? m[0] : null; };
// Hour-precision stamp. Two points with the same metric and stamp are the SAME
// reading redelivered, not two readings — this is what makes replays safe.
const stamp = (s) => { const m = String(s || "").match(/^\d{4}-\d{2}-\d{2}[T ](\d{2})/); return m ? m[1] : "d"; };
export const hkRound = (v, p = 2) => (v == null || !Number.isFinite(v)) ? null : Math.round(v * 10 ** p) / 10 ** p;

/* ---------------- flatten Health Auto Export JSON ---------------- */
const SLEEP_FIELDS = { asleep: "sleep_asleep", totalSleep: "sleep_asleep", inBed: "sleep_in_bed",
  core: "sleep_core", deep: "sleep_deep", rem: "sleep_rem", awake: "sleep_awake" };
const SKIP_KEYS = new Set(["date", "source", "units", "sleepStart", "sleepEnd", "inBedStart", "inBedEnd", "mealTime", "id"]);

/**
 * @param opts.dayAgg  true when each datum is a whole-day total rather than a
 *   slice of one. Health Auto Export tells us this in its automation-aggregation
 *   header; our own backfill sets data.meta.backfill. Getting it wrong in the
 *   "false" direction double-counts a day; getting it wrong in the "true"
 *   direction loses part of one. Never guess it from the data shape.
 */
export function hkFlatten(payload, opts = {}) {
  const root = (payload && payload.data) || payload || {};
  const records = [], workouts = [];
  let skipped = 0;
  const dayAgg = !!opts.dayAgg || !!(root.meta && root.meta.backfill);

  for (const metric of root.metrics || []) {
    const name = metric && metric.name, units = metric && metric.units;
    if (!name || !Array.isArray(metric.data)) { skipped++; continue; }

    for (const d of metric.data) {
      const day = localDay(d && d.date);
      if (!day) { skipped++; continue; }

      if (name === "sleep_analysis") {
        let inBed = 0, staged = 0, unspec = 0;
        for (const [k, val] of Object.entries(d)) {
          if (SKIP_KEYS.has(k)) continue;
          const target = SLEEP_FIELDS[k];
          if (!target || !Number.isFinite(Number(val))) continue;
          const hrs = Number(val);
          records.push({ day, metric: target, qty: hrs, t: stamp(d.date), dayAgg: dayAgg ? 1 : undefined });
          if (target === "sleep_in_bed") inBed = Math.max(inBed, hrs);
          if (target === "sleep_asleep") unspec = Math.max(unspec, hrs);
          if (target === "sleep_core" || target === "sleep_deep" || target === "sleep_rem") staged += hrs;
        }
        const asleep = unspec || staged;
        if (asleep > 0 && inBed > 0)
          records.push({ day, metric: "sleep_efficiency", qty: Math.min(100, asleep / inBed * 100) });
        continue;
      }

      if (name === "blood_pressure") {
        if (Number.isFinite(Number(d.systolic))) records.push({ day, metric: "blood_pressure_systolic", qty: Number(d.systolic), t: stamp(d.date) });
        if (Number.isFinite(Number(d.diastolic))) records.push({ day, metric: "blood_pressure_diastolic", qty: Number(d.diastolic), t: stamp(d.date) });
        continue;
      }

      const primary = Number.isFinite(Number(d.qty)) ? Number(d.qty)
        : Number.isFinite(Number(d.Avg != null ? d.Avg : d.avg)) ? Number(d.Avg != null ? d.Avg : d.avg) : null;

      if (primary != null) {
        const rec = { day, metric: name, qty: conv(name, primary, units), t: stamp(d.date) };
        // An unregistered metric has no declared unit, so carry the source one
        // through rather than rendering an unlabelled axis.
        if (!HK_METRICS[name] && units) rec.u = String(units);
        if (dayAgg) rec.dayAgg = 1;
        const lo = d.Min != null ? d.Min : d.min, hi = d.Max != null ? d.Max : d.max;
        if (Number.isFinite(Number(lo))) rec.min = conv(name, lo, units);
        if (Number.isFinite(Number(hi))) rec.max = conv(name, hi, units);
        // `n` carries the sample count so a pre-aggregated mean merges at the
        // right weight against individually-reported samples.
        if (Number.isFinite(Number(d.n))) rec.n = Number(d.n);
        if (rec.qty != null) records.push(rec);
        continue;
      }

      let emitted = false;
      for (const [k, val] of Object.entries(d)) {
        if (SKIP_KEYS.has(k) || !Number.isFinite(Number(val))) continue;
        records.push({ day, metric: `${name}_${k}`, qty: Number(val), t: stamp(d.date) });
        emitted = true;
      }
      if (!emitted) skipped++;
    }
  }

  for (const w of root.workouts || []) {
    const day = localDay(w && w.start);
    if (!day) continue;
    // Health Auto Export is not consistent here: some workout fields arrive as
    // {qty, units}, others as a bare number. Accept both rather than silently
    // dropping the value — a null heart rate quietly removes a whole chart.
    const q = (o, n) => {
      if (o == null) return null;
      if (Number.isFinite(Number(o))) return hkRound(conv(n, Number(o), null), 2);
      if (Number.isFinite(Number(o.qty))) return hkRound(conv(n, Number(o.qty), o.units), 2);
      return null;
    };
    workouts.push({
      id: w.id || `${day}-${w.name}-${w.start}`,
      day, name: w.name || "Workout", start: w.start, end: w.end,
      min: durationMinutes(w.duration),
      kcal: q(w.activeEnergyBurned, "active_energy"),
      km: q(w.distance, "walking_running_distance"),
      hrAvg: q(w.heartRate && w.heartRate.avg, "heart_rate"),
      hrMax: q(w.heartRate && w.heartRate.max, "heart_rate"),
      // Which device logged it. Oura and the Watch name the same treadmill
      // session differently, so the source is the only reliable way to tell
      // them apart later. Only present on workouts ingested from here on.
      src: w.source ? String(w.source).slice(0, 40) : null,
    });
  }

  return { records, workouts, skipped };
}

/* ---------------- accumulate ---------------- */
/** Workout duration: seconds by default, but honour an explicit unit. */
function durationMinutes(d) {
  if (d == null) return null;
  if (Number.isFinite(Number(d))) return hkRound(Number(d) / 60, 1);
  const v = Number(d.qty);
  if (!Number.isFinite(v)) return null;
  const u = String(d.units || "s");
  return hkRound(/min/i.test(u) ? v : /hr|hour/i.test(u) ? v * 60 : v / 60, 1);
}

export const hkEmptyState = () => ({ days: {}, workouts: {}, units: {}, v: SCHEMA_VERSION, n: 0, lastSync: null, lastAutomation: null });

export function hkAccumulate(state, records) {
  state.units = state.units || {};
  for (const r of records) {
    if (!r || !r.day || !r.metric || !Number.isFinite(r.qty)) continue;
    if (r.u && !state.units[r.metric]) state.units[r.metric] = r.u;
    const day = (state.days[r.day] = state.days[r.day] || {});
    const c = (day[r.metric] = day[r.metric] || { s: 0, c: 0, lo: null, hi: null, last: null });
    const n = Number.isFinite(r.n) && r.n > 0 ? r.n : 1;
    if (meta(r.metric).agg === "sum") {
      // Keyed by stamp: a redelivered hour replaces its old value instead of
      // adding to it, so a retried or overlapping sync cannot inflate a total.
      if (r.dayAgg) c.d = Math.max(c.d || 0, r.qty);
      else if (r.t) { c.p = c.p || {}; c.p[r.t] = r.qty; }
      else c.s += r.qty;
      c.c += 1;
    } else {
      // Means are naturally replay-safe — duplicating a value leaves it unchanged.
      c.s += r.qty * n; c.c += n;
    }
    c.last = r.qty;
    const lo = r.min != null ? r.min : r.qty, hi = r.max != null ? r.max : r.qty;
    c.lo = c.lo == null ? lo : Math.min(c.lo, lo);
    c.hi = c.hi == null ? hi : Math.max(c.hi, hi);
    state.n++;
  }
  return state;
}

export function hkAccumulateWorkouts(state, workouts) {
  for (const w of workouts) if (w && w.id) state.workouts[w.id] = w; // keyed => replays are idempotent
  return state;
}

export function hkResolveDay(cells) {
  const out = {};
  for (const [m, c] of Object.entries(cells)) {
    const M = meta(m);
    // max(), not sum(): the hourly parts and the backfilled day total are two
    // measurements OF THE SAME DAY. Taking the larger means a day the live sync
    // only caught half of still reports the backfill's full figure, and a fully
    // live day ignores a staler backfill — without ever adding the two together.
    const v = M.agg === "sum"
      ? Math.max(c.s + (c.p ? Object.values(c.p).reduce((a, b) => a + b, 0) : 0), c.d || 0)
      : M.agg === "last" ? c.last : (c.c ? c.s / c.c : null);
    if (v == null || !Number.isFinite(v)) continue;
    out[m] = hkRound(v, M.p);
    if (M.agg !== "sum" && c.lo != null && c.hi != null && c.lo !== c.hi) {
      out[m + "#lo"] = hkRound(c.lo, M.p);
      out[m + "#hi"] = hkRound(c.hi, M.p);
    }
  }
  return out;
}

/* ---------------- build the bundle the page renders ---------------- */
const mean = (a) => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
const MAX_DAYS = 2200;   // ~6 years

export function hkBuildBundle(state, nowISO) {
  const srcUnits = state.units || {};
  const allDays = Object.keys(state.days || {}).sort();
  const days = allDays.slice(-MAX_DAYS);
  if (!days.length) {
    return { generated_at: nowISO, empty: true, lastSync: state.lastSync || null,
      lastAutomation: state.lastAutomation || null, groups: HK_GROUPS };
  }

  const resolved = {};
  for (const d of days) resolved[d] = hkResolveDay(state.days[d]);

  const counts = new Map();
  for (const d of days) for (const k of Object.keys(resolved[d])) {
    if (k.includes("#")) continue;
    counts.set(k, (counts.get(k) || 0) + 1);
  }

  const series = {}, metrics = {};
  for (const [m, n] of counts) {
    if (n < 2) continue;                       // a single point is a number, not a series
    const M = meta(m), pts = [];
    for (const d of days) {
      const v = resolved[d][m];
      if (v == null) continue;
      pts.push([d, v]);
    }
    series[m] = pts;
    metrics[m] = { l: M.l, u: M.u || srcUnits[m] || "", g: M.g, agg: M.agg, p: M.p, inv: M.inv ? 1 : 0, n: pts.length,
      stats: describe(pts.map((x) => x[1])) };
  }

  const tiles = HEADLINE.filter((m) => series[m]).map((m) => tile(m, series[m], metrics[m]));
  for (const m of Object.keys(series)) {
    if (tiles.length >= 6) break;
    if (!tiles.some((t) => t.m === m)) tiles.push(tile(m, series[m], metrics[m]));
  }

  const workouts = Object.values(state.workouts || {}).sort((a, b) => a.start < b.start ? 1 : -1).slice(0, 1500);

  return {
    generated_at: nowISO,
    empty: false,
    lastSync: state.lastSync || null,
    lastAutomation: state.lastAutomation || null,
    range: { from: days[0], to: days[days.length - 1], days: days.length, total: allDays.length },
    groups: HK_GROUPS,
    headline: tiles,
    metrics, series,
    workouts,
    workoutSummary: summariseWorkouts(Object.values(state.workouts || {})),
    weekday: weekdayProfile(series.step_count || []),
    insights: insights(series, metrics),
  };
}

function tile(m, pts, M) {
  const vals = pts.map((p) => p[1]);
  const cur = mean(vals.slice(-30));
  const prev = vals.length > 30 ? mean(vals.slice(-60, -30)) : null;
  const dp = (prev != null && prev !== 0) ? (cur - prev) / Math.abs(prev) * 100 : null;
  const lastPt = pts[pts.length - 1];
  return {
    m, l: M.l, u: M.u, g: M.g, p: M.p,
    latest: lastPt[1], latestDay: lastPt[0],
    avg30: hkRound(cur, M.p), prev30: hkRound(prev, M.p),
    dp: hkRound(dp, 1),
    // direction-aware: a falling resting HR is an improvement, not a decline
    good: dp == null ? null : (dp === 0 ? 0 : ((dp > 0) !== !!M.inv ? 1 : -1)),
    spark: vals.slice(-60),
  };
}

function describe(v) {
  if (!v.length) return null;
  const s = [...v].sort((a, b) => a - b), q = (p) => s[Math.min(s.length - 1, Math.floor(p * (s.length - 1)))];
  return { n: v.length, min: hkRound(s[0], 3), p25: hkRound(q(0.25), 3), med: hkRound(q(0.5), 3),
    p75: hkRound(q(0.75), 3), max: hkRound(s[s.length - 1], 3), mean: hkRound(mean(v), 3) };
}

function weekdayProfile(pts) {
  const names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], b = names.map(() => []);
  for (const [d, v] of pts.slice(-365)) b[new Date(d + "T12:00:00Z").getUTCDay()].push(v);
  return [1, 2, 3, 4, 5, 6, 0].map((i) => ({ d: names[i], v: hkRound(mean(b[i]) || 0, 0), n: b[i].length }));
}

function summariseWorkouts(ws) {
  const by = {};
  for (const w of ws) {
    const t = (by[w.name] = by[w.name] || { name: w.name, count: 0, min: 0, kcal: 0, km: 0 });
    t.count++; t.min += w.min || 0; t.kcal += w.kcal || 0; t.km += w.km || 0;
  }
  return Object.values(by).map((t) => ({ ...t, min: hkRound(t.min, 0), kcal: hkRound(t.kcal, 0), km: hkRound(t.km, 1) }))
    .sort((a, b) => b.min - a.min);
}

/* Conservative: association only, never phrased as cause. */
function insights(series, metrics) {
  const out = [];
  const pairs = [
    ["sleep_asleep", "heart_rate_variability", "HRV", 0, "on the same night"],
    ["sleep_asleep", "resting_heart_rate", "resting heart rate", 0, "on the same night"],
    ["apple_exercise_time", "resting_heart_rate", "resting heart rate", 1, "the next day"],
    ["step_count", "sleep_asleep", "time asleep", 0, "that night"],
  ];
  for (const [a, b, label, lag, when] of pairs) {
    if (!series[a] || !series[b]) continue;
    const r = pearson(series[a], series[b], lag);
    if (r == null || Math.abs(r) < 0.2) continue;
    out.push({ kind: "corr", m: [a, b], r: hkRound(r, 2),
      text: `Days with more ${metrics[a].l.toLowerCase()} show ${r > 0 ? "higher" : "lower"} ${label} ${when} (r = ${hkRound(r, 2)}, n = ${Math.min(series[a].length, series[b].length)} days). Association only — not cause.` });
  }
  for (const m of HEADLINE) {
    if (!series[m] || series[m].length < 45) continue;
    const v = series[m].map((p) => p[1]);
    const recent = mean(v.slice(-30)), prior = mean(v.slice(-90, -30));
    if (prior == null || prior === 0) continue;
    const pct = (recent - prior) / Math.abs(prior) * 100;
    if (Math.abs(pct) < 7) continue;
    out.push({ kind: "trend", m: [m],
      text: `${metrics[m].l} is ${pct > 0 ? "up" : "down"} ${Math.abs(hkRound(pct, 1))}% over the last 30 days versus the 60 before.` });
  }
  return out.slice(0, 8);
}

function pearson(a, b, lag) {
  const bm = new Map(b.map(([d, v]) => [d, v])), xs = [], ys = [];
  for (const [day, v] of a) {
    const d = new Date(day + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + lag);
    const k = d.toISOString().slice(0, 10);
    if (bm.has(k)) { xs.push(v); ys.push(bm.get(k)); }
  }
  if (xs.length < 20) return null;
  const mx = mean(xs), my = mean(ys);
  let num = 0, dx = 0, dy = 0;
  for (let i = 0; i < xs.length; i++) { const p = xs[i] - mx, q = ys[i] - my; num += p * q; dx += p * p; dy += q * q; }
  const den = Math.sqrt(dx * dy);
  return den === 0 ? null : num / den;
}

/* ---------------- state migrations ---------------- */
export const SCHEMA_VERSION = 1;

/**
 * Bump whenever the SHAPE of the built bundle changes — new caps, new fields,
 * corrected units. The fold rebuilds when the stored bundle was built by an
 * older version, so a deploy takes effect on the next cron tick instead of
 * waiting for the phone to happen to sync.
 */
export const BUNDLE_VERSION = 3;

/** Multiply every magnitude in a cell, leaving the sample count alone. */
function scaleCell(c, f) {
  for (const k of ["s", "lo", "hi", "last", "d"]) if (typeof c[k] === "number") c[k] *= f;
  if (c.p) for (const k of Object.keys(c.p)) c.p[k] *= f;
}

const MIGRATIONS = [
  {
    v: 1,
    note: "running_speed was stored in mi/hr before it entered the registry",
    apply(state) {
      let n = 0;
      for (const cells of Object.values(state.days || {})) {
        if (cells.running_speed) { scaleCell(cells.running_speed, 1.609344); n++; }
      }
      return n;
    },
  },
];

/**
 * Applied once per state, before the bundle is built. Without this a unit fix
 * shows up as a step change in the chart on the day it deployed — which reads
 * as a dramatic change in the athlete, not in the code.
 */
export function hkMigrate(state) {
  const from = state.v || 0;
  const applied = [];
  for (const m of MIGRATIONS) {
    if (from >= m.v) continue;
    const n = m.apply(state);
    applied.push(`v${m.v}: ${m.note} (${n} days)`);
  }
  state.v = SCHEMA_VERSION;
  return applied;
}

/* ---------------- request handling ---------------- */
const MAX_BODY = 24 * 1024 * 1024;

/** Length-independent constant-time compare. */
export function hkSafeEqual(a, b) {
  if (!a || !b) return false;
  const te = new TextEncoder(), A = te.encode(a), B = te.encode(b);
  let diff = A.length ^ B.length;
  for (let i = 0; i < Math.max(A.length, B.length); i++) diff |= (A[i] || 0) ^ (B[i] || 0);
  return diff === 0;
}

const bearer = (req) => req.headers.get("x-api-key") ||
  (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");

/**
 * Append-only: the phone's payload is parked in R2 and folded in by the cron.
 * Keeps the request cheap and means two overlapping syncs cannot corrupt state.
 */
export async function hkIngest(request, env) {
  if (request.method !== "POST") return new Response("POST only", { status: 405 });
  if (!env.HK_TOKEN) return new Response("HK_TOKEN not configured", { status: 500 });
  if (!hkSafeEqual(bearer(request), env.HK_TOKEN)) return new Response("unauthorized", { status: 401 });
  if (Number(request.headers.get("content-length") || 0) > MAX_BODY)
    return new Response("payload too large", { status: 413 });

  let payload;
  try { payload = await request.json(); }
  catch (e) { return new Response("invalid JSON", { status: 400 }); }

  // "Daily" and coarser mean each value already covers a whole day. Anything
  // hourly or finer is a slice. The app sends this on every automation request.
  const agg = String(request.headers.get("automation-aggregation") || "");
  const dayAgg = /day|daily|week|month|year/i.test(agg) && !/hour|min|sec/i.test(agg);
  const { records, workouts, skipped } = hkFlatten(payload, { dayAgg });
  if (!records.length && !workouts.length)
    return json({ ok: true, stored: 0, skipped, note: "nothing recognisable in payload" });

  const key = `hk/raw/${new Date().toISOString()}-${crypto.randomUUID().slice(0, 8)}.ndjson`;
  const lines = [JSON.stringify({ __b: 1, at: new Date().toISOString(), a: request.headers.get("automation-name") || null, g: agg || null })]
    .concat(records.map((r) => JSON.stringify(r)))
    .concat(workouts.map((w) => JSON.stringify({ __w: 1, ...w })));
  await env.PW.put(key, lines.join("\n"), { httpMetadata: { contentType: "application/x-ndjson" } });

  return json({ ok: true, stored: records.length, workouts: workouts.length, skipped, key });
}

/**
 * Folds any new raw batches into hk/state.json and re-encrypts hk.enc.
 * Cheap no-op when nothing new has arrived, so it is safe on the 1-minute cron.
 */
export async function hkFold(env, encryptBundle, cryptoState) {
  const cursorObj = await env.PW.get("hk/cursor.json");
  const cursor = cursorObj ? (JSON.parse(await cursorObj.text()).key || "") : "";

  const listing = await env.PW.list({ prefix: "hk/raw/", startAfter: cursor || undefined, limit: 120 });

  const stObj = await env.PW.get("hk/state.json");
  const state = stObj ? JSON.parse(await stObj.text()) : hkEmptyState();
  state.days = state.days || {}; state.workouts = state.workouts || {};

  // Nothing new to fold AND the stored bundle already matches this code — the
  // common case, and it must stay cheap because this runs every minute.
  const stale = (state.bv || 0) !== BUNDLE_VERSION || (state.v || 0) < SCHEMA_VERSION;
  if (!listing.objects.length && !stale) return { folded: 0 };

  state.seen = state.seen || [];
  let last = cursor;
  for (const o of listing.objects) {
    const body = await env.PW.get(o.key);
    if (!body) { last = o.key; continue; }
    const text = await body.text();
    // Content hash guards against the same payload being delivered twice under
    // two different keys (Health Auto Export retries on timeout). The leading
    // __b header carries the arrival time, so it is excluded — otherwise a
    // byte-identical retry would hash differently and be counted twice.
    const nl = text.indexOf("\n");
    const hash = await sha256(nl >= 0 ? text.slice(nl + 1) : text);
    if (state.seen.includes(hash)) { last = o.key; continue; }
    state.seen.push(hash);
    if (state.seen.length > 400) state.seen = state.seen.slice(-400);
    const recs = [], wks = [];
    for (const line of text.split("\n")) {
      if (!line) continue;
      let r;
      try { r = JSON.parse(line); } catch (e) { continue; }
      if (r.__b) { state.lastSync = r.at || state.lastSync; state.lastAutomation = r.a || state.lastAutomation; continue; }
      if (r.__w) wks.push(r); else recs.push(r);
    }
    hkAccumulate(state, recs);
    hkAccumulateWorkouts(state, wks);
    last = o.key;
  }

  const migrated = hkMigrate(state);
  if (migrated.length) console.log("apple health migrations:", migrated.join("; "));
  compact(state);
  const now = new Date().toISOString();
  const bundle = hkBuildBundle(state, now);
  state.bv = BUNDLE_VERSION;
  await env.PW.put("hk/state.json", JSON.stringify(state));
  await env.PW.put("hk/cursor.json", JSON.stringify({ key: last, at: now }));
  await env.PW.put("hk.enc", await encryptBundle(cryptoState, bundle));

  return { folded: listing.objects.length, rebuilt: stale,
    days: (bundle.range && bundle.range.days) || 0, more: listing.truncated };
}

/** Full rebuild from every raw batch — used after a historical backfill. */
export async function hkRebuild(env, encryptBundle, cryptoState) {
  await env.PW.delete("hk/state.json").catch(() => {});
  await env.PW.delete("hk/cursor.json").catch(() => {});
  let total = 0, guard = 0;
  for (;;) {
    const r = await hkFold(env, encryptBundle, cryptoState);
    total += r.folded || 0;
    if (!r.folded || ++guard > 400) break;   // a version-only rebuild folds 0 and stops here
  }
  return { rebuilt: true, batches: total };
}

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Collapse the stamp-keyed maps on days older than the replay window. Keeps
 * state.json bounded: only recent days can realistically be re-delivered.
 */
const REPLAY_WINDOW_DAYS = 21;
function compact(state) {
  const cutoff = new Date(Date.now() - REPLAY_WINDOW_DAYS * 864e5).toISOString().slice(0, 10);
  for (const [day, cells] of Object.entries(state.days || {})) {
    if (day >= cutoff) continue;
    for (const c of Object.values(cells)) {
      if (!c.p) continue;
      c.s += Object.values(c.p).reduce((a, b) => a + b, 0);
      delete c.p;
    }
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}
