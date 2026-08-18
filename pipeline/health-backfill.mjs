#!/usr/bin/env node
/**
 * One-off historical backfill of Apple Health into the dashboard.
 *
 *   node pipeline/health-backfill.mjs ~/Downloads/export.zip \
 *        --url https://powerwall-api.randlefamily.com --token "$HK_TOKEN"
 *
 * Apple's export.xml can be several GB. It is streamed and reduced to one value
 * per metric per day before anything leaves this machine, then re-emitted in
 * Health Auto Export's own JSON shape so the backfill and the phone's hourly
 * sync go through one identical parsing path in the worker.
 *
 * Export it from: Health app → profile picture → Export All Health Data.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { createInterface } from "node:readline";
import { hkEmptyState, hkAccumulate, hkAccumulateWorkouts, hkResolveDay, hkRound, HK_METRICS } from "../worker/src/health.js";

const argv = process.argv.slice(2);
const input = argv.find((a) => !a.startsWith("--"));
const flag = (n, d = null) => { const i = argv.indexOf("--" + n); return i >= 0 ? argv[i + 1] : d; };
const url = flag("url");
const token = flag("token") || process.env.HK_TOKEN;
const outFile = flag("out");
const chunk = Number(flag("chunk", "200"));

if (!input) {
  console.error("usage: node pipeline/health-backfill.mjs <export.zip|export.xml> [--url URL --token TOKEN] [--out FILE]");
  process.exit(1);
}

/* HealthKit type identifier -> the metric names health.js understands */
const TYPES = {
  StepCount: "step_count", DistanceWalkingRunning: "walking_running_distance", DistanceCycling: "cycling_distance",
  FlightsClimbed: "flights_climbed", ActiveEnergyBurned: "active_energy", BasalEnergyBurned: "basal_energy_burned",
  AppleExerciseTime: "apple_exercise_time", AppleStandHour: "apple_stand_hour", PhysicalEffort: "physical_effort",
  WalkingSpeed: "walking_speed", AppleWalkingSteadiness: "apple_walking_steadiness",
  HeartRate: "heart_rate", RestingHeartRate: "resting_heart_rate", WalkingHeartRateAverage: "walking_heart_rate_average",
  HeartRateVariabilitySDNN: "heart_rate_variability", VO2Max: "vo2_max", OxygenSaturation: "blood_oxygen_saturation",
  RespiratoryRate: "respiratory_rate", BodyTemperature: "body_temperature",
  BloodPressureSystolic: "blood_pressure_systolic", BloodPressureDiastolic: "blood_pressure_diastolic",
  BodyMass: "weight_body_mass", BodyFatPercentage: "body_fat_percentage", LeanBodyMass: "lean_body_mass",
  BodyMassIndex: "body_mass_index", WaistCircumference: "waist_circumference", Height: "height",
  DietaryWater: "dietary_water", DietaryEnergyConsumed: "dietary_energy", TimeInDaylight: "time_in_daylight",
  EnvironmentalAudioExposure: "environmental_audio_exposure", HeadphoneAudioExposure: "headphone_audio_exposure",
};
const SLEEP_VALUES = {
  HKCategoryValueSleepAnalysisInBed: "sleep_in_bed",
  HKCategoryValueSleepAnalysisAsleepUnspecified: "sleep_asleep",
  HKCategoryValueSleepAnalysisAsleepCore: "sleep_core",
  HKCategoryValueSleepAnalysisAsleepDeep: "sleep_deep",
  HKCategoryValueSleepAnalysisAsleepREM: "sleep_rem",
  HKCategoryValueSleepAnalysisAwake: "sleep_awake",
};
const UNITS = {
  mi: ["km", (v) => v * 1.609344], lb: ["kg", (v) => v * 0.45359237], st: ["kg", (v) => v * 6.35029318],
  in: ["cm", (v) => v * 2.54], ft: ["m", (v) => v * 0.3048], degF: ["°C", (v) => (v - 32) * 5 / 9],
  "fl_oz_us": ["L", (v) => v * 0.0295735], ml: ["L", (v) => v / 1000], kJ: ["kcal", (v) => v * 0.239006],
  "mi/hr": ["km/hr", (v) => v * 1.609344], "m/s": ["km/hr", (v) => v * 3.6],
};
const day = (s) => { const m = String(s || "").match(/^\d{4}-\d{2}-\d{2}/); return m ? m[0] : null; };
const attrs = (tag) => { const re = /(\w+)="([^"]*)"/g; const o = {}; let m; while ((m = re.exec(tag))) o[m[1]] = m[2]; return o; };

function convert(metric, value, unit) {
  const target = (HK_METRICS[metric] || {}).u;
  const c = unit ? UNITS[unit.trim()] : null;
  return (c && c[0] === target) ? c[1](value) : value;
}

const xml = await resolveXml(input);
console.error(`> parsing ${xml}`);
const state = hkEmptyState();
const stats = { n: 0, sleep: 0, workouts: 0, unknown: new Map() };
await parse(xml);

const days = Object.keys(state.days).sort();
console.error(`> ${stats.n.toLocaleString()} records · ${days.length} days (${days[0] || "-"} → ${days.at(-1) || "-"})`);
console.error(`> ${stats.workouts} workouts · ${stats.sleep.toLocaleString()} sleep intervals`);
if (stats.unknown.size) {
  const top = [...stats.unknown].sort((a, b) => b[1] - a[1]).slice(0, 10);
  console.error(`> ${stats.unknown.size} unmapped types kept under derived names: ${top.map(([k, v]) => k + "×" + v).join(", ")}`);
}

const batches = [];
for (let i = 0; i < days.length; i += chunk) batches.push(toBatch(days.slice(i, i + chunk)));
console.error(`> ${batches.length} batch(es)`);

if (outFile) {
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(batches.length === 1 ? batches[0] : batches));
  console.error(`> wrote ${outFile}`);
}

if (url) {
  if (!token) { console.error("! --token or $HK_TOKEN required"); process.exit(1); }
  for (const [i, b] of batches.entries()) {
    const res = await fetch(new URL("/hk/ingest", url), {
      method: "POST", headers: { "content-type": "application/json", "x-api-key": token }, body: JSON.stringify(b),
    });
    const text = await res.text();
    if (!res.ok) { console.error(`! batch ${i + 1} failed ${res.status}: ${text.slice(0, 300)}`); process.exit(1); }
    console.error(`  ${i + 1}/${batches.length} ok`);
  }
  console.error("> rebuilding…");
  const r = await fetch(new URL("/hk/rebuild", url), { method: "POST", headers: { "x-api-key": token } });
  console.error("> " + (await r.text()));
} else if (!outFile) {
  console.error("! pass --url to upload or --out to write a file");
}

async function resolveXml(p) {
  if (p.endsWith(".xml")) return p;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "health-"));
  execFileSync("unzip", ["-q", "-o", p, "-d", dir], { stdio: ["ignore", "ignore", "inherit"] });
  const find = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { const hit = find(full); if (hit) return hit; }
      else if (e.name === "export.xml") return full;
    }
    return null;
  };
  const hit = find(dir);
  if (!hit) throw new Error("export.xml not found in the zip");
  return hit;
}

async function parse(file) {
  const rl = createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  let buf = [], wbuf = [];
  for await (const line of rl) {
    const t = line.trimStart();
    if (t.startsWith("<Record ")) { const r = toRecord(attrs(t)); if (r) buf.push(r); }
    else if (t.startsWith("<Workout ")) { const w = toWorkout(attrs(t)); if (w) { wbuf.push(w); stats.workouts++; } }
    if (buf.length >= 50000) hkAccumulate(state, buf.splice(0));
  }
  hkAccumulate(state, buf);
  hkAccumulateWorkouts(state, wbuf);
}

function toRecord(a) {
  const type = a.type;
  if (!type) return null;

  if (type === "HKCategoryTypeIdentifierSleepAnalysis") {
    const metric = SLEEP_VALUES[a.value];
    if (!metric) return null;
    const hrs = (new Date(a.endDate) - new Date(a.startDate)) / 36e5;
    if (!(hrs > 0) || hrs > 24) return null;
    stats.sleep++; stats.n++;
    // attributed to the day the sleep ENDED, matching how the Health app reports it
    return { day: day(a.endDate), metric, qty: hrs };
  }
  if (type === "HKCategoryTypeIdentifierMindfulSession") {
    const mins = (new Date(a.endDate) - new Date(a.startDate)) / 6e4;
    if (!(mins > 0)) return null;
    stats.n++;
    return { day: day(a.startDate), metric: "mindful_minutes", qty: mins };
  }

  const value = Number(a.value);
  if (!Number.isFinite(value)) return null;
  const short = type.replace(/^HK(Quantity|Category)TypeIdentifier/, "");
  let metric = TYPES[short];
  if (!metric) {
    metric = short.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
    stats.unknown.set(short, (stats.unknown.get(short) || 0) + 1);
  }
  const d = day(a.startDate);
  if (!d) return null;
  stats.n++;
  return { day: d, metric, qty: convert(metric, value, a.unit) };
}

function toWorkout(a) {
  const d = day(a.startDate);
  if (!d) return null;
  const name = (a.workoutActivityType || "Workout").replace(/^HKWorkoutActivityType/, "");
  const dur = Number(a.duration);
  const mins = Number.isFinite(dur) ? (a.durationUnit === "sec" ? dur / 60 : a.durationUnit === "hr" ? dur * 60 : dur) : null;
  return {
    id: `${a.startDate}-${name}`, day: d, name, start: a.startDate, end: a.endDate,
    min: hkRound(mins, 1),
    kcal: a.totalEnergyBurned != null ? hkRound(convert("active_energy", Number(a.totalEnergyBurned), a.totalEnergyBurnedUnit), 0) : null,
    km: a.totalDistance != null ? hkRound(convert("walking_running_distance", Number(a.totalDistance), a.totalDistanceUnit), 2) : null,
    hrAvg: null, hrMax: null,
  };
}

function toBatch(slice) {
  const byMetric = new Map(), sleepByDay = new Map();
  const set = new Set(slice);
  for (const d of slice) {
    const resolved = hkResolveDay(state.days[d]);
    for (const [metric, value] of Object.entries(resolved)) {
      if (metric.includes("#")) continue;
      const M = HK_METRICS[metric] || { g: "other", u: "" };
      if (M.g === "sleep") {
        const b = sleepByDay.get(d) || {};
        b[metric.replace(/^sleep_/, "").replace("in_bed", "inBed")] = value;
        sleepByDay.set(d, b);
        continue;
      }
      const e = byMetric.get(metric) || { name: metric, units: M.u, data: [] };
      const datum = { date: `${d} 12:00:00 +0000`, qty: value };
      if (resolved[metric + "#lo"] != null) datum.Min = resolved[metric + "#lo"];
      if (resolved[metric + "#hi"] != null) datum.Max = resolved[metric + "#hi"];
      e.data.push(datum);
      byMetric.set(metric, e);
    }
  }
  if (sleepByDay.size) {
    const data = [];
    for (const [d, b] of sleepByDay) {
      // HealthKit splits sleep across stages; "time asleep" is their sum
      const asleep = (b.asleep || 0) + (b.core || 0) + (b.deep || 0) + (b.rem || 0);
      data.push({ date: `${d} 12:00:00 +0000`, asleep: hkRound(asleep, 3),
        inBed: b.inBed != null ? b.inBed : hkRound(asleep + (b.awake || 0), 3),
        core: b.core || 0, deep: b.deep || 0, rem: b.rem || 0, awake: b.awake || 0 });
    }
    byMetric.set("sleep_analysis", { name: "sleep_analysis", units: "hr", data });
  }
  const workouts = Object.values(state.workouts).filter((w) => set.has(w.day)).map((w) => ({
    id: w.id, name: w.name, start: w.start, end: w.end,
    duration: w.min == null ? null : w.min * 60,
    activeEnergyBurned: w.kcal == null ? undefined : { qty: w.kcal, units: "kcal" },
    distance: w.km == null ? undefined : { qty: w.km, units: "km" },
  }));
  // Flag it: the worker must not add these day totals to hourly live values.
  return { data: { meta: { backfill: true }, metrics: [...byMetric.values()], workouts } };
}
