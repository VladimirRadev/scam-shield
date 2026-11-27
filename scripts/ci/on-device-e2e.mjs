#!/usr/bin/env node
/**
 * On-device E2E for Scam Shield. Drives a real, headful Google Chrome over the DevTools protocol
 * (CDP) and records evidence that the app's device route runs on Gemini Nano:
 *
 *  a. internals  enable Chrome's internal debugging pages, dump chrome://on-device-internals
 *  b. model      LanguageModel.availability(); download the model if needed (BITS workaround)
 *  c. smoke      one session + one prompt, timed
 *  d. eval       <target>/eval.html, device route over the labelled examples
 *  e. shots      three checks in the main app, 1366x900 screenshots with the provenance chip
 *  f. demo       scripted flow recorded with Page.startScreencast (frames/ + frames.json)
 *  g. summary    summary.md, printed and appended to $GITHUB_STEP_SUMMARY
 *
 * Dependency-free: Node 24 global fetch + WebSocket. Environment:
 *   CDP_BASE (http://127.0.0.1:9222), TARGET_URL, OUT_DIR, PROFILE_DIR, MODEL (default|gemma4),
 *   RECORD_DEMO (true|false), E2E_DRY=1 (keep going without a working Nano: plumbing test only).
 */
import { execFileSync } from 'node:child_process';
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { cpus, release, totalmem } from 'node:os';
import { join, resolve } from 'node:path';

const env = process.env;
const CDP_BASE = env.CDP_BASE || 'http://127.0.0.1:9222';
const TARGET = (env.TARGET_URL || 'https://scamshield-hybrid.web.app').replace(/\/+$/, '');
const OUT = resolve(env.OUT_DIR || 'e2e-out');
const PROFILE = env.PROFILE_DIR || 'D:\\chrome-profile';
const MODEL = env.MODEL || 'default';
const RECORD = (env.RECORD_DEMO ?? 'true') !== 'false';
const DRY = env.E2E_DRY === '1';
const IS_WIN = process.platform === 'win32';
const VIEW = { width: 1366, height: 900 };
const MIN = 60_000;
/** The app's create options (packages/ai/src/on-device.ts), as a JS literal for the page. */
const OPTS = "{ expectedInputs: [{ type: 'text', languages: ['en'] }], expectedOutputs: [{ type: 'text', languages: ['en'] }] }";
const SMOKE_PROMPT =
  'Is this message a scam? Answer in one short sentence.\n\nMessage: "Hello, this is the official MetaMask support team. Your wallet will be locked. Send us your 12-word recovery phrase within 30 minutes to keep access."';

const EXAMPLES = JSON.parse(readFileSync(new URL('../../packages/core/src/examples.json', import.meta.url), 'utf8'));
const EXAMPLE_LIST = Array.isArray(EXAMPLES) ? EXAMPLES : EXAMPLES.examples;
const EXAMPLE_COUNT = EXAMPLE_LIST.length;
const example = (id) => {
  const ex = EXAMPLE_LIST.find((e) => e.id === id);
  if (!ex) throw new Error(`example ${id} not found in examples.json`);
  return ex;
};
const SHOTS = [
  { id: 'scam-recruiter-repo', file: 'shot-1-recruiter-repo.png' },
  { id: 'scam-seed-support', file: 'shot-2-seed-phrase.png' },
  { id: 'legit-recruiter', file: 'shot-3-legit-recruiter.png' },
];

mkdirSync(OUT, { recursive: true });
const T0 = Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const iso = () => new Date().toISOString();
const secs = (ms) => Math.round(ms / 100) / 10;

function log(...parts) {
  const s = Math.round((Date.now() - T0) / 1000);
  const line = `[${String(Math.floor(s / 60)).padStart(3)}m${String(s % 60).padStart(2, '0')}s] ${parts.join(' ')}`;
  console.log(line);
  appendFileSync(join(OUT, 'run.log'), line + '\n');
}

/** Everything measured so far; rewritten after every phase so a failed run still has it. */
const R = { startedAt: iso(), target: TARGET, model: MODEL, recordDemo: RECORD, dry: DRY, phases: {}, problems: [] };
const save = () => writeFileSync(join(OUT, 'results.json'), JSON.stringify(R, null, 2));
const problem = (msg) => {
  R.problems.push(msg);
  log(`PROBLEM: ${msg}`);
  save();
};

class Fatal extends Error {}

// ------------------------------------------------------------------ CDP

class CDP {
  #ws;
  #id = 0;
  #pending = new Map();
  #listeners = new Set();

  static async connect(base, timeoutMs = 90_000) {
    const deadline = Date.now() + timeoutMs;
    let version;
    for (;;) {
      try {
        version = await (await fetch(`${base}/json/version`)).json();
        break;
      } catch (e) {
        if (Date.now() > deadline) throw new Fatal(`no DevTools endpoint at ${base}: ${e.message}`);
        await sleep(1000);
      }
    }
    const ws = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', () => rej(new Fatal('CDP WebSocket error')), { once: true });
    });
    return new CDP(ws, version);
  }

  constructor(ws, version) {
    this.version = version;
    this.#ws = ws;
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
      if (msg.id !== undefined) {
        const p = this.#pending.get(msg.id);
        if (!p) return;
        this.#pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`CDP ${p.method}: ${msg.error.message}${msg.error.data ? ` (${msg.error.data})` : ''}`));
        else p.resolve(msg.result);
      } else {
        for (const fn of this.#listeners) fn(msg);
      }
    });
    ws.addEventListener('close', () => {
      for (const p of this.#pending.values()) p.reject(new Error('CDP socket closed (did Chrome exit?)'));
      this.#pending.clear();
    });
  }

  send(method, params = {}, sessionId, timeoutMs = 120_000) {
    const id = ++this.#id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`CDP ${method} timed out after ${secs(timeoutMs)} s`));
      }, timeoutMs);
      this.#pending.set(id, {
        method,
        resolve: (v) => (clearTimeout(timer), resolve(v)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      });
      this.#ws.send(JSON.stringify(sessionId ? { id, method, params, sessionId } : { id, method, params }));
    });
  }

  on(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  close() {
    this.#ws.close();
  }
}

class Tab {
  static async open(cdp, url) {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    const tab = new Tab(cdp, targetId, sessionId);
    await tab.send('Page.enable');
    await tab.send('Runtime.enable');
    if (url) await tab.goto(url);
    return tab;
  }

  constructor(cdp, targetId, sessionId) {
    Object.assign(this, { cdp, targetId, sessionId });
  }

  send(method, params = {}, timeoutMs) {
    return this.cdp.send(method, params, this.sessionId, timeoutMs);
  }

  on(method, fn) {
    return this.cdp.on((m) => m.sessionId === this.sessionId && m.method === method && fn(m.params));
  }

  once(method, timeoutMs) {
    return new Promise((res, rej) => {
      const timer = setTimeout(() => (off(), rej(new Error(`${method} did not fire within ${secs(timeoutMs)} s`))), timeoutMs);
      const off = this.on(method, (p) => (clearTimeout(timer), off(), res(p)));
    });
  }

  async goto(url, timeoutMs = 90_000) {
    const loaded = this.once('Page.loadEventFired', timeoutMs);
    const r = await this.send('Page.navigate', { url });
    if (r.errorText) throw new Error(`navigate ${url}: ${r.errorText}`);
    await loaded;
  }

  /** Evaluate an expression (promises are awaited) and return its JSON value. */
  async eval(expression, { gesture = false, timeoutMs = 120_000 } = {}) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: gesture }, timeoutMs);
    if (r.exceptionDetails) throw new Error(`page threw: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  }

  /** Poll `expression` until it is truthy; returns its value. */
  async waitFor(expression, { timeoutMs = 60_000, intervalMs = 500, what = expression } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = await this.eval(expression).catch(() => null);
      if (v) return v;
      if (Date.now() > deadline) throw new Error(`timed out after ${secs(timeoutMs)} s waiting for: ${what}`);
      await sleep(intervalMs);
    }
  }

  async front() {
    await this.cdp.send('Target.activateTarget', { targetId: this.targetId });
    await this.send('Page.bringToFront');
  }

  async viewport() {
    await this.send('Emulation.setDeviceMetricsOverride', { ...VIEW, deviceScaleFactor: 1, mobile: false });
    await this.send('Emulation.setFocusEmulationEnabled', { enabled: true }).catch(() => undefined);
  }

  /** Center of the element found by the JS expression `finder`, after scrolling it into view. */
  rect(finder, { block = 'center', smooth = false } = {}) {
    const scroll = block ? `el.scrollIntoView({ block: '${block}', behavior: '${smooth ? 'smooth' : 'instant'}' });` : '';
    return this.eval(`(() => { const el = ${finder}; if (!el) return null; ${scroll} const r = el.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2, top: r.top, bottom: r.bottom }; })()`);
  }

  /** A real mouse click (Input.dispatchMouseEvent), so the page sees a user gesture. */
  async click(finder, { block = 'center', smooth = false } = {}) {
    let r = await this.rect(finder, { block, smooth });
    if (!r) throw new Error(`click: element not found: ${finder}`);
    if (smooth) {
      await sleep(1000);
      r = await this.rect(finder, { block: null });
    }
    const at = { x: r.x, y: r.y };
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', ...at });
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', ...at, button: 'left', buttons: 1, clickCount: 1 });
    await sleep(70);
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...at, button: 'left', buttons: 0, clickCount: 1 });
    return r;
  }

  async screenshot(file, { full = false } = {}) {
    const params = { format: 'png' };
    if (full) {
      const m = await this.send('Page.getLayoutMetrics');
      params.captureBeyondViewport = true;
      params.clip = { x: 0, y: 0, width: VIEW.width, height: Math.min(Math.ceil(m.cssContentSize.height), 8000), scale: 1 };
    }
    const r = await this.send('Page.captureScreenshot', params, 60_000);
    writeFileSync(join(OUT, file), Buffer.from(r.data, 'base64'));
    log(`saved ${file}`);
  }
}

/** JS expression: the first element matching `sel` whose text contains `text`. */
const byText = (sel, text) =>
  `[...document.querySelectorAll(${JSON.stringify(sel)})].find((e) => e.textContent.replace(/\\s+/g, ' ').trim().includes(${JSON.stringify(text)}))`;
const CHECK_BUTTON = byText('button.ss-btn-primary', 'Check privately');
const chip = (title) => byText('.ss-examples-row[role=group] .ss-chip', title);

/** Helpers for Chrome's WebUI pages, which live in (nested) shadow roots. */
const DEEP_JS = `
  const deepAll = (root = document) => { const out = []; const visit = (n) => { for (const el of n.querySelectorAll('*')) { out.push(el); if (el.shadowRoot) visit(el.shadowRoot); } }; visit(root); return out; };
  const BLOCK = /^(ADDRESS|ARTICLE|BR|BUTTON|CR-BUTTON|DD|DIV|DT|FOOTER|H[1-6]|HEADER|HR|LI|MAIN|OPTION|P|PRE|SECTION|SELECT|TABLE|TBODY|THEAD|TR|UL|OL)$/;
  const deepText = () => { const out = []; const walk = (n) => {
    if (n.nodeType === 3) { if (n.textContent.trim()) out.push(n.textContent.replace(/\\s+/g, ' ')); return; }
    if (n.nodeType === 1) {
      if (/^(SCRIPT|STYLE|TEMPLATE)$/.test(n.tagName) || n.hidden) return;
      const cs = getComputedStyle(n); if (cs.display === 'none' || cs.visibility === 'hidden') return;
      if (BLOCK.test(n.tagName)) out.push('\\n');
      if (n.tagName === 'TD' || n.tagName === 'TH') out.push(' | ');
      if ((n.tagName === 'INPUT' || n.tagName === 'TEXTAREA') && n.value) out.push(' [' + n.value + '] ');
      if (n.shadowRoot) walk(n.shadowRoot);
    } else if (n.nodeType !== 11 && n.nodeType !== 9) return;
    for (const c of n.childNodes) walk(c);
  }; walk(document); return out.join('').replace(/[ \\t]+/g, ' ').replace(/ *\\n */g, '\\n').replace(/\\n{2,}/g, '\\n').trim(); };
`;

// ------------------------------------------------------------------ machine facts

function ps(command, timeout = 60_000) {
  if (!IS_WIN) return '';
  try {
    return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8', timeout }).trim();
  } catch (e) {
    return `(powershell failed: ${String(e.stderr || e.message).trim().slice(0, 400)})`;
  }
}

function psJson(command) {
  const out = ps(`${command} | ConvertTo-Json -Compress -Depth 4`);
  try {
    return out ? JSON.parse(out) : null;
  } catch {
    return out;
  }
}

function machineFacts() {
  const c = cpus();
  const facts = { platform: `${process.platform} ${release()}`, node: process.version, cpu: c[0]?.model?.trim() ?? null, logicalCpus: c.length, ramGiB: +(totalmem() / 2 ** 30).toFixed(1) };
  if (IS_WIN) {
    facts.win32Processor = psJson('Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed');
    if (!facts.win32Processor?.Name) facts.wmicCpu = ps('wmic cpu get name');
    facts.os = psJson('Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber');
    facts.gpus = psJson('@(Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion)');
    facts.disks = psJson("@(Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | Select-Object Name, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}, @{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}})");
    if (facts.win32Processor?.Name) facts.cpu = String(facts.win32Processor.Name).trim();
  }
  return facts;
}

function dirSize(dir) {
  let total = 0;
  try {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) total += dirSize(p);
      else if (e.isFile()) total += statSync(p).size;
    }
  } catch {
    // Missing or locked: counts as 0.
  }
  return total;
}

/** Component folders in the profile (<dir>/<version>/manifest.json), e.g. OptGuideOnDeviceModel. */
function profileComponents() {
  const out = [];
  if (!existsSync(PROFILE)) return out;
  for (const d of readdirSync(PROFILE, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    const dir = join(PROFILE, d.name);
    let subs = [];
    try {
      subs = readdirSync(dir, { withFileTypes: true }).filter((s) => s.isDirectory());
    } catch {
      continue;
    }
    for (const s of subs) {
      const mf = join(dir, s.name, 'manifest.json');
      if (!existsSync(mf)) continue;
      let manifest = {};
      try {
        manifest = JSON.parse(readFileSync(mf, 'utf8'));
      } catch {
        // Unreadable manifest: keep the folder name only.
      }
      const bytes = dirSize(join(dir, s.name));
      out.push({ folder: `${d.name}\\${s.name}`, name: manifest.name ?? null, version: manifest.version ?? s.name, mib: Math.round(bytes / 2 ** 20) });
    }
  }
  return out.sort((a, b) => b.mib - a.mib);
}

function logTail(file, bytes = 200_000) {
  try {
    const size = statSync(file).size;
    const fd = openSync(file, 'r');
    const buf = Buffer.alloc(Math.min(bytes, size));
    readSync(fd, buf, 0, buf.length, size - buf.length);
    closeSync(fd);
    return buf.toString('utf8');
  } catch (e) {
    return `(cannot read ${file}: ${e.message})`;
  }
}

function saveLogTail(label) {
  const tail = logTail(join(PROFILE, 'chrome_debug.log'));
  writeFileSync(join(OUT, `chrome_debug-tail-${label}.log`), tail);
  const hits = tail.split('\n').filter((l) => /on_device|OnDevice|optimization_guide|model_execution|SessionCreate|CHECK failed|Terminating/i.test(l));
  writeFileSync(join(OUT, `chrome_debug-model-lines-${label}.log`), hits.slice(-400).join('\n'));
  log(`saved chrome_debug tail (${label}): ${hits.length} model-related lines`);
}

// ------------------------------------------------------------------ a. internals

let internalsTab = null;

async function enableInternalPages(cdp) {
  internalsTab = await Tab.open(cdp, 'chrome://chrome-urls');
  await sleep(1500);
  const r = await internalsTab.eval(`(() => { ${DEEP_JS}
    const b = deepAll().find((e) => /^(BUTTON|CR-BUTTON)$/.test(e.tagName) && /enable internal debugging pages/i.test(e.textContent));
    if (!b) return { clicked: false };
    b.click(); return { clicked: true }; })()`);
  await sleep(1500);
  const text = await internalsTab.eval(`(() => { ${DEEP_JS} return deepText(); })()`);
  const enabled = /disable internal debugging pages/i.test(text);
  R.phases.internals = { clickedEnable: r.clicked, enabled };
  log(`chrome://chrome-urls: clicked "Enable internal debugging pages" = ${r.clicked}, enabled = ${enabled}`);
  if (!enabled) writeFileSync(join(OUT, 'chrome-urls.txt'), text);
}

const TAB_SEL = `deepAll().filter((e) => e.getAttribute('role') === 'tab' || e.getAttribute('slot') === 'tab')`;

/** Full text of chrome://on-device-internals (every tab), saved as internals-<label>.txt. */
async function dumpInternals(label) {
  if (!internalsTab) return null;
  try {
    await internalsTab.goto('chrome://on-device-internals');
    await sleep(2500);
    const tabs = await internalsTab.eval(`(() => { ${DEEP_JS} return ${TAB_SEL}.map((e) => e.textContent.replace(/\\s+/g, ' ').trim()); })()`);
    let text = `# chrome://on-device-internals, ${label}, ${iso()}\n`;
    if (!tabs.length) text += (await internalsTab.eval(`(() => { ${DEEP_JS} return deepText(); })()`)) + '\n';
    for (let i = 0; i < tabs.length; i++) {
      await internalsTab.eval(`(() => { ${DEEP_JS} ${TAB_SEL}[${i}]?.click(); })()`);
      await sleep(1500);
      text += `\n## tab ${i + 1}: ${tabs[i]}\n${await internalsTab.eval(`(() => { ${DEEP_JS} return deepText(); })()`)}\n`;
    }
    writeFileSync(join(OUT, `internals-${label}.txt`), text);
    const facts = internalsFacts(text);
    (R.internals ??= {})[label] = facts;
    save();
    log(`saved internals-${label}.txt (${text.length} chars); performance class: ${facts.performanceClass ?? 'n/a'}`);
    return facts;
  } catch (e) {
    log(`internals dump (${label}) failed: ${e.message}`);
    return null;
  }
}

/**
 * The facts of the "Broker State" tab: performance class, crash count, criteria, and the asset
 * and model tables ("| Name | Version | State | Progress | Error" rows).
 */
function internalsFacts(text) {
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const cells = (l) => l.replace(/^\|\s*/, '').split(/\s*\|\s*/);
  const row = (key) => lines.map(cells).find((c) => c[0].toLowerCase() === key.toLowerCase())?.slice(1).join(' | ') ?? null;
  const table = (header) => {
    const i = lines.findIndex((l) => l.startsWith('|') && cells(l)[0] === 'Name' && cells(l).includes(header));
    if (i < 0) return [];
    const head = cells(lines[i]);
    const out = [];
    for (const l of lines.slice(i + 1)) {
      if (!l.startsWith('|')) break;
      out.push(Object.fromEntries(cells(l).map((v, k) => [head[k] ?? `c${k}`, v])));
    }
    return out;
  };
  const crash = lines.find((l) => /crash count/i.test(l)) ?? null;
  const criteria = Object.fromEntries(
    ['Enough VRAM', 'Device Capable', 'Enough disk space to install', 'Enabled by feature flag', 'Enabled by enterprise policy'].map((k) => [k, row(k)]),
  );
  const performanceClass = row('Performance Class') ?? /performance class:\s*(.+)$/im.exec(text)?.[1]?.trim() ?? null;
  const assets = table('Version');
  const models = table('Backend Type');
  const keyLines = [
    `Performance Class: ${performanceClass}`,
    crash,
    ...Object.entries(criteria).map(([k, v]) => `${k}: ${v}`),
    ...assets.map((a) => `asset ${a.Name} ${a.Version}: ${a.State} ${a.Progress ?? ''} ${a.Error && a.Error !== 'None' ? a.Error : ''}`.trim()),
    ...models.map((m) => `model ${m.Name}: ${m['Folder Size']} ${m['Backend Type']}`),
    ...lines.filter((l) => /prompt_api/.test(l)),
  ].filter(Boolean);
  return { performanceClass, crash, criteria, assets, models, keyLines };
}

// ------------------------------------------------------------------ b. model

const availability = (tab) => tab.eval(`(typeof LanguageModel === 'undefined') ? 'no-LanguageModel' : LanguageModel.availability(${OPTS})`);

const BITS_LIST = "Get-BitsTransfer -AllUsers | Format-List DisplayName, JobState, BytesTransferred, BytesTotal, OwnerAccount, ErrorDescription | Out-String -Width 200";
const BITS_REMOVE = "Get-BitsTransfer | Where-Object DisplayName -eq 'Chrome Component Updater' | Remove-BitsTransfer; Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq 'Chrome Component Updater' | Remove-BitsTransfer";

async function ensureModel(app) {
  const P = (R.phases.model = { startedAt: iso(), progress: [] });
  let avail = await availability(app);
  log(`LanguageModel.availability() = ${avail}`);
  // A fresh profile computes its performance class after start-up; give it a moment.
  for (let i = 0; avail === 'unavailable' && i < 8; i++) {
    await sleep(15_000);
    avail = await availability(app);
    log(`availability (retry ${i + 1}) = ${avail}`);
  }
  P.initial = avail;
  save();
  if (DRY && avail !== 'available') return problem(`dry run: availability is ${avail}; no download attempted`);
  if (avail === 'no-LanguageModel') throw new Fatal('this Chrome exposes no LanguageModel (Prompt API) to the page');
  if (avail === 'unavailable') {
    const f = await dumpInternals('unavailable');
    throw new Fatal(`Gemini Nano is "unavailable" on this machine (performance class: ${f?.performanceClass ?? 'n/a'}); see internals-unavailable.txt`);
  }
  if (avail === 'available') {
    P.downloadMs = 0;
    P.alreadyInstalled = true;
    log('model already installed');
    return;
  }

  // downloadable / downloading: create() with a user gesture starts (or joins) the download.
  await app.front();
  const t0 = Date.now();
  await app.eval(
    `(() => { window.__dl = { loaded: 0, events: 0, done: false, error: null, t0: performance.now() };
      LanguageModel.create({ ...${OPTS}, monitor(m) { m.addEventListener('downloadprogress', (e) => { window.__dl.loaded = e.loaded; window.__dl.events++; }); } })
        .then((s) => { window.__dl.ms = Math.round(performance.now() - window.__dl.t0); window.__dl.done = true; s.destroy(); })
        .catch((e) => { window.__dl.error = (e && e.name ? e.name + ': ' : '') + (e && e.message ? e.message : String(e)); window.__dl.done = true; });
      return true; })()`,
    { gesture: true },
  );
  log('download started: LanguageModel.create() with a user gesture');
  let best = 0;
  let lastProgressAt = Date.now();
  let lastLog = 0;
  let bitsKicks = 0;
  let s;
  for (;;) {
    await sleep(5000);
    s = await app.eval(`(async () => ({ ...window.__dl, avail: await LanguageModel.availability(${OPTS}) }))()`);
    if (s.loaded > best) {
      best = s.loaded;
      lastProgressAt = Date.now();
    }
    const elapsed = Date.now() - t0;
    if (Date.now() - lastLog >= 30_000 || s.done) {
      lastLog = Date.now();
      const modelMiB = Math.round(dirSize(join(PROFILE, 'OptGuideOnDeviceModel')) / 2 ** 20);
      P.progress.push({ s: Math.round(elapsed / 1000), loaded: s.loaded, events: s.events, avail: s.avail, modelMiB });
      save();
      log(`download: ${(s.loaded * 100).toFixed(1)}% (${s.events} events), availability=${s.avail}, OptGuideOnDeviceModel=${modelMiB} MiB, ${secs(elapsed)} s`);
      if (best === 0 && IS_WIN) log(`BITS jobs:\n${ps(BITS_LIST) || '(none)'}`);
    }
    if (s.done) break;
    if (best === 0 && IS_WIN && Date.now() - lastProgressAt > 4 * MIN && bitsKicks < 3) {
      bitsKicks++;
      log(`no download progress for 4 minutes: removing the "Chrome Component Updater" BITS job (attempt ${bitsKicks})`);
      log(ps(BITS_REMOVE) || 'BITS job removed (no output)');
      lastProgressAt = Date.now();
    }
    if (elapsed > 90 * MIN) throw new Fatal('the model download did not finish within 90 minutes');
  }
  P.downloadMs = Date.now() - t0;
  P.bitsKicks = bitsKicks;
  P.createAfterDownloadMs = s.ms ?? null;
  P.error = s.error;
  save();
  log(`download finished after ${secs(P.downloadMs)} s; create() ${s.error ? `failed: ${s.error}` : 'opened a session'}`);
  if (s.error) {
    await dumpInternals('download-error');
    saveLogTail('download-error');
    throw new Fatal(`LanguageModel.create() after the download failed: ${s.error}`);
  }
}

// ------------------------------------------------------------------ c. smoke

async function smoke(app) {
  const P = (R.phases.smoke = { startedAt: iso(), prompt: SMOKE_PROMPT });
  if (DRY && (await availability(app)) !== 'available') {
    P.skipped = 'dry run without an installed model (create() would start a download)';
    return log(`smoke: skipped, ${P.skipped}`);
  }
  try {
    const r = await app.eval(
      `(async () => { const t0 = performance.now(); const s = await LanguageModel.create(${OPTS}); const t1 = performance.now();
        const a = await s.prompt(${JSON.stringify(SMOKE_PROMPT)}); const t2 = performance.now();
        const b = await s.prompt('Answer with one word: is the sky blue on a clear day?'); const t3 = performance.now(); s.destroy();
        return { createMs: Math.round(t1 - t0), promptMs: Math.round(t2 - t1), secondPromptMs: Math.round(t3 - t2), answer: a, secondAnswer: b }; })()`,
      { gesture: true, timeoutMs: 10 * MIN },
    );
    Object.assign(P, r, { ok: true });
    save();
    log(`smoke: create ${r.createMs} ms, prompt ${r.promptMs} ms, second prompt ${r.secondPromptMs} ms; answer: ${JSON.stringify(r.answer).slice(0, 300)}`);
  } catch (e) {
    Object.assign(P, { ok: false, error: e.message });
    save();
    await dumpInternals('smoke-failed');
    saveLogTail('smoke-failed');
    if (DRY) return problem(`smoke test failed: ${e.message}`);
    throw new Fatal(`smoke test failed: ${e.message}`);
  }
}

// ------------------------------------------------------------------ d. eval

async function evalDevice(app) {
  const P = (R.phases.eval = { startedAt: iso() });
  await app.viewport();
  await app.goto(`${TARGET}/eval.html`);
  await app.front();
  const status = await app.waitFor(
    `window.__evalResult && window.__evalResult.onDeviceStatus !== 'checking' && document.querySelector('button[data-route=device]') && window.__evalResult.onDeviceStatus`,
    { timeoutMs: 3 * MIN, what: 'eval page: on-device status known' },
  );
  P.statusOnPage = status;
  log(`eval page: Gemini Nano status = ${status}`);
  let route = 'device';
  if (status !== 'available') {
    await dumpInternals('eval-status');
    if (!DRY) throw new Fatal(`eval page reports Gemini Nano as "${status}" (smoke test passed, so the app's start-up probe failed)`);
    // Dry run: the device button would start a model download; exercise the same code on another route.
    route = 'heuristics';
    problem(`dry run: eval page status ${status}, running the heuristics route instead`);
  }
  P.route = route;
  const button = `document.querySelector('button[data-route=${route}]')`;
  await app.click(button);
  log(`clicked the ${route} route button (real mouse event)`);
  await app.waitFor(`${button}.textContent.includes('Running') || !!window.__evalResult?.routes?.${route}`, { timeoutMs: 60_000, what: `${route} run started` });
  const t0 = Date.now();
  let lastLog = 0;
  let st;
  for (;;) {
    await sleep(5000);
    st = await app.eval(`(() => { const d = window.__evalResult?.routes?.${route}; const last = d?.rows?.[d.rows.length - 1];
      return { running: ${button}.textContent.includes('Running'), n: d?.summary?.n ?? 0, complete: !!d?.complete, backends: d?.summary?.backends ?? {},
        error: document.querySelector('.ev-warn[role=alert]')?.textContent ?? null,
        last: last ? { id: last.id, backend: last.backend, ms: Math.round(last.latencyMs), risk: last.risk, note: last.note } : null }; })()`);
    if (Date.now() - lastLog >= 30_000 || !st.running) {
      lastLog = Date.now();
      log(`eval: ${st.n}/${EXAMPLE_COUNT} done, backends ${JSON.stringify(st.backends)}, last ${JSON.stringify(st.last)}`);
    }
    if (!st.running) break;
    if (Date.now() - t0 > 60 * MIN) {
      problem('eval run did not finish within 60 minutes; keeping the partial result');
      break;
    }
  }
  P.wallMs = Date.now() - t0;
  const result = await app.eval('window.__evalResult');
  writeFileSync(join(OUT, `eval-${route}.json`), JSON.stringify(result, null, 2));
  // The text the page's "Copy Markdown for README" button copies.
  const md = await app.eval(`document.querySelector('textarea[aria-label="Markdown for ${route}"]')?.value ?? null`);
  if (md) writeFileSync(join(OUT, `eval-${route}.md`), md + '\n');
  await app.screenshot('eval-page.png', { full: true });
  const run = result?.routes?.[route];
  const s = run?.summary;
  Object.assign(P, { complete: !!run?.complete, n: s?.n ?? 0, backends: s?.backends ?? {}, offRoute: s?.offRoute ?? null, median: s?.latencyMs?.median, p90: s?.latencyMs?.p90, error: st.error, markdown: md });
  save();
  log(`eval finished in ${secs(P.wallMs)} s: ${P.n}/${EXAMPLE_COUNT}, ${JSON.stringify(P.backends)}, median ${P.median} ms, p90 ${P.p90} ms`);
  if (st.error) problem(`eval page error: ${st.error}`);
  if (!P.complete) problem(`eval ${route} run incomplete: ${P.n}/${EXAMPLE_COUNT}`);
  if (route !== 'device') return;
  if (!(P.backends['on-device'] > 0)) problem('no eval example was answered on the device');
  else if (P.offRoute) problem(`${P.offRoute} of ${P.n} eval examples were not answered on the device (see eval-device.json notes)`);
}

// ------------------------------------------------------------------ e. shots

async function waitModelReady(app, what) {
  try {
    await app.waitFor(`document.querySelector('.ss-model')?.classList.contains('ss-model-available')`, { timeoutMs: DRY ? 15_000 : 3 * MIN, what });
    return true;
  } catch {
    const cls = await app.eval(`document.querySelector('.ss-model')?.className ?? 'no status panel'`).catch(() => '?');
    problem(`${what}: model status panel is "${cls}", not available`);
    return false;
  }
}

/** Click "Check privately" and wait for the result card. Returns what the card says. */
async function runCheck(app, { smooth = false } = {}) {
  await app.click(CHECK_BUTTON, { smooth });
  const t0 = Date.now();
  await app.waitFor(`!!document.querySelector('.ss-result .ss-prov') && !document.querySelector('.ss-btn-big')?.textContent.includes('Checking')`, {
    timeoutMs: 3 * MIN,
    what: 'result card',
  });
  const card = await app.eval(`(() => { const r = document.querySelector('.ss-result');
    return { provenance: r.querySelector('.ss-prov').textContent.trim(), verdict: r.querySelector('.ss-verdict')?.textContent.trim() ?? null,
      category: r.querySelector('.ss-category')?.textContent.trim() ?? null, foot: r.querySelector('.ss-result-foot .ss-muted')?.textContent.trim() ?? null,
      note: r.querySelector('.ss-note')?.textContent.trim() ?? null }; })()`);
  return { ...card, waitMs: Date.now() - t0, onDevice: /^On-device/.test(card.provenance) };
}

/** Bring the result card header (verdict + provenance chip) into the viewport. */
async function frameResult(app, smooth = false) {
  await app.eval(`(() => { const r = document.querySelector('.ss-result'); const y = r.getBoundingClientRect().top + window.scrollY - 24;
    window.scrollTo({ top: Math.max(0, y), behavior: '${smooth ? 'smooth' : 'instant'}' }); })()`);
  await sleep(smooth ? 1400 : 600);
  return app.eval(`(() => { const c = document.querySelector('.ss-result .ss-prov').getBoundingClientRect(); return c.top >= 0 && c.bottom <= window.innerHeight; })()`);
}

async function screenshots(app) {
  const P = (R.phases.shots = { startedAt: iso(), items: [] });
  await app.viewport();
  await app.goto(TARGET);
  await app.front();
  await waitModelReady(app, 'main app');
  for (const { id, file } of SHOTS) {
    const ex = example(id);
    await app.eval('window.scrollTo(0, 0)');
    await app.click(chip(ex.title));
    await app.waitFor(`document.querySelector('#ss-text').value === ${JSON.stringify(ex.text)}`, { timeoutMs: 10_000, what: `example ${id} in the text box` });
    const card = await runCheck(app);
    await sleep(1200); // let the app's own smooth scroll finish
    const chipVisible = await frameResult(app);
    await app.screenshot(file);
    const item = { id, file, ...card, chipVisible };
    P.items.push(item);
    save();
    log(`shot ${id}: ${card.verdict} · ${card.provenance} (chip visible: ${chipVisible})`);
    if (!card.onDevice) problem(`${id}: the check did not run on the device (${card.provenance}${card.note ? `; ${card.note}` : ''})`);
    if (!chipVisible) problem(`${id}: provenance chip not inside the screenshot`);
  }
}

// ------------------------------------------------------------------ f. demo

/**
 * Type `text` on a fixed clock of `delayMs` per character. When the page answers slower than the
 * clock, the characters that are due are inserted together, so the typing always lasts about
 * text.length * delayMs. A newline is a real Enter key press.
 */
async function typeText(app, text, delayMs = 25) {
  const t0 = Date.now();
  let i = 0;
  while (i < text.length) {
    const due = Math.max(i + 1, Math.min(text.length, Math.floor((Date.now() - t0) / delayMs) + 1));
    let chunk = text.slice(i, due);
    const nl = chunk.indexOf('\n');
    if (nl === 0) {
      const key = { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 };
      await app.send('Input.dispatchKeyEvent', { type: 'keyDown', ...key, text: '\r', unmodifiedText: '\r' });
      await app.send('Input.dispatchKeyEvent', { type: 'keyUp', ...key });
      i += 1;
    } else {
      if (nl > 0) chunk = chunk.slice(0, nl);
      await app.send('Input.insertText', { text: chunk });
      i += chunk.length;
    }
    const wait = t0 + i * delayMs - Date.now();
    if (wait > 0) await sleep(wait);
  }
}

async function demo(app) {
  const P = (R.phases.demo = { startedAt: iso() });
  const dir = join(OUT, 'frames');
  mkdirSync(dir, { recursive: true });
  const frames = [];
  const marks = [];
  const mark = (name) => {
    marks.push({ name, timestamp: Date.now() / 1000 });
    log(`demo: ${name}`);
  };
  const off = app.on('Page.screencastFrame', (p) => {
    const file = `frame-${String(frames.length + 1).padStart(5, '0')}.jpg`;
    writeFileSync(join(dir, file), Buffer.from(p.data, 'base64'));
    frames.push({ file, timestamp: p.metadata.timestamp });
    app.send('Page.screencastFrameAck', { sessionId: p.sessionId }).catch(() => undefined);
  });
  await app.viewport();
  await app.goto('about:blank');
  await app.front();
  await app.send('Page.startScreencast', { format: 'jpeg', quality: 85, maxWidth: VIEW.width, maxHeight: VIEW.height, everyNthFrame: 1 });
  try {
    mark('load app');
    await app.goto(TARGET);
    await waitModelReady(app, 'demo');
    await sleep(2000);

    const scam = example('scam-recruiter-repo');
    mark('type recruiter message');
    await app.click(`document.querySelector('#ss-text')`, { smooth: true });
    await typeText(app, scam.text);
    const typed = await app.eval(`document.querySelector('#ss-text').value`);
    if (typed !== scam.text) problem(`demo: typed text differs from the example (${typed.length} vs ${scam.text.length} chars)`);
    await sleep(1200);
    mark('check recruiter message');
    const r1 = await runCheck(app, { smooth: true });
    await sleep(2000);
    mark('scroll through reasons');
    await frameResult(app, true);
    await sleep(800);
    for (const sel of ['.ss-result .ss-reasons', '.ss-result .ss-evidence']) {
      await app.eval(`document.querySelector('${sel}')?.scrollIntoView({ block: 'start', behavior: 'smooth' })`);
      await sleep(2200);
    }
    await frameResult(app, true);
    await sleep(1500);

    const results = [r1];
    for (const id of ['scam-seed-support', 'legit-recruiter']) {
      const ex = example(id);
      mark(`pick example ${id}`);
      await app.click(chip(ex.title), { smooth: true });
      await sleep(900);
      mark(`check ${id}`);
      results.push(await runCheck(app, { smooth: true }));
      await sleep(1500);
      await frameResult(app, true);
      await sleep(2500);
    }
    mark('end');
    await sleep(1000);
    P.checks = results.map((r) => ({ verdict: r.verdict, provenance: r.provenance, onDevice: r.onDevice }));
    for (const r of results) if (!r.onDevice) problem(`demo check did not run on the device: ${r.provenance}`);
  } finally {
    await app.send('Page.stopScreencast').catch(() => undefined);
    await sleep(500);
    off();
  }
  const first = frames[0]?.timestamp ?? 0;
  const last = frames[frames.length - 1]?.timestamp ?? 0;
  const end = Math.max(last, marks[marks.length - 1]?.timestamp ?? last);
  writeFileSync(join(dir, 'frames.json'), JSON.stringify({ viewport: VIEW, firstTimestamp: first, endTimestamp: end, frames, marks }, null, 2));
  // ffmpeg concat list with each frame shown until the next one (variable frame times -> constant fps on encode).
  const lines = ['ffconcat version 1.0'];
  frames.forEach((f, i) => {
    const next = frames[i + 1]?.timestamp ?? end + 0.5;
    lines.push(`file '${f.file}'`, `duration ${Math.max(0.001, next - f.timestamp).toFixed(4)}`);
  });
  if (frames.length) lines.push(`file '${frames[frames.length - 1].file}'`);
  writeFileSync(join(dir, 'frames.ffconcat'), lines.join('\n') + '\n');
  Object.assign(P, { frames: frames.length, durationS: +(end - first).toFixed(1), marks: marks.map((m) => ({ name: m.name, atS: +(m.timestamp - first).toFixed(1) })) });
  save();
  log(`demo: ${frames.length} frames over ${P.durationS} s`);
  if (!frames.length) problem('demo: the screencast produced no frames');
}

// ------------------------------------------------------------------ g. summary

function summary() {
  const m = R.machine ?? {};
  const mp = R.phases.model ?? {};
  const sm = R.phases.smoke ?? {};
  const ev = R.phases.eval ?? {};
  const facts = R.internals?.end ?? R.internals?.start ?? {};
  const comps = (R.components ?? []).filter((c) => c.mib >= 50 || /model|nano|gemma/i.test(`${c.folder} ${c.name}`));
  const L = [];
  L.push(`# Scam Shield on-device E2E${R.problems.length || R.fatal ? ' (with problems)' : ''}`, '');
  L.push(`- Run: ${R.runUrl ?? 'local'} · started ${R.startedAt} · target ${TARGET} · model input \`${MODEL}\``);
  L.push(`- Chrome: ${R.chrome ?? 'n/a'}`);
  L.push(`- CPU: ${m.cpu ?? 'n/a'} (${m.win32Processor?.NumberOfCores ?? '?'} cores / ${m.logicalCpus ?? '?'} logical) · RAM ${m.ramGiB ?? '?'} GiB · ${m.os?.Caption ?? m.platform ?? ''}`);
  if (Array.isArray(m.gpus)) L.push(`- GPU: ${m.gpus.map((g) => g.Name).join(', ')}`);
  L.push(`- Performance class (chrome://on-device-internals): ${facts.performanceClass ?? 'n/a'}`);
  L.push(`- Model component(s) in the profile: ${comps.length ? comps.map((c) => `${c.folder} (${c.name ?? 'no name'}, version ${c.version}, ${c.mib} MiB)`).join('; ') : 'n/a'}`);
  L.push(`- Availability at start: ${mp.initial ?? 'n/a'} · download: ${mp.alreadyInstalled ? 'already installed' : mp.downloadMs ? `${secs(mp.downloadMs)} s (${(mp.downloadMs / MIN).toFixed(1)} min)` : 'n/a'}${mp.bitsKicks ? ` · BITS job removed ${mp.bitsKicks}x` : ''}`);
  L.push(`- Smoke test: ${sm.ok ? `create ${sm.createMs} ms · first prompt ${sm.promptMs} ms · second prompt ${sm.secondPromptMs} ms` : `failed: ${sm.error ?? 'not run'}`}`);
  if (sm.answer) L.push(`  - answer: ${JSON.stringify(sm.answer).slice(0, 400)}`);
  for (const s of R.phases.shots?.items ?? []) L.push(`- Screenshot \`${s.file}\`: ${s.verdict} · ${s.provenance}`);
  if (R.phases.demo) L.push(`- Demo recording: ${R.phases.demo.frames} frames over ${R.phases.demo.durationS} s (frames/frames.json, frames/frames.ffconcat)`);
  L.push('', '## Device eval (`/eval.html`, Run on device)', '');
  L.push(ev.markdown ?? `_not available${ev.n ? ` (${ev.n}/${EXAMPLE_COUNT} done)` : ''}_`);
  if (ev.wallMs) L.push('', `Wall time of the run: ${secs(ev.wallMs)} s.`);
  if (R.problems.length || R.fatal) L.push('', '## Problems', '', ...(R.fatal ? [`- FATAL: ${R.fatal}`] : []), ...R.problems.map((p) => `- ${p}`));
  if (facts.keyLines?.length) L.push('', '<details><summary>chrome://on-device-internals key lines</summary>', '', '```', ...facts.keyLines, '```', '', '</details>');
  return L.join('\n') + '\n';
}

// ------------------------------------------------------------------ main

async function main() {
  log(`target ${TARGET}, model ${MODEL}, record demo ${RECORD}, out ${OUT}, profile ${PROFILE}${DRY ? ', DRY' : ''}`);
  if (env.GITHUB_RUN_ID) R.runUrl = `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`;
  R.machine = machineFacts();
  save();
  log(`machine: ${R.machine.cpu}, ${R.machine.logicalCpus} logical CPUs, ${R.machine.ramGiB} GiB RAM`);

  const cdp = await CDP.connect(CDP_BASE);
  R.chrome = cdp.version.Browser;
  R.userAgent = cdp.version['User-Agent'];
  log(`connected to ${R.chrome}`);
  let app;
  try {
    await enableInternalPages(cdp);
    await dumpInternals('start');
    app = await Tab.open(cdp, TARGET);
    await app.viewport();
    await ensureModel(app);
    await dumpInternals('after-download');
    await smoke(app);
    await evalDevice(app);
    await screenshots(app);
    if (RECORD) await demo(app);
  } catch (e) {
    R.fatal = e.message;
    log(`FATAL: ${e.stack ?? e.message}`);
    if (app) await app.screenshot('fatal.png').catch(() => undefined);
    saveLogTail('fatal');
  } finally {
    await dumpInternals('end');
    R.components = profileComponents();
    R.finishedAt = iso();
    save();
    const md = summary();
    writeFileSync(join(OUT, 'summary.md'), md);
    console.log(`\n${md}`);
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md);
    // Close only the tabs this script opened.
    for (const t of [app, internalsTab]) if (t) await cdp.send('Target.closeTarget', { targetId: t.targetId }).catch(() => undefined);
    cdp.close();
  }
  const failed = Boolean(R.fatal) || R.problems.length > 0;
  log(failed ? `FAILED: ${R.fatal ?? R.problems.join(' | ')}` : 'OK: all phases passed');
  process.exitCode = failed ? 1 : 0;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
