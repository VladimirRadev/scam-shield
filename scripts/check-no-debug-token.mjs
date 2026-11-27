#!/usr/bin/env node
/**
 * Build guard: fails when an App Check debug token appears anywhere in the hosted web build.
 *
 * Two checks, so it fails closed even when no token is configured on this machine:
 * 1. the configured token value (environment or the repo's .env files; never printed);
 * 2. the shape of any debug token: a UUID assigned to FIREBASE_APPCHECK_DEBUG_TOKEN or
 *    VITE_APPCHECK_DEBUG_TOKEN.
 *
 *   node scripts/check-no-debug-token.mjs [distDir]
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ENV_FILES = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.development.local',
  '.env.production',
  '.env.production.local',
];

/** `FIREBASE_APPCHECK_DEBUG_TOKEN = "<uuid>"`, `VITE_APPCHECK_DEBUG_TOKEN:"<uuid>"` and quoted-key forms. */
const TOKEN_SHAPE_RE =
  /(?:FIREBASE|VITE)_APPCHECK_DEBUG_TOKEN["'`]?\s*[:=]\s*["'`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["'`]/i;

export function readDebugToken(root = ROOT, env = process.env) {
  if (env.VITE_APPCHECK_DEBUG_TOKEN) return env.VITE_APPCHECK_DEBUG_TOKEN.trim();
  for (const f of ENV_FILES) {
    const p = join(root, f);
    if (!existsSync(p)) continue;
    const m = /^\s*VITE_APPCHECK_DEBUG_TOKEN\s*=\s*["']?([^"'\s#]+)/m.exec(readFileSync(p, 'utf8'));
    if (m?.[1]) return m[1];
  }
  return null;
}

function walk(dir, visit) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, visit);
    else visit(p);
  }
}

/** Return every file under `dir` that contains `needle`. */
export function filesContaining(dir, needle) {
  const hits = [];
  walk(dir, (p) => {
    if (readFileSync(p).includes(needle)) hits.push(p);
  });
  return hits;
}

/** Return every file under `dir` that assigns a UUID-shaped App Check debug token. */
export function filesWithDebugTokenPattern(dir) {
  const hits = [];
  walk(dir, (p) => {
    if (TOKEN_SHAPE_RE.test(readFileSync(p, 'latin1'))) hits.push(p);
  });
  return hits;
}

/** Run both checks on a build directory. */
export function checkBuild({ dist, root = ROOT, env = process.env }) {
  const token = readDebugToken(root, env);
  const hits = new Set(filesWithDebugTokenPattern(dist));
  if (token) for (const h of filesContaining(dist, token)) hits.add(h);
  if (hits.size) {
    return { ok: false, message: `check-no-debug-token: FAIL, an App Check debug token is inside the hosted build:\n  ${[...hits].join('\n  ')}` };
  }
  return {
    ok: true,
    message: `check-no-debug-token: OK, no debug token in ${dist} (${token ? 'configured value and ' : ''}token-shaped values checked).`,
  };
}

function main() {
  const dist = resolve(process.argv[2] ?? join(ROOT, 'apps/web/dist'));
  if (!existsSync(dist)) {
    console.error(`check-no-debug-token: ${dist} does not exist; build the web app first.`);
    process.exit(2);
  }
  const r = checkBuild({ dist });
  if (!r.ok) {
    console.error(r.message);
    process.exit(1);
  }
  console.log(r.message);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
