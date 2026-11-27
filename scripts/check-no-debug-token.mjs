#!/usr/bin/env node
/**
 * Build guard: fails when the App Check debug token appears anywhere in the hosted web build.
 * The token value is read from the environment or from the repo's .env files (never printed).
 *
 *   node scripts/check-no-debug-token.mjs [distDir]
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ENV_FILES = ['.env', '.env.local', '.env.production', '.env.production.local'];

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

/** Return every file under `dir` that contains `needle`. */
export function filesContaining(dir, needle) {
  const hits = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (readFileSync(p).includes(needle)) hits.push(p);
    }
  };
  walk(dir);
  return hits;
}

function main() {
  const dist = resolve(process.argv[2] ?? join(ROOT, 'apps/web/dist'));
  if (!existsSync(dist)) {
    console.error(`check-no-debug-token: ${dist} does not exist; build the web app first.`);
    process.exit(2);
  }
  const token = readDebugToken();
  if (!token) {
    console.log('check-no-debug-token: no debug token configured, nothing to check.');
    return;
  }
  const hits = filesContaining(dist, token);
  if (hits.length) {
    console.error(`check-no-debug-token: FAIL, the App Check debug token is inside the hosted build:\n  ${hits.join('\n  ')}`);
    process.exit(1);
  }
  console.log(`check-no-debug-token: OK, debug token not found in ${dist}.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
