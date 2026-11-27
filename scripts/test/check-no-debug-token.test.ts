import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain ESM script without type declarations
import { checkBuild, filesContaining, filesWithDebugTokenPattern, readDebugToken } from '../check-no-debug-token.mjs';

const UUID = '123e4567-e89b-42d3-a456-426614174000';

function dist(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'ss-dist-'));
  mkdirSync(join(dir, 'assets'));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

describe('check-no-debug-token', () => {
  it('finds the token in nested build files', () => {
    const dir = dist({ 'index.html': '<html></html>', 'assets/app.js': 'const t="1111-SECRET-2222";' });
    expect(filesContaining(dir, '1111-SECRET-2222')).toEqual([join(dir, 'assets', 'app.js')]);
    expect(filesContaining(dir, 'not-there')).toEqual([]);
  });

  it('reads the token from an env file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ss-env-'));
    writeFileSync(join(dir, '.env.local'), 'VITE_FIREBASE_API_KEY=x\nVITE_APPCHECK_DEBUG_TOKEN="abc-123"\n');
    expect(readDebugToken(dir, {})).toBe('abc-123');
    expect(readDebugToken(dir, { VITE_APPCHECK_DEBUG_TOKEN: 'from-env' })).toBe('from-env');
  });

  it.each(['.env.development', '.env.development.local'])('also reads %s', (file) => {
    const dir = mkdtempSync(join(tmpdir(), 'ss-env-'));
    writeFileSync(join(dir, file), `VITE_APPCHECK_DEBUG_TOKEN=${UUID}\n`);
    expect(readDebugToken(dir, {})).toBe(UUID);
  });

  it('finds an App Check debug token by its shape, with no env file at all', () => {
    const dir = dist({
      'assets/a.js': `self.FIREBASE_APPCHECK_DEBUG_TOKEN="${UUID}";`,
      'assets/b.js': `const env={VITE_APPCHECK_DEBUG_TOKEN:'${UUID.toUpperCase()}'};`,
      'assets/c.js': 'globalThis.FIREBASE_APPCHECK_DEBUG_TOKEN=e.appCheckDebugToken;',
    });
    expect(filesWithDebugTokenPattern(dir).sort()).toEqual([join(dir, 'assets', 'a.js'), join(dir, 'assets', 'b.js')]);
  });

  it('fails closed: a token-shaped value fails the check even when no token is configured', () => {
    const root = mkdtempSync(join(tmpdir(), 'ss-root-'));
    const bad = checkBuild({ dist: dist({ 'assets/a.js': `x.FIREBASE_APPCHECK_DEBUG_TOKEN = "${UUID}"` }), root, env: {} });
    expect(bad.ok).toBe(false);
    const good = checkBuild({ dist: dist({ 'assets/a.js': 'globalThis.FIREBASE_APPCHECK_DEBUG_TOKEN=e;' }), root, env: {} });
    expect(good.ok).toBe(true);
  });

  it('fails when the configured token is inside the build', () => {
    const root = mkdtempSync(join(tmpdir(), 'ss-root-'));
    writeFileSync(join(root, '.env.development.local'), 'VITE_APPCHECK_DEBUG_TOKEN=plain-token-value\n');
    expect(checkBuild({ dist: dist({ 'assets/a.js': 'var t="plain-token-value"' }), root, env: {} }).ok).toBe(false);
  });
});

describe('firebase.json', () => {
  it('builds the web app and runs the guard before every Hosting deploy', () => {
    const cfg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'firebase.json'), 'utf8')) as { hosting: { predeploy?: string[] } };
    expect(cfg.hosting.predeploy?.join(' ')).toMatch(/npm .*run build/);
  });
});
