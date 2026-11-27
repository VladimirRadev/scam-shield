import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain ESM script without type declarations
import { filesContaining, readDebugToken } from '../check-no-debug-token.mjs';

describe('check-no-debug-token', () => {
  it('finds the token in nested build files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ss-dist-'));
    mkdirSync(join(dir, 'assets'));
    writeFileSync(join(dir, 'index.html'), '<html></html>');
    writeFileSync(join(dir, 'assets', 'app.js'), 'const t="1111-SECRET-2222";');
    expect(filesContaining(dir, '1111-SECRET-2222')).toEqual([join(dir, 'assets', 'app.js')]);
    expect(filesContaining(dir, 'not-there')).toEqual([]);
  });

  it('reads the token from an env file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ss-env-'));
    writeFileSync(join(dir, '.env.local'), 'VITE_FIREBASE_API_KEY=x\nVITE_APPCHECK_DEBUG_TOKEN="abc-123"\n');
    expect(readDebugToken(dir, {})).toBe('abc-123');
    expect(readDebugToken(dir, { VITE_APPCHECK_DEBUG_TOKEN: 'from-env' })).toBe('from-env');
  });
});
