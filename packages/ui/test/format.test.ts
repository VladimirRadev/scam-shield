import { describe, expect, it } from 'vitest';
import { formatBytes, formatMs, provenance } from '../src/format';

describe('format helpers', () => {
  it('formats latency', () => {
    expect(formatMs(840)).toBe('840 ms');
    expect(formatMs(1234)).toBe('1.2 s');
    expect(formatMs(12_400)).toBe('12 s');
  });

  it('formats bytes', () => {
    expect(formatBytes(0)).toBe('0 bytes');
    expect(formatBytes(512)).toBe('512 bytes');
    expect(formatBytes(2150)).toBe('2.1 kB');
  });

  it('builds the provenance line', () => {
    expect(provenance({ backend: 'on-device', latencyMs: 840, bytesSent: 0, kind: 'quick' })).toBe(
      'On-device Gemini Nano · 840 ms · 0 bytes sent',
    );
    expect(provenance({ backend: 'cloud-redacted', latencyMs: 1200, bytesSent: 2150, kind: 'quick' })).toBe(
      'Cloud · redacted · 1.2 s · 2.1 kB sent',
    );
  });
});
