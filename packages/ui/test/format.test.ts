import { describe, expect, it } from 'vitest';
import { communityLine, dataPathSteps, formatBytes, formatMs, provenance } from '../src/format';

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

  it('builds the community line, or nothing before the first check', () => {
    expect(communityLine({ checks: 1284, onDevice: 800, cloudRedacted: 372, heuristicsOnly: 112 })).toBe('1,284 checks so far · 71% never left the device');
    expect(communityLine({ checks: 1, onDevice: 1, cloudRedacted: 0, heuristicsOnly: 0 })).toBe('1 check so far · 100% never left the device');
    expect(communityLine({ checks: 0, onDevice: 0, cloudRedacted: 0, heuristicsOnly: 0 })).toBeNull();
    expect(communityLine(null)).toBeNull();
  });

  it('never rounds a partial share up to 100% or down to 0%', () => {
    expect(communityLine({ checks: 1000, onDevice: 998, cloudRedacted: 2, heuristicsOnly: 0 })).toBe('1,000 checks so far · 99% never left the device');
    expect(communityLine({ checks: 1000, onDevice: 2, cloudRedacted: 998, heuristicsOnly: 0 })).toBe('1,000 checks so far · 1% never left the device');
  });
});

describe('data path and provenance agree on what left the device', () => {
  const base = { latencyMs: 1200, kind: 'quick' as const, signals: [], redaction: { text: '', redactions: [], counts: {} } };
  const cloud = (r: Parameters<typeof dataPathSteps>[0]) => dataPathSteps(r).find((s) => s.key === 'cloud')!;

  it('a failed cloud call that sent redacted text lights the cloud step and says so', () => {
    const r = { ...base, backend: 'heuristics-only' as const, bytesSent: 2150 };
    expect(cloud(r)).toMatchObject({ on: true });
    expect(cloud(r).detail).toBe('redacted only · 2.1 kB · no usable answer');
    expect(provenance(r)).toBe('Local checks · no usable cloud answer · 1.2 s · 2.1 kB sent');
  });

  it('nothing sent only when no byte left the device', () => {
    const r = { ...base, backend: 'heuristics-only' as const, bytesSent: 0 };
    expect(cloud(r)).toMatchObject({ on: false, detail: 'nothing sent' });
    expect(provenance(r)).toBe('Local checks only · 1.2 s · 0 bytes sent');
  });

  it('a cloud answer', () => {
    const r = { ...base, backend: 'cloud-redacted' as const, bytesSent: 2150 };
    expect(cloud(r)).toMatchObject({ on: true, detail: 'redacted only · 2.1 kB' });
  });

  it('an on-device answer', () => {
    const r = { ...base, backend: 'on-device' as const, bytesSent: 0, latencyMs: 840 };
    expect(dataPathSteps(r).find((s) => s.key === 'device')).toMatchObject({ on: true, detail: '840 ms · raw text stayed here' });
    expect(cloud(r)).toMatchObject({ on: false, detail: 'nothing sent' });
  });
});
