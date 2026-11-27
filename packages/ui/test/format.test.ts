import { describe, expect, it } from 'vitest';
import { communityLine, formatBytes, formatMs, provenance } from '../src/format';

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
