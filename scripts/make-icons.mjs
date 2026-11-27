#!/usr/bin/env node
/**
 * Rasterise the Scam Shield mark into the PNG icons Chrome extensions need (16/32/48/128 px).
 * Dependency-free: point-in-polygon with 4x4 supersampling, PNG written with node:zlib.
 *
 *   node scripts/make-icons.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { deflateSync, crc32 } from 'node:zlib';

const OUT = new URL('../apps/extension/public/icons/', import.meta.url);
// Diagonal brand gradient, top-left to bottom-right (same as the ShieldMark SVG).
const BRAND_FROM = [0x8a, 0x5c, 0xf0];
const BRAND_TO = [0xd3, 0x5c, 0xff];
const brandAt = (x, y) => {
  const t = Math.max(0, Math.min(1, (x / 100 + y / 116) / 2));
  return BRAND_FROM.map((c, i) => c + (BRAND_TO[i] - c) * t);
};

function cubic(p0, p1, p2, p3, n = 24) {
  const pts = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n, u = 1 - t;
    pts.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return pts;
}

// M50 4 L92 18 V54 C92 82 74 102 50 112 C26 102 8 82 8 54 V18 Z  (viewBox 100 x 116)
const SHIELD = [[50, 4], [92, 18], [92, 54], ...cubic([92, 54], [92, 82], [74, 102], [50, 112]), ...cubic([50, 112], [26, 102], [8, 82], [8, 54]), [8, 18]];
const KEY_STEM = [[45, 58], [55, 58], [58, 78], [42, 78]];

function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
const inKeyhole = (x, y) => (x - 50) ** 2 + (y - 50) ** 2 <= 11 ** 2 || inPoly(x, y, KEY_STEM);

function render(size) {
  const scale = (size * 0.94) / 116;
  const ox = (size - 100 * scale) / 2, oy = (size - 116 * scale) / 2;
  const showKey = size >= 32;
  const px = Buffer.alloc(size * size * 4);
  const S = 4;
  for (let py = 0; py < size; py++) {
    for (let pxl = 0; pxl < size; pxl++) {
      let shield = 0, key = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const x = (pxl + (sx + 0.5) / S - ox) / scale;
          const y = (py + (sy + 0.5) / S - oy) / scale;
          if (inPoly(x, y, SHIELD)) {
            if (showKey && inKeyhole(x, y)) key++;
            else shield++;
          }
        }
      }
      const total = S * S, a = (shield + key) / total;
      const k = shield + key ? key / (shield + key) : 0;
      const i = (py * size + pxl) * 4;
      const brand = brandAt((pxl + 0.5 - ox) / scale, (py + 0.5 - oy) / scale);
      px[i] = Math.round(brand[0] * (1 - k) + 0xfc * k);
      px[i + 1] = Math.round(brand[1] * (1 - k) + 0xfa * k);
      px[i + 2] = Math.round(brand[2] * (1 - k) + 0xff * k);
      px[i + 3] = Math.round(a * 255);
    }
  }
  return px;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([len, body, crc]);
}

function png(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync(OUT, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  writeFileSync(new URL(`icon-${size}.png`, OUT), png(size, render(size)));
  console.log(`icons/icon-${size}.png`);
}
