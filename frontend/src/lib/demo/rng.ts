/** Deterministic pseudo-random helpers for DEMO data (same seed, same data). */

export function hashSeed(text: string): number {
  // FNV-1a 32-bit
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export interface Rng {
  next(): number;
  int(min: number, max: number): number;
  float(min: number, max: number, digits?: number): number;
  pick<T>(items: readonly T[]): T;
  chance(p: number): boolean;
  weighted<T>(items: readonly (readonly [T, number])[]): T;
  sample<T>(items: readonly T[], n: number): T[];
  hex(length: number): string;
}

export function createRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = () => {
    // mulberry32
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const rng: Rng = {
    next,
    int: (min, max) => Math.floor(next() * (max - min + 1)) + min,
    float: (min, max, digits = 1) => Number((next() * (max - min) + min).toFixed(digits)),
    pick: (items) => items[Math.floor(next() * items.length)],
    chance: (p) => next() < p,
    weighted: (items) => {
      const total = items.reduce((s, [, w]) => s + w, 0);
      let r = next() * total;
      for (const [value, w] of items) {
        r -= w;
        if (r <= 0) return value;
      }
      return items[items.length - 1][0];
    },
    sample: (items, n) => {
      const copy = [...items];
      const out: typeof items[number][] = [];
      while (copy.length && out.length < n) out.push(copy.splice(Math.floor(next() * copy.length), 1)[0]);
      return out;
    },
    hex: (length) => Array.from({ length }, () => Math.floor(next() * 16).toString(16)).join(""),
  };
  return rng;
}
