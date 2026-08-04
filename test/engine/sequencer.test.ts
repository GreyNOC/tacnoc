import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { analyzeTokenSamples } from '../../src/engine/analysis/sequencer.js';

function deterministicTokens(count: number): Buffer[] {
  return Array.from({ length: count }, (_unused, index) =>
    createHash('sha256').update(`tacnoc-sequencer-${index}`).digest(),
  );
}

describe('sequencer token analysis', () => {
  it('detects collisions, compression, and severe bias in a repeated token set', () => {
    const analysis = analyzeTokenSamples(new Array(200).fill('AAAAAAAAAAAAAAAA'), 'text');
    expect(analysis.assessment).toBe('poor');
    expect(analysis.uniqueCount).toBe(1);
    expect(analysis.duplicateCount).toBe(199);
    expect(analysis.shannonBitsPerByte).toBe(0);
    expect(analysis.estimatedEntropyBitsPerToken).toBe(0);
    expect(analysis.observations.some((item) => item.level === 'warning')).toBe(true);
  });

  it('reports high distribution entropy without claiming cryptographic proof', () => {
    const samples = deterministicTokens(500).map((token) => token.toString('hex'));
    const analysis = analyzeTokenSamples(samples, 'hex');
    expect(analysis.assessment).toBe('no-obvious-bias');
    expect(analysis.uniqueCount).toBe(500);
    expect(analysis.shannonBitsPerByte).toBeGreaterThan(7.9);
    expect(analysis.estimatedEntropyBitsPerToken).toBeGreaterThan(200);
    expect(Math.abs(analysis.serialCorrelation)).toBeLessThan(0.1);
  });

  it('analyzes decoded bytes instead of the printable Base64 alphabet', () => {
    const samples = deterministicTokens(200).map((token) => token.toString('base64'));
    const analysis = analyzeTokenSamples(samples, 'base64');
    expect(analysis.totalBytes).toBe(200 * 32);
    expect(analysis.meanLength).toBe(32);
    expect(analysis.alphabetSize).toBeGreaterThan(240);
  });

  it('rates small sample sets as insufficient and rejects malformed encodings', () => {
    expect(analyzeTokenSamples(['a', 'b', 'c'], 'text').assessment).toBe('insufficient-data');
    expect(() => analyzeTokenSamples(['xyz'], 'hex')).toThrow(/hexadecimal/i);
    expect(() => analyzeTokenSamples(['%%%'], 'base64')).toThrow(/Base64/i);
  });

  it('rates a strong monobit bit-bias as poor even when its p-value formats in exponential notation', () => {
    // Bits are 1 with probability ~0.52 (iid): byte entropy stays high (no
    // distribution/compression/collision warning), but the global bit bias is
    // extreme, so the monobit p-value is astronomically small and renders in
    // exponential notation. Severity must be decided from the number — the old
    // string-matching classifier rated this the LESS-severe "weak".
    const samples = biasedBitTokens(300, 32, 133).map((token) => token.toString('hex'));
    const analysis = analyzeTokenSamples(samples, 'hex');
    expect(analysis.monobitPValue).toBeLessThan(1e-4);
    expect(analysis.shannonBitsPerByte).toBeGreaterThan(7);
    expect(analysis.duplicateCount).toBe(0);
    expect(analysis.assessment).toBe('poor');
    expect(analysis.observations.some((observation) => /monobit/i.test(observation.message))).toBe(
      true,
    );
  });

  it('validates Base64 and Base64url identically (no cross-alphabet divergence)', () => {
    // length % 4 === 1 is invalid for both alphabets, not just Base64.
    expect(() => analyzeTokenSamples(['ABCDE'], 'base64')).toThrow(/Base64/i);
    expect(() => analyzeTokenSamples(['ABCDE'], 'base64url')).toThrow(/Base64url/i);
    // Interior whitespace is stripped for both, so a spaced value decodes the same.
    expect(analyzeTokenSamples(['A AAA'], 'base64url').totalBytes).toBe(3);
    expect(analyzeTokenSamples(['AAAA'], 'base64url').totalBytes).toBe(3);
  });
});

/** Deterministic tokens whose bits are 1 when the next PRNG byte < `threshold` (of 256). */
function biasedBitTokens(count: number, byteLen: number, threshold: number): Buffer[] {
  let pool = Buffer.alloc(0);
  let counter = 0;
  const nextByte = (): number => {
    if (pool.length === 0) pool = createHash('sha256').update(`bias-${counter++}`).digest();
    const value = pool[0]!;
    pool = pool.subarray(1);
    return value;
  };
  const tokens: Buffer[] = [];
  for (let t = 0; t < count; t++) {
    const bytes = Buffer.alloc(byteLen);
    for (let k = 0; k < byteLen; k++) {
      let value = 0;
      for (let bit = 0; bit < 8; bit++) value = (value << 1) | (nextByte() < threshold ? 1 : 0);
      bytes[k] = value;
    }
    tokens.push(bytes);
  }
  return tokens;
}
