/**
 * Statistical token analysis inspired by the workflow of randomness analyzers.
 * Results are screening signals, not a cryptographic proof of unpredictability.
 */

import * as zlib from 'node:zlib';
import type {
  PositionalEntropy,
  SequenceAnalysis,
  SequenceAssessment,
  SequenceObservation,
  TokenEncoding,
} from '../../shared/sequencer.js';

const MAX_SAMPLES = 100_000;
const MAX_SAMPLE_BYTES = 64 * 1024;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_POSITIONAL_BYTES = 256;

const POPCOUNT = Uint8Array.from({ length: 256 }, (_v, n) => {
  let value = n;
  let count = 0;
  while (value) {
    count += value & 1;
    value >>>= 1;
  }
  return count;
});

export function analyzeTokenSamples(
  samples: readonly string[],
  encoding: TokenEncoding,
): SequenceAnalysis {
  if (samples.length === 0) throw new Error('Provide at least one non-empty token sample.');
  if (samples.length > MAX_SAMPLES) {
    throw new Error(`Too many samples: the analyzer limit is ${MAX_SAMPLES.toLocaleString()}.`);
  }

  const decoded: Buffer[] = [];
  let totalBytes = 0;
  for (let i = 0; i < samples.length; i++) {
    const bytes = decodeSample(samples[i] ?? '', encoding, i + 1);
    if (bytes.length === 0) throw new Error(`Sample ${i + 1} decodes to an empty token.`);
    if (bytes.length > MAX_SAMPLE_BYTES) {
      throw new Error(
        `Sample ${i + 1} exceeds the ${MAX_SAMPLE_BYTES.toLocaleString()}-byte limit.`,
      );
    }
    totalBytes += bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error(
        `Decoded samples exceed the ${Math.trunc(MAX_TOTAL_BYTES / 1024 / 1024)} MiB analysis limit.`,
      );
    }
    decoded.push(bytes);
  }

  // Fold min/max with a loop rather than Math.min(...spread): the spread throws
  // "Maximum call stack size exceeded" on very large sample sets (near the
  // MAX_SAMPLES cap), turning a legitimate large input into a confusing crash.
  let minLength = Infinity;
  let maxLength = 0;
  for (const sample of decoded) {
    if (sample.length < minLength) minLength = sample.length;
    if (sample.length > maxLength) maxLength = sample.length;
  }
  const meanLength = totalBytes / decoded.length;
  const joined = Buffer.concat(decoded, totalBytes);
  const counts = byteCounts(joined);
  const alphabetSize = counts.filter((count) => count > 0).length;
  const shannonBitsPerByte = shannon(counts, totalBytes);
  const minEntropyBitsPerByte = minEntropy(counts, totalBytes);
  const positional = positionalEntropy(decoded, maxLength);
  const estimatedEntropyBitsPerToken = positional.reduce(
    (sum, position) => sum + position.entropyBits * (position.sampleCount / decoded.length),
    0,
  );

  const frequencies = new Map<string, number>();
  for (const sample of decoded) {
    const key = sample.toString('base64');
    frequencies.set(key, (frequencies.get(key) ?? 0) + 1);
  }
  let maxTokenFrequency = 0;
  for (const freq of frequencies.values()) if (freq > maxTokenFrequency) maxTokenFrequency = freq;
  const uniqueCount = frequencies.size;
  const duplicateCount = decoded.length - uniqueCount;
  const observedTokenMinEntropyBits = -Math.log2(maxTokenFrequency / decoded.length);

  let ones = 0;
  for (const value of joined) ones += POPCOUNT[value] ?? 0;
  const totalBits = joined.length * 8;
  const zeros = totalBits - ones;
  const bitOneRatio = ones / totalBits;
  const monobitPValue = erfc(Math.abs(ones - zeros) / Math.sqrt(totalBits * 2));
  const serialCorrelation = correlation(joined);
  const compressedLength = zlib.deflateRawSync(joined, { level: 9 }).length;
  const compressionRatio = compressedLength / joined.length;

  const observations = observationsFor({
    sampleCount: decoded.length,
    totalBytes,
    duplicateCount,
    minLength,
    maxLength,
    shannonBitsPerByte,
    estimatedEntropyBitsPerToken,
    monobitPValue,
    serialCorrelation,
    compressionRatio,
    positional,
  });
  const assessment = assess(
    {
      sampleCount: decoded.length,
      totalBytes,
      duplicateCount,
      shannonBitsPerByte,
      estimatedEntropyBitsPerToken,
      monobitPValue,
      serialCorrelation,
      compressionRatio,
    },
    observations,
  );

  return {
    assessment,
    encoding,
    sampleCount: decoded.length,
    uniqueCount,
    duplicateCount,
    totalBytes,
    minLength,
    maxLength,
    meanLength,
    alphabetSize,
    shannonBitsPerByte,
    minEntropyBitsPerByte,
    estimatedEntropyBitsPerToken,
    observedTokenMinEntropyBits,
    bitOneRatio,
    monobitPValue,
    serialCorrelation,
    compressionRatio,
    positional,
    observations,
  };
}

function decodeSample(sample: string, encoding: TokenEncoding, line: number): Buffer {
  switch (encoding) {
    case 'text':
      return Buffer.from(sample, 'utf8');
    case 'hex': {
      const normalized = sample
        .trim()
        .replace(/^0x/i, '')
        .replace(/[\s:-]/g, '');
      if (!normalized || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(normalized)) {
        throw new Error(`Sample ${line} is not valid even-length hexadecimal.`);
      }
      return Buffer.from(normalized, 'hex');
    }
    case 'base64': {
      const normalized = sample.replace(/\s/g, '');
      if (!isBase64(normalized)) throw new Error(`Sample ${line} is not valid Base64.`);
      return Buffer.from(normalized, 'base64');
    }
    case 'base64url': {
      // Match the base64 branch: strip interior whitespace and apply the same
      // length guard, so a value is not accepted under one alphabet and
      // rejected (or decoded differently) under the other.
      const normalized = sample.replace(/\s/g, '');
      if (!/^[A-Za-z0-9_-]+={0,2}$/.test(normalized) || normalized.length % 4 === 1) {
        throw new Error(`Sample ${line} is not valid Base64url.`);
      }
      return Buffer.from(normalized, 'base64url');
    }
    default:
      // Guards the untyped IPC boundary (encoding arrives as `never`); a bad
      // value gets a clear message instead of an opaque undefined-length crash.
      throw new Error(`Unsupported token encoding: ${String(encoding)}`);
  }
}

function isBase64(value: string): boolean {
  if (!value || value.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const padding = value.indexOf('=');
  return padding === -1 || padding >= value.length - 2;
}

function byteCounts(bytes: Uint8Array): number[] {
  const counts = new Array<number>(256).fill(0);
  for (const value of bytes) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function shannon(counts: readonly number[], total: number): number {
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function minEntropy(counts: readonly number[], total: number): number {
  return -Math.log2(Math.max(...counts) / total);
}

function positionalEntropy(samples: readonly Buffer[], maxLength: number): PositionalEntropy[] {
  const positions = Math.min(maxLength, MAX_POSITIONAL_BYTES);
  const out: PositionalEntropy[] = [];
  for (let position = 0; position < positions; position++) {
    const counts = new Array<number>(256).fill(0);
    let count = 0;
    for (const sample of samples) {
      const value = sample[position];
      if (value === undefined) continue;
      counts[value] = (counts[value] ?? 0) + 1;
      count += 1;
    }
    const entropyBits = shannon(counts, count);
    out.push({ position, sampleCount: count, entropyBits, normalized: entropyBits / 8 });
  }
  return out;
}

function correlation(bytes: Uint8Array): number {
  if (bytes.length < 3) return 0;
  const n = bytes.length - 1;
  let sumX = 0;
  let sumY = 0;
  let sumXX = 0;
  let sumYY = 0;
  let sumXY = 0;
  for (let i = 0; i < n; i++) {
    const x = bytes[i] ?? 0;
    const y = bytes[i + 1] ?? 0;
    sumX += x;
    sumY += y;
    sumXX += x * x;
    sumYY += y * y;
    sumXY += x * y;
  }
  const numerator = n * sumXY - sumX * sumY;
  const denominator = Math.sqrt((n * sumXX - sumX ** 2) * (n * sumYY - sumY ** 2));
  return denominator === 0 ? 1 : numerator / denominator;
}

function observationsFor(metrics: {
  sampleCount: number;
  totalBytes: number;
  duplicateCount: number;
  minLength: number;
  maxLength: number;
  shannonBitsPerByte: number;
  estimatedEntropyBitsPerToken: number;
  monobitPValue: number;
  serialCorrelation: number;
  compressionRatio: number;
  positional: PositionalEntropy[];
}): SequenceObservation[] {
  const observations: SequenceObservation[] = [];
  const duplicateRate = metrics.duplicateCount / metrics.sampleCount;

  if (metrics.sampleCount < 100 || metrics.totalBytes < 1024) {
    observations.push({
      level: 'info',
      message: 'Collect at least 100 samples and 1 KiB of decoded token data before rating bias.',
    });
  }
  if (metrics.minLength !== metrics.maxLength) {
    observations.push({
      level: 'info',
      message: `Token length varies from ${metrics.minLength} to ${metrics.maxLength} decoded bytes.`,
    });
  }
  if (duplicateRate > 0.01) {
    observations.push({
      level: 'warning',
      message: `${(duplicateRate * 100).toFixed(2)}% of samples repeat a previously observed token.`,
    });
  }
  if (metrics.shannonBitsPerByte < 5) {
    observations.push({
      level: 'warning',
      message: 'The decoded byte distribution has very low entropy.',
    });
  } else if (metrics.shannonBitsPerByte < 7) {
    observations.push({
      level: 'warning',
      message: 'The decoded byte distribution is materially non-uniform.',
    });
  }
  if (metrics.estimatedEntropyBitsPerToken < 32) {
    observations.push({
      level: 'warning',
      message:
        'Estimated per-token entropy is below 32 bits under the positional independence model.',
    });
  } else if (metrics.estimatedEntropyBitsPerToken < 64) {
    observations.push({
      level: 'warning',
      message:
        'Estimated per-token entropy is below 64 bits under the positional independence model.',
    });
  }
  if (metrics.monobitPValue < 0.01) {
    observations.push({
      level: 'warning',
      message: `The monobit frequency test detects significant bit bias (p=${formatP(metrics.monobitPValue)}).`,
    });
  }
  if (Math.abs(metrics.serialCorrelation) > 0.1) {
    observations.push({
      level: 'warning',
      message: `Adjacent decoded bytes are correlated (r=${metrics.serialCorrelation.toFixed(3)}).`,
    });
  }
  if (metrics.totalBytes >= 1024 && metrics.compressionRatio < 0.9) {
    observations.push({
      level: 'warning',
      message: `Samples compress to ${(metrics.compressionRatio * 100).toFixed(1)}% of their decoded size, indicating structure or repetition.`,
    });
  }
  const fixedPositions = metrics.positional.filter(
    (position) => position.sampleCount === metrics.sampleCount && position.entropyBits === 0,
  ).length;
  if (fixedPositions > 0) {
    observations.push({
      level: 'info',
      message: `${fixedPositions} decoded byte position(s) are constant across every sample.`,
    });
  }
  if (!observations.some((item) => item.level === 'warning')) {
    observations.push({
      level: 'info',
      message:
        'No obvious distribution, collision, compression, or adjacent-byte bias was detected.',
    });
  }
  return observations;
}

interface AssessMetrics {
  sampleCount: number;
  totalBytes: number;
  duplicateCount: number;
  shannonBitsPerByte: number;
  estimatedEntropyBitsPerToken: number;
  monobitPValue: number;
  serialCorrelation: number;
  compressionRatio: number;
}

function assess(
  metrics: AssessMetrics,
  observations: readonly SequenceObservation[],
): SequenceAssessment {
  if (metrics.sampleCount < 100 || metrics.totalBytes < 1024) return 'insufficient-data';
  const duplicateRate = metrics.duplicateCount / metrics.sampleCount;
  // Decide severity from the numbers directly. The previous version matched
  // regexes against the formatted warning strings, which silently inverted:
  // a monobit p-value < 1e-4 renders in exponential notation ("3.4e-27") and
  // failed the /p=0…/ test, so the STRONGEST bias was rated less severe than a
  // milder one. A monotonic numeric test cannot regress that way.
  const severe =
    metrics.shannonBitsPerByte < 5 ||
    metrics.estimatedEntropyBitsPerToken < 32 ||
    duplicateRate > 0.01 ||
    (metrics.totalBytes >= 1024 && metrics.compressionRatio < 0.9) ||
    metrics.monobitPValue < 0.01 ||
    Math.abs(metrics.serialCorrelation) > 0.3;
  if (severe) return 'poor';
  return observations.some((item) => item.level === 'warning') ? 'weak' : 'no-obvious-bias';
}

/** Numerical Recipes approximation, accurate enough for the monobit p-value. */
function erfc(value: number): number {
  const z = Math.abs(value);
  const t = 1 / (1 + z / 2);
  const answer =
    t *
    Math.exp(
      -z * z -
        1.26551223 +
        t *
          (1.00002368 +
            t *
              (0.37409196 +
                t *
                  (0.09678418 +
                    t *
                      (-0.18628806 +
                        t *
                          (0.27886807 +
                            t *
                              (-1.13520398 +
                                t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))),
    );
  return value >= 0 ? answer : 2 - answer;
}

function formatP(value: number): string {
  return value < 0.0001 ? value.toExponential(2) : value.toFixed(4);
}
