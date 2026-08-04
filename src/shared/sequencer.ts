/** DTOs for token randomness analysis. */

export type TokenEncoding = 'text' | 'hex' | 'base64' | 'base64url';
export type SequenceAssessment = 'insufficient-data' | 'poor' | 'weak' | 'no-obvious-bias';

export interface PositionalEntropy {
  position: number;
  sampleCount: number;
  entropyBits: number;
  normalized: number;
}

export interface SequenceObservation {
  level: 'warning' | 'info';
  message: string;
}

export interface SequenceAnalysis {
  assessment: SequenceAssessment;
  encoding: TokenEncoding;
  sampleCount: number;
  uniqueCount: number;
  duplicateCount: number;
  totalBytes: number;
  minLength: number;
  maxLength: number;
  meanLength: number;
  alphabetSize: number;
  shannonBitsPerByte: number;
  minEntropyBitsPerByte: number;
  estimatedEntropyBitsPerToken: number;
  observedTokenMinEntropyBits: number;
  bitOneRatio: number;
  monobitPValue: number;
  serialCorrelation: number;
  compressionRatio: number;
  positional: PositionalEntropy[];
  observations: SequenceObservation[];
}
