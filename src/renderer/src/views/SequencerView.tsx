import React, { useState } from 'react';
import type { SequenceAnalysis, TokenEncoding } from '@shared/sequencer.js';
import { api } from '../api.js';

export function SequencerView(): JSX.Element {
  const [input, setInput] = useState('');
  const [encoding, setEncoding] = useState<TokenEncoding>('text');
  const [analysis, setAnalysis] = useState<SequenceAnalysis>();
  const [error, setError] = useState<string>();

  // Trim before filtering: a whitespace-only line is not a token, and under
  // hex/base64 it would otherwise abort the whole run as an invalid sample.
  const samples = input.split(/\r?\n/).filter((sample) => sample.trim().length > 0);

  const analyze = async (): Promise<void> => {
    setError(undefined);
    try {
      setAnalysis(await api.analyzeTokenSamples(samples, encoding));
    } catch (caught) {
      setAnalysis(undefined);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Sequencer</strong>
        <span className="hint">
          token collision, entropy, bit-bias, correlation, and compression screening
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <select
          aria-label="Token encoding"
          value={encoding}
          onChange={(event) => setEncoding(event.target.value as TokenEncoding)}
        >
          <option value="text">plain text bytes</option>
          <option value="hex">hex-decoded bytes</option>
          <option value="base64">Base64-decoded bytes</option>
          <option value="base64url">Base64url-decoded bytes</option>
        </select>
        <span className="hint">{samples.length.toLocaleString()} samples</span>
        <button className="primary" disabled={samples.length === 0} onClick={analyze}>
          Analyze
        </button>
      </div>

      <div className="split h" style={{ flex: 1 }}>
        <div className="pane">
          <div className="pane-title">Samples · one token per line</div>
          <textarea
            className="sequence-input"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Paste session tokens, reset tokens, nonces, or other security-sensitive values…"
            spellCheck={false}
          />
          <div className="warn-box" style={{ margin: 10 }}>
            This is a statistical screen, not proof that a token generator is unpredictable. Decode
            hex/Base64 before analysis, collect at least 100 samples (preferably thousands), and
            investigate generator state, replay, expiry, and binding separately.
          </div>
        </div>

        <div className="pane">
          <div className="pane-title">
            Analysis
            {analysis && (
              <span className={`assessment ${assessmentClass(analysis.assessment)}`}>
                {assessmentLabel(analysis.assessment)}
              </span>
            )}
          </div>
          {error && (
            <div className="danger-box" style={{ margin: 10 }}>
              {error}
            </div>
          )}
          {!analysis && !error && <div className="empty">Paste a sample set and run analysis.</div>}
          {analysis && <AnalysisResults analysis={analysis} />}
        </div>
      </div>
    </div>
  );
}

function AnalysisResults({ analysis }: { analysis: SequenceAnalysis }): JSX.Element {
  return (
    <div className="scrolly">
      <div className="metric-grid">
        <Metric label="Samples" value={analysis.sampleCount.toLocaleString()} />
        <Metric
          label="Unique"
          value={`${analysis.uniqueCount.toLocaleString()} (${percent(analysis.uniqueCount / analysis.sampleCount)})`}
        />
        <Metric label="Decoded bytes" value={analysis.totalBytes.toLocaleString()} />
        <Metric
          label="Token length"
          value={`${analysis.minLength}–${analysis.maxLength} B (mean ${analysis.meanLength.toFixed(1)})`}
        />
        <Metric label="Byte alphabet" value={`${analysis.alphabetSize}/256`} />
        <Metric
          label="Shannon entropy"
          value={`${analysis.shannonBitsPerByte.toFixed(3)} bits/byte`}
        />
        <Metric
          label="Min entropy"
          value={`${analysis.minEntropyBitsPerByte.toFixed(3)} bits/byte`}
        />
        <Metric
          label="Estimated/token"
          value={`${analysis.estimatedEntropyBitsPerToken.toFixed(1)} bits`}
        />
        <Metric
          label="Observed token Hmin"
          value={`${analysis.observedTokenMinEntropyBits.toFixed(1)} bits`}
        />
        <Metric label="One-bit ratio" value={analysis.bitOneRatio.toFixed(4)} />
        <Metric label="Monobit p-value" value={formatP(analysis.monobitPValue)} />
        <Metric label="Serial correlation" value={analysis.serialCorrelation.toFixed(4)} />
        <Metric label="Compression ratio" value={percent(analysis.compressionRatio)} />
      </div>

      <h3>Observations</h3>
      {analysis.observations.map((observation, index) => (
        <div
          key={`${observation.level}-${index}`}
          className={observation.level === 'warning' ? 'warn-box' : 'card'}
          style={{ margin: '6px 0', padding: '8px 10px' }}
        >
          {observation.message}
        </div>
      ))}

      <h3>Per-position entropy</h3>
      <div className="table-wrap" style={{ maxHeight: 280, border: '1px solid var(--border)' }}>
        <table className="grid">
          <thead>
            <tr>
              <th>Byte</th>
              <th>Samples</th>
              <th>Entropy</th>
              <th>8-bit utilization</th>
            </tr>
          </thead>
          <tbody>
            {analysis.positional.map((position) => (
              <tr key={position.position}>
                <td className="mono">{position.position}</td>
                <td className="mono">{position.sampleCount}</td>
                <td className="mono">{position.entropyBits.toFixed(3)} bits</td>
                <td className="mono">{percent(position.normalized)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {analysis.maxLength > analysis.positional.length && (
        <small className="hint">
          Per-position output is capped at the first 256 decoded bytes.
        </small>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong className="mono">{value}</strong>
    </div>
  );
}

function percent(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function formatP(value: number): string {
  return value < 0.0001 ? value.toExponential(2) : value.toFixed(4);
}

function assessmentLabel(assessment: SequenceAnalysis['assessment']): string {
  switch (assessment) {
    case 'insufficient-data':
      return 'insufficient data';
    case 'no-obvious-bias':
      return 'no obvious bias';
    default:
      return assessment;
  }
}

function assessmentClass(assessment: SequenceAnalysis['assessment']): string {
  if (assessment === 'no-obvious-bias') return 'ok';
  if (assessment === 'weak' || assessment === 'insufficient-data') return 'warn';
  return 'bad';
}
