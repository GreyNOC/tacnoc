import { describe, it, expect } from 'vitest';
import { diffLines, diffJson, diffBytes } from '../../src/engine/compare/compare.js';

describe('compare', () => {
  it('produces a line diff with add/remove/equal', () => {
    const diff = diffLines('a\nb\nc', 'a\nB\nc\nd');
    const types = diff.map((d) => d.type);
    expect(types).toContain('equal');
    expect(types).toContain('remove');
    expect(types).toContain('add');
    // reconstruct the right side from equal+add lines
    const right = diff
      .filter((d) => d.type !== 'remove')
      .map((d) => d.text)
      .join('\n');
    expect(right).toBe('a\nB\nc\nd');
  });

  it('diffs JSON structurally', () => {
    const entries = diffJson(
      '{"a":1,"b":{"c":2},"d":[1,2]}',
      '{"a":1,"b":{"c":3},"e":9,"d":[1,2,3]}',
    );
    const byPath = Object.fromEntries(entries.map((e) => [e.path, e.kind]));
    expect(byPath['$.b.c']).toBe('changed');
    expect(byPath['$.e']).toBe('added');
    expect(byPath['$.d[2]']).toBe('added');
  });

  it('reports byte-level differences and offsets', () => {
    expect(diffBytes(Buffer.from('abc'), Buffer.from('abc')).equal).toBe(true);
    const d = diffBytes(Buffer.from('abcd'), Buffer.from('abXd'));
    expect(d.equal).toBe(false);
    expect(d.firstDiffOffset).toBe(2);
    const lenDiff = diffBytes(Buffer.from('abc'), Buffer.from('abcd'));
    expect(lenDiff.firstDiffOffset).toBe(3);
    expect(lenDiff.differingBytes).toBe(1);
  });
});
