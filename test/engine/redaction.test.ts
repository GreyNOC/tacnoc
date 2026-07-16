import { describe, it, expect } from 'vitest';
import { Redactor, detectSensitive, REDACTION_MASK } from '../../src/engine/redaction/redactor.js';
import type { HttpHeader } from '../../src/shared/model.js';

const redactor = new Redactor({
  maskCookies: true,
  maskAuthorization: true,
  maskSecretPatterns: true,
});

describe('redaction', () => {
  it('masks Authorization header entirely', () => {
    expect(redactor.redactHeaderValue('Authorization', 'Bearer abc.def.ghi')).toBe(REDACTION_MASK);
    expect(redactor.redactHeaderValue('proxy-authorization', 'Basic Zm9vOmJhcg==')).toBe(
      REDACTION_MASK,
    );
  });

  it('masks cookie values but keeps names', () => {
    const out = redactor.redactHeaderValue('Cookie', 'session=deadbeef; theme=dark');
    expect(out).toContain('session=' + REDACTION_MASK);
    expect(out).toContain('theme=' + REDACTION_MASK);
    expect(out).not.toContain('deadbeef');
  });

  it('masks Set-Cookie value but preserves attributes', () => {
    const out = redactor.redactHeaderValue('Set-Cookie', 'sid=SECRET; Path=/; HttpOnly; Secure');
    expect(out).toBe(`sid=${REDACTION_MASK}; Path=/; HttpOnly; Secure`);
  });

  it('redacts JWTs, AWS keys, and private keys in free text', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I';
    expect(redactor.redactText(`token=${jwt}`)).not.toContain(jwt);
    expect(redactor.redactText('key AKIAIOSFODNN7EXAMPLE here')).toContain(REDACTION_MASK);
    const pk = '-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----';
    expect(redactor.redactText(pk)).toBe(REDACTION_MASK);
  });

  it('redacts sensitive key=value assignments but keeps the key', () => {
    const out = redactor.redactText('password=hunter2secret&user=bob');
    expect(out).toContain('password=' + REDACTION_MASK);
    expect(out).toContain('user=bob');
    expect(out).not.toContain('hunter2secret');
  });

  it('redacts sensitive query params in URLs', () => {
    const out = redactor.redactUrl('https://h.test/cb?access_token=SECRETVAL&page=2');
    expect(out).toContain('access_token=' + REDACTION_MASK);
    expect(out).toContain('page=2');
    expect(out).not.toContain('SECRETVAL');
  });

  it('detectSensitive flags cookies, authorization, and tokens for warnings', () => {
    const headers: HttpHeader[] = [
      { name: 'Cookie', value: 'a=b' },
      { name: 'Authorization', value: 'Bearer x' },
      { name: 'X-Api-Key', value: 'zzz' },
    ];
    const report = detectSensitive(headers, 'nothing here');
    expect(report.hasCookies).toBe(true);
    expect(report.hasAuthorization).toBe(true);
    expect(report.hasTokens).toBe(true);
    expect(report.fields).toContain('Cookie');
  });

  it('leaves ordinary text untouched', () => {
    expect(redactor.redactText('the quick brown fox')).toBe('the quick brown fox');
  });
});
